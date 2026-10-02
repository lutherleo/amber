#!/usr/bin/env python
"""End-to-end Amber run for the gittuf NDSS-2025 research artifact.

    uv run python run_gittuf_amber.py

Pipeline (all results land under ``gittuff_test_results/``):

  A. CODE GRAPH — built separately by Orion's (Oracle) streaming Joern build into
     ``gittuff_test_results/gittuf-orion-graph.json`` (see build_and_export in the
     orion-builder container). This script consumes it.
  B. AMBER CONTAINER — builds/uses the ``amber-gittuf`` image (python3.12 + witness
     + Go + gittuf) and live-captures the gittuf verification benchmark with witness
     **twice** (run-A, run-B) via ``research.container.run_capture_in_container``.
  C. CROSS-VERIFY — ingests both runs into an Amber research project, joins the code
     graph (Run -> CpgFile -> methods), checks the paper's claims (verify_seconds<=0.59,
     storage_overhead_pct<=4), and compares run-A vs run-B for reproducibility.

Prereqs: Docker running; the ``amber-gittuf`` image (this script builds it if missing
and ``AMBER_GITTUF_SRC`` points at the gittuf source tree); the code graph JSON.

Config via env: GITTUF_BENCH_REPOS, GITTUF_BENCH_PUSHES, GITTUF_BENCH_DEPTH.
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
PKG = REPO / "packages" / "darnit-reproducibility"
sys.path.insert(0, str(PKG / "src"))
sys.path.insert(0, str(REPO / "packages" / "darnit" / "src"))

from darnit_reproducibility.research import artifact as artifact_mod  # noqa: E402
from darnit_reproducibility.research import container as container_mod  # noqa: E402
from darnit_reproducibility.research import run as run_mod  # noqa: E402
from darnit_reproducibility.research import verify as verify_mod  # noqa: E402
from darnit_reproducibility.research.agent import deterministic_answer  # noqa: E402
from darnit_reproducibility.research.claims import parse_claim  # noqa: E402
from darnit_reproducibility.research.graph import CodeGraph  # noqa: E402

RESULTS = REPO / "gittuff_test_results"
AMBER_ROOT = str(RESULTS / ".amber-research")
GRAPH_JSON = RESULTS / "gittuf-orion-graph.json"
PROJECT = "gittuf"
IMAGE = os.environ.get("AMBER_GITTUF_IMAGE", "amber-gittuf:latest")
EXPERIMENT = PKG / "examples" / "research" / "gittuf" / "experiment.py"
# The benchmark harness is experiment.py, but the run EXERCISES gittuf's verify-ref
# code — so link each Run to that gittuf source file in the code graph (Run ->
# CpgFile -> methods resolves to the real verification functions the paper measures).
CODE_REF = "internal/cmd/verifyref/verifyref.go"
PAPER_TITLE = "Rethinking Trust in Forge-Based Git Security (gittuf)"
PAPER_URL = "https://www.ndss-symposium.org/ndss-paper/rethinking-trust-in-forge-based-git-security/"

# Scratch (large, not committed): per-run bench trees + the shared clone cache.
SCRATCH = Path(os.environ.get("AMBER_GITTUF_SCRATCH",
                              str(Path(os.environ.get("TEMP", "/tmp")) / "amber-gittuf")))

BENCH_ENV = {
    "GITTUF_BENCH_REPOS": os.environ.get("GITTUF_BENCH_REPOS", "git kubernetes"),
    "GITTUF_BENCH_PUSHES": os.environ.get("GITTUF_BENCH_PUSHES", "1 5 10 25"),
    "GITTUF_BENCH_DEPTH": os.environ.get("GITTUF_BENCH_DEPTH", "1000"),
    "GITTUF_BENCH_CACHE": "/cache",
    "GITTUF_BENCH_SCRATCH": "/bench",
    "GITTUF_BENCH_METRICS": "/metrics",
}


def rule(title: str) -> None:
    print("\n" + "=" * 74 + f"\n{title}\n" + "=" * 74, flush=True)


def _rmtree(path: Path) -> None:
    """rmtree that survives Windows read-only .git objects (WinError 5)."""
    import stat

    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if Path(path).exists():
        shutil.rmtree(path, onerror=_onerror)


def _docker() -> str:
    exe = shutil.which("docker")
    if not exe:
        raise SystemExit("docker not found on PATH")
    return exe


def ensure_image() -> None:
    out = subprocess.run([_docker(), "images", "-q", IMAGE], capture_output=True, text=True)
    if out.stdout.strip():
        print(f"image {IMAGE} present", flush=True)
        return
    src = os.environ.get("AMBER_GITTUF_SRC")
    if not src or not Path(src).exists():
        raise SystemExit(f"image {IMAGE} missing and AMBER_GITTUF_SRC not set to a gittuf source tree")
    rule(f"build image {IMAGE}")
    ctx = SCRATCH / "build-gittuf"
    _rmtree(ctx)
    (ctx / "packages").mkdir(parents=True)
    shutil.copy2(REPO / "packaging" / "container" / "gittuf" / "Dockerfile", ctx / "Dockerfile")
    shutil.copytree(REPO / "packaging" / "container" / "vendor" / "witness", ctx / "witness")
    shutil.copytree(REPO / "packages" / "darnit", ctx / "packages" / "darnit")
    shutil.copytree(PKG, ctx / "packages" / "darnit-reproducibility")
    shutil.copytree(Path(src), ctx / "gittuf-src")
    dockerfile = (REPO / "packaging" / "container" / "gittuf" / "Dockerfile").read_text()
    container_mod.build_default_image(IMAGE, ctx, dockerfile=dockerfile)


def prepare_workspace(run_id: str) -> Path:
    """A per-run /work: a git repo (witness' git attestor needs one) with the experiment."""
    ws = RESULTS / "runs" / run_id
    _rmtree(ws)
    ws.mkdir(parents=True)
    env = dict(os.environ, GIT_AUTHOR_DATE="2020-01-01T00:00:00 +0000",
               GIT_COMMITTER_DATE="2020-01-01T00:00:00 +0000")
    subprocess.run(["git", "init", "-q", str(ws)], check=True)
    subprocess.run(["git", "-C", str(ws), "-c", "user.name=amber", "-c", "user.email=amber@local",
                    "commit", "--allow-empty", "-q", "-m", "init"], check=True, env=env)
    shutil.copy2(EXPERIMENT, ws / "experiment.py")
    return ws


def capture_run(run_id: str) -> tuple[Path, Path]:
    ws = prepare_workspace(run_id)
    bench = SCRATCH / f"bench-{run_id}"
    # metrics sidecar MUST live outside the capture workspace (/work), else witness's
    # product attestor captures the nondeterministic metrics.json as an output and the
    # run-A/run-B reproducibility compare fails on it. Only result.json is captured.
    metrics = SCRATCH / f"metrics-{run_id}"
    cache = SCRATCH / "cache"
    for d in (bench, metrics, cache):
        d.mkdir(parents=True, exist_ok=True)
    docker_args: list[str] = [
        "-v", f"{bench.as_posix()}:/bench",
        "-v", f"{metrics.as_posix()}:/metrics",
        "-v", f"{cache.as_posix()}:/cache",
    ]
    for k, v in BENCH_ENV.items():
        docker_args += ["-e", f"{k}={v}"]
    rule(f"capture {run_id} (witness, in {IMAGE})")
    bundle = container_mod.run_capture_in_container(
        IMAGE, ws, ["python3", "/work/experiment.py"],
        step="gittuf", capture_args=["--no-ebpf"], docker_args=docker_args,
    )
    return bundle, metrics / "metrics.json"


def headline_metrics(metrics_json: Path) -> dict[str, float]:
    data = json.loads(metrics_json.read_text())
    h = data.get("headline", {})
    return {"verify_seconds": float(h.get("verify_seconds", 0.0)),
            "storage_overhead_pct": float(h.get("storage_overhead_pct", 0.0))}


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "runs").mkdir(exist_ok=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    ensure_image()

    # B. two live captures
    bundle_a, metrics_a = capture_run("run-A")
    bundle_b, metrics_b = capture_run("run-B")
    m_a, m_b = headline_metrics(metrics_a), headline_metrics(metrics_b)
    print(f"run-A metrics: {m_a}\nrun-B metrics: {m_b}", flush=True)

    # C. research project
    rule("amber research: begin + ingest + join")
    root = AMBER_ROOT
    _rmtree(Path(root) / PROJECT)
    claims = [
        parse_claim("verify_seconds<=0.59"),
        parse_claim("storage_overhead_pct<=4"),
        parse_claim("exit_code<=0"),
        parse_claim("output_count>=1"),
    ]
    run_mod.begin(PROJECT, paper_title=PAPER_TITLE, paper_url=PAPER_URL, claims=claims,
                  code_graph_path=str(GRAPH_JSON) if GRAPH_JSON.exists() else None, root=root)

    def pylibs(bundle: Path) -> str | None:
        p = bundle.parent / "amber-pylibs.json"
        return str(p) if p.exists() else None

    run_mod.run_ingest(PROJECT, str(bundle_a), pylibs(bundle_a), run_id="run-A",
                       experiment_path=CODE_REF,
                       extra_metrics=m_a, root=root)
    run_mod.run_ingest(PROJECT, str(bundle_b), pylibs(bundle_b), run_id="run-B",
                       experiment_path=CODE_REF,
                       extra_metrics=m_b, root=root)

    graph = run_mod.load_graph(PROJECT, root)
    join_report = None
    if GRAPH_JSON.exists():
        join_report = graph.join(CodeGraph.load(str(GRAPH_JSON)))
        for r in graph.nodes("Run"):
            methods = r.get("executed_methods") or []
            print(f"  {r['run_id']}: code_ref={r.get('code_ref', {}).get('file_path')} "
                  f"methods={len(methods)}", flush=True)
    run_mod.save_graph(PROJECT, graph, root)

    # claims (paper vs run-A)
    rule("amber research: verify claims (paper vs run-A)")
    paper_uid = graph.nodes("Paper")[0]["uid"]
    run_a_uid = graph.add_node("Run", "run-A", {})
    rec_a = run_mod.load_capture_for_run(PROJECT, "run-A", root)
    claim_results = verify_mod.verify_claims(graph, paper_uid, run_a_uid, rec_a)
    for res in claim_results:
        print(f"  claim {res['metric']:20} {res['level']:15} {res['detail']}", flush=True)

    # reproducibility (run-A vs run-B)
    rule("amber research: verify reproducibility (run-A vs run-B)")
    a_uid = graph.add_node("Run", "run-A", {})
    b_uid = graph.add_node("Run", "run-B", {})
    level, _ = verify_mod.verify_reproducibility(
        graph, a_uid, run_mod.load_capture_for_run(PROJECT, "run-A", root),
        b_uid, run_mod.load_capture_for_run(PROJECT, "run-B", root),
        original_dir=str(bundle_a.parent), reproduction_dir=str(bundle_b.parent),
    )
    print(f"  run-A vs run-B -> {level}", flush=True)
    run_mod.save_graph(PROJECT, graph, root)

    # agent + artifact
    rule("amber research: ask (deterministic) + artifact")
    graph = run_mod.load_graph(PROJECT, root)
    if GRAPH_JSON.exists():
        graph.join(CodeGraph.load(str(GRAPH_JSON)))
    print(deterministic_answer(graph), flush=True)
    art = artifact_mod.pack(PROJECT, str(RESULTS / "gittuf-artifact.tar.gz"), root=root)
    print(f"packed artifact -> {art}", flush=True)

    # machine-readable summary
    summary = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "image": IMAGE,
        "bench_env": BENCH_ENV,
        "code_graph": {"path": str(GRAPH_JSON), "exists": GRAPH_JSON.exists(),
                       "join": join_report},
        "run_A": {"metrics": m_a, "bundle": str(bundle_a)},
        "run_B": {"metrics": m_b, "bundle": str(bundle_b)},
        "claims": claim_results,
        "reproducibility": level,
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nsummary -> {RESULTS / 'summary.json'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
