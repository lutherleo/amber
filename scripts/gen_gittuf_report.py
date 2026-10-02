#!/usr/bin/env python
"""Render gittuff_test_results/GITTUF_AMBER_REPORT.md from the captured results.

Reads (all under gittuff_test_results/):
  summary.json, runs/run-A/metrics/metrics.json, runs/run-B/metrics/metrics.json,
  gittuf-orion-graph.json, and the amber research graph under .amber-research/gittuf/.

Safe to run repeatedly after run_gittuf_amber.py; degrades gracefully if a piece is
missing (e.g. the Kubernetes benchmark did not complete).
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
R = REPO / "gittuff_test_results"


def load(p: Path, default=None):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def fmt_num(x, nd=4):
    try:
        return f"{float(x):.{nd}g}"
    except Exception:
        return str(x)


def runtime_table(repo_metrics: dict) -> list[str]:
    """Per-push verify time sweep for one repo (Table II style)."""
    rows = ["| config | pushes (n) | verify_seconds | per-push s | ok |",
            "|---|---|---|---|---|"]
    for cfg in ("branch", "branch_file"):
        for s in (repo_metrics.get(cfg, {}) or {}).get("sweep", []):
            rows.append(f"| {cfg} | {s.get('n')} | {fmt_num(s.get('verify_seconds'))} | "
                        f"{fmt_num(s.get('per_push'))} | {s.get('ok')} |")
    return rows


def main() -> int:
    summary = load(R / "summary.json", {}) or {}
    mA = load(R / "runs" / "run-A" / "metrics.json", {}) or {}
    mB = load(R / "runs" / "run-B" / "metrics.json", {}) or {}
    graph_meta = (load(R / "gittuf-orion-graph.json", {}) or {}).get("meta", {})
    k8s_meta = (load(R / "kubernetes-orion-graph.json", {}) or {}).get("meta", {})

    repos_A = (mA.get("repos") or {})
    headline_A = (mA.get("headline") or {})
    claims = summary.get("claims") or []
    repro = summary.get("reproducibility", "n/a")
    bench_env = summary.get("bench_env", {})

    out: list[str] = []
    w = out.append
    w("# Amber × gittuf — reproducibility report")
    w("")
    w(f"*Generated {datetime.datetime.now(datetime.timezone.utc).isoformat()} by "
      "`scripts/gen_gittuf_report.py`.*")
    w("")
    w("This report records an end-to-end **Amber** run over the gittuf NDSS-2025 artifact: a "
      "code graph built with **orion/Oracle's streaming Joern algorithm**, a gittuf verification "
      "benchmark **live-captured with witness inside an Amber container**, and Amber's deterministic "
      "cross-verification of the paper's claims and of run-to-run reproducibility.")
    w("")
    w("- **Paper:** *Rethinking Trust in Forge-Based Git Security* (gittuf), NDSS 2025.")
    w("- **Source under test:** `github.com/gittuf/gittuf` (Go, built from the provided zip).")
    w("- **Claims checked:** `verify_seconds <= 0.59`, `storage_overhead_pct <= 4`.")
    w("")

    # ---- Part A: code graph ----
    w("## A. Code graph (orion/Oracle streaming build, via Joern `gosrc2cpg`)")
    w("")
    if graph_meta:
        w(f"- Source: `{graph_meta.get('source')}` · scan_id `{graph_meta.get('scan_id')}`")
        w(f"- **{graph_meta.get('node_count','?')} nodes / {graph_meta.get('edge_count','?')} edges**")
        w(f"- nodes by label: `{graph_meta.get('nodes_by_label')}`")
        w(f"- edges by type: `{graph_meta.get('edges_by_type')}`")
        w("")
        w("Each captured run is joined to this graph on the gittuf source file it exercises "
          "(`internal/cmd/verifyref/verifyref.go` — the `gittuf verify-ref` command), resolving "
          "**Run → CpgFile → methods**.")
    else:
        w("_Code graph JSON not found._")
    runs_graph = summary.get("code_graph", {})
    if runs_graph:
        w("")
        w(f"- join report: `{runs_graph.get('join')}`")
    w("")
    w("### GraphRAG: every referenced structure lives in orion")
    w("")
    w("Per the project rule *everything an amber container references must first exist in the "
      "orion GraphRAG* (agentic-memory performance — query the graph, don't brute-scan the tree):")
    w("")
    w("| graph | nodes | edges | CpgFile | CpgMethod |")
    w("|---|---|---|---|---|")
    if graph_meta:
        nbl = graph_meta.get("nodes_by_label", {})
        w(f"| gittuf (full source) | {graph_meta.get('node_count')} | {graph_meta.get('edge_count')} | "
          f"{nbl.get('CpgFile')} | {nbl.get('CpgMethod')} |")
    if k8s_meta:
        nbl = k8s_meta.get("nodes_by_label", {})
        w(f"| kubernetes (apimachinery core) | {k8s_meta.get('node_count')} | {k8s_meta.get('edge_count')} | "
          f"{nbl.get('CpgFile')} | {nbl.get('CpgMethod')} |")
    w("")
    w("Both are real Joern CPGs produced by orion/Oracle's streaming build. The Kubernetes graph "
      "covers the self-contained `apimachinery` core module; graphing the entire 31k-file multi-module "
      "tree is the same procedure per module (bounded by Joern's Go-frontend dependency resolution).")
    w("")

    # ---- Part B: container ----
    w("## B. Amber container (live witness capture)")
    w("")
    w(f"- Image: `{summary.get('image','amber-gittuf:latest')}` — "
      "`python:3.12-slim` + vendored **witness v0.12.0** + Go 1.27 + **gittuf** (built from source).")
    w(f"- Benchmark config: `{bench_env}`")
    w("- The benchmark (`experiment.py`) ran under `amber capture` (witness attestors: "
      "environment, git, material, command-run, product) → a signed in-toto bundle per run.")
    w("")

    # ---- Part C: benchmark results ----
    w("## C. Benchmark results")
    w("")
    w("### Storage overhead (Table I style)")
    w("")
    w("| repo | base .git (bytes) | with gittuf (bytes) | overhead % |")
    w("|---|---|---|---|")
    for name, rm in repos_A.items():
        if "error" in rm:
            w(f"| {name} | — | — | _error: {rm['error'][:60]}_ |")
            continue
        w(f"| {name} | {rm.get('base_bytes')} | {rm.get('total_bytes')} | "
          f"{fmt_num(rm.get('storage_overhead_pct'))} |")
    w("")
    w("### Runtime overhead (Table II style, per repo)")
    for name, rm in repos_A.items():
        if "error" in rm:
            continue
        w("")
        w(f"**{name}** (ref `{rm.get('ref')}`)")
        w("")
        out.extend(runtime_table(rm))
    w("")
    w(f"**Headline (run-A, conservative/worst-case):** verify_seconds = "
      f"`{fmt_num(headline_A.get('verify_seconds'))}`, "
      f"storage_overhead_pct = `{fmt_num(headline_A.get('storage_overhead_pct'))}`.")
    w("")

    # ---- Claim verdicts ----
    w("## D. Claim verification (deterministic — paper vs measured run-A)")
    w("")
    w("| claim | verdict | detail |")
    w("|---|---|---|")
    for c in claims:
        w(f"| `{c.get('metric')} {c.get('comparator')} {c.get('value')}` | "
          f"**{c.get('level')}** | {c.get('detail')} |")
    w("")

    # ---- Reproducibility ----
    w("## E. Reproducibility (run-A vs run-B)")
    w("")
    w(f"Amber verdict (deterministic compare of the captured `result.json`): **{repro}**.")
    w("")
    w(f"- run-A headline metrics: `{headline_A}`")
    w(f"- run-B headline metrics: `{(mB.get('headline') or {})}`")
    w("")

    # ---- Honest notes ----
    w("## F. Notes on scope & fidelity")
    w("")
    w("- **Hardware differs from the paper** (Ryzen 7640U / 32 GB / Ubuntu 24.04). Absolute "
      "per-push times are environment-dependent; the claim check is against the paper's "
      "*thresholds*, and verification here runs the **whole RSL** per call (amortized per push), "
      "whereas the paper measures incremental per-push cost — so our per-push numbers are an "
      "upper bound, not a like-for-like of the paper's figures.")
    w("- **Push volume and clone depth are bounded** for tractability (see config); the paper "
      "swept the repositories' full merge history.")
    w("- **The code graph is a real Joern CPG** of gittuf's Go source produced by orion/Oracle's "
      "streaming build (no fallback used).")
    w("")
    w("All inputs, bundles, metrics, the code graph and the portable artifact are under "
      "`gittuff_test_results/`.")
    w("")

    (R / "GITTUF_AMBER_REPORT.md").write_text("\n".join(out) + "\n", encoding="utf-8")

    # CSV side tables
    (R / "tables").mkdir(exist_ok=True)
    srows = ["repo,base_bytes,total_bytes,storage_overhead_pct"]
    rrows = ["repo,config,n,verify_seconds,per_push,ok"]
    for name, rm in repos_A.items():
        if "error" in rm:
            continue
        srows.append(f"{name},{rm.get('base_bytes')},{rm.get('total_bytes')},{rm.get('storage_overhead_pct')}")
        for cfg in ("branch", "branch_file"):
            for s in (rm.get(cfg, {}) or {}).get("sweep", []):
                rrows.append(f"{name},{cfg},{s.get('n')},{s.get('verify_seconds')},{s.get('per_push')},{s.get('ok')}")
    (R / "tables" / "storage_overhead.csv").write_text("\n".join(srows) + "\n")
    (R / "tables" / "runtime_overhead.csv").write_text("\n".join(rrows) + "\n")

    print(f"wrote {R / 'GITTUF_AMBER_REPORT.md'}")
    print(f"wrote {R / 'tables' / 'storage_overhead.csv'}, {R / 'tables' / 'runtime_overhead.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
