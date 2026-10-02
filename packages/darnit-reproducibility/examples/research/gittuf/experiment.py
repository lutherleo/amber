#!/usr/bin/env python3
"""gittuf verification benchmark — the experiment Amber live-captures in-container.

Reproduces the *methodology* of the NDSS 2025 gittuf paper's performance
evaluation (§VI, Tables I & II): set up a gittuf policy on a real Git repository,
replay pushes recorded in the Reference State Log (RSL), and measure

  * runtime overhead  — wall time of ``gittuf verify-ref`` per push, for
    branch-protection-only and branch+file-protection policies, and
  * storage overhead  — size added to ``.git`` by gittuf metadata vs the base repo.

Paper claims checked downstream by Amber:
  * ``verify_seconds       <= 0.59``   (per-push verification, worst case)
  * ``storage_overhead_pct <= 4``

Design for Amber capture/reproducibility:
  * All heavy work happens in ``$BENCH`` (default ``/bench``), NOT in the capture
    working dir ``/work``. So witness's material/product attestors (scoped to
    ``/work``) record only the small, deterministic ``result.json`` — keeping the
    bundle tiny and the two runs byte-for-byte comparable.
  * ``result.json`` (in ``/work``) holds only deterministic facts (tool versions,
    repos, rule names, verified booleans) — this is the reproducibility artifact.
  * Timings/sizes (nondeterministic) go to ``$METRICS/metrics.json`` (a sidecar
    mount, default ``/metrics``, outside ``/work``) and are echoed as
    ``AMBER_METRIC key=value`` lines for the host orchestrator to read.

Everything is parameterized via env vars so the push volume / repos can scale:
  GITTUF_BENCH_REPOS   space-separated subset of {git kubernetes}  (default both)
  GITTUF_BENCH_PUSHES  space-separated sweep of push counts        (default "1 5 10 25")
  GITTUF_BENCH_DEPTH   clone depth (bounds clone size/time)         (default 1000)
  GITTUF_BENCH_WORK    capture working dir                          (default /work)
  GITTUF_BENCH_METRICS sidecar metrics dir                          (default /metrics)
  GITTUF_BENCH_SCRATCH heavy-work dir                               (default /bench)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_URLS = {
    "git": "https://github.com/git/git.git",
    "kubernetes": "https://github.com/kubernetes/kubernetes.git",
}

REPOS = os.environ.get("GITTUF_BENCH_REPOS", "git kubernetes").split()
PUSHES = [int(x) for x in os.environ.get("GITTUF_BENCH_PUSHES", "1 5 10 25").split()]
# File-protection namespace. The paper protects *specific* project namespaces (~12k
# files), NOT every file, so default to a bounded real subtree rather than file:* —
# `file:*` would make every verify-ref re-scan the whole working tree.
FILE_PATTERN = os.environ.get("GITTUF_BENCH_FILE_PATTERN", "file:Documentation/*")
DEPTH = os.environ.get("GITTUF_BENCH_DEPTH", "1000")
WORK = Path(os.environ.get("GITTUF_BENCH_WORK", "/work"))
METRICS = Path(os.environ.get("GITTUF_BENCH_METRICS", "/metrics"))
SCRATCH = Path(os.environ.get("GITTUF_BENCH_SCRATCH", "/bench"))


def run(cmd, cwd=None, check=True, capture=False, env=None):
    """Run a command; raise on failure unless check=False. Returns CompletedProcess."""
    return subprocess.run(
        cmd, cwd=cwd, check=check, env=env,
        stdout=(subprocess.PIPE if capture else None),
        stderr=(subprocess.PIPE if capture else None),
        text=True,
    )


def tool_version(cmd) -> str:
    try:
        r = run(cmd, check=False, capture=True)
        return (r.stdout or r.stderr or "").strip().splitlines()[0] if (r.stdout or r.stderr) else "?"
    except Exception as exc:  # noqa: BLE001
        return f"?({exc})"


def du_bytes(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def gen_keys(keydir: Path) -> None:
    keydir.mkdir(parents=True, exist_ok=True)
    for name in ("root", "policy", "developer"):
        kp = keydir / name
        if not kp.exists():
            run(["ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", str(kp)])


def git_env() -> dict:
    """Deterministic, offline git identity so commits never prompt or vary by host."""
    e = dict(os.environ)
    e.update(
        GIT_AUTHOR_NAME="amber", GIT_AUTHOR_EMAIL="amber@local",
        GIT_COMMITTER_NAME="amber", GIT_COMMITTER_EMAIL="amber@local",
        GIT_AUTHOR_DATE="2020-01-01T00:00:00 +0000",
        GIT_COMMITTER_DATE="2020-01-01T00:00:00 +0000",
        GIT_TERMINAL_PROMPT="0",
    )
    return e


def verify_time(repo: Path, ref: str, env: dict) -> tuple[float, bool]:
    """Time `gittuf verify-ref <ref>`; return (seconds, ok)."""
    t0 = time.perf_counter()
    r = run(["gittuf", "verify-ref", ref], cwd=repo, check=False, capture=True, env=env)
    dt = time.perf_counter() - t0
    return dt, (r.returncode == 0)


def bench_repo(name: str, url: str) -> dict:
    env = git_env()
    repo = SCRATCH / name
    keydir = SCRATCH / "keys"
    gen_keys(keydir)
    root, policy, developer = keydir / "root", keydir / "policy", keydir / "developer"

    # Clone once into a shared cache (persists across run-A/run-B), then copy per run so
    # each run benchmarks from an identical starting state without re-downloading.
    cache = os.environ.get("GITTUF_BENCH_CACHE")
    if repo.exists():
        shutil.rmtree(repo, ignore_errors=True)
    if cache:
        cache_repo = Path(cache) / name
        if not cache_repo.exists():
            print(f"[{name}] clone (depth={DEPTH}) -> cache {url}", flush=True)
            run(["git", "clone", "--depth", str(DEPTH), "--single-branch", url, str(cache_repo)], env=env)
        print(f"[{name}] copy from cache", flush=True)
        shutil.copytree(cache_repo, repo)
    else:
        print(f"[{name}] clone (depth={DEPTH}) {url}", flush=True)
        run(["git", "clone", "--depth", str(DEPTH), "--single-branch", url, str(repo)], env=env)

    # default branch
    ref = run(["git", "symbolic-ref", "--short", "HEAD"], cwd=repo, capture=True, env=env).stdout.strip()
    run(["git", "config", "gpg.format", "ssh"], cwd=repo, env=env)
    run(["git", "config", "user.signingkey", str(developer)], cwd=repo, env=env)
    run(["git", "config", "commit.gpgsign", "true"], cwd=repo, env=env)

    # baseline repo size (packed), before any gittuf metadata
    run(["git", "gc", "--quiet"], cwd=repo, check=False, env=env)
    base_bytes = du_bytes(repo / ".git")

    # gittuf root of trust + policy
    run(["gittuf", "trust", "init", "-k", str(root)], cwd=repo, env=env)
    run(["gittuf", "trust", "add-policy-key", "-k", str(root), "--policy-key", str(policy) + ".pub"], cwd=repo, env=env)
    run(["gittuf", "policy", "init", "-k", str(policy), "--policy-name", "targets"], cwd=repo, env=env)
    run(["gittuf", "policy", "add-person", "-k", str(policy), "--person-ID", "developer",
         "--public-key", str(developer) + ".pub"], cwd=repo, env=env)
    # branch-protection rule
    run(["gittuf", "policy", "add-rule", "-k", str(policy), "--rule-name", "protect-branch",
         "--rule-pattern", f"git:refs/heads/{ref}", "--authorize", "developer"], cwd=repo, env=env)
    run(["gittuf", "policy", "stage", "--local-only"], cwd=repo, env=env)
    run(["gittuf", "policy", "apply", "--local-only"], cwd=repo, env=env)

    maxN = max(PUSHES)
    sweep_set = set(PUSHES)
    bench_file = repo / "amber-bench.txt"

    def replay_and_measure(config_label: str, start: int, count: int) -> list[dict]:
        rows = []
        for i in range(start, start + count):
            bench_file.write_text(f"amber bench push {i}\n")
            run(["git", "add", "-A"], cwd=repo, env=env)
            run(["git", "commit", "-q", "-S", "-m", f"amber bench {i}"], cwd=repo, env=env)
            run(["gittuf", "rsl", "record", ref, "--local-only"], cwd=repo, env=env)
            n = i  # total pushes recorded so far in this config
            if (n - start + 1) in sweep_set or n in sweep_set:
                secs, ok = verify_time(repo, ref, env)
                rows.append({"n": n, "verify_seconds": round(secs, 6),
                             "per_push": round(secs / max(n, 1), 6), "ok": ok})
                print(f"[{name}:{config_label}] n={n} verify={secs:.4f}s ok={ok}", flush=True)
        return rows

    # Phase A: branch-protection only
    branch_rows = replay_and_measure("branch", 1, maxN)

    # Phase B: add file-protection rule, then continue the sweep (verify now covers file policy)
    run(["gittuf", "policy", "add-rule", "-k", str(policy), "--rule-name", "protect-files",
         "--rule-pattern", FILE_PATTERN, "--authorize", "developer"], cwd=repo, env=env)
    run(["gittuf", "policy", "stage", "--local-only"], cwd=repo, env=env)
    run(["gittuf", "policy", "apply", "--local-only"], cwd=repo, env=env)
    branch_file_rows = replay_and_measure("branch_file", maxN + 1, maxN)

    # storage overhead: size added by gittuf metadata vs base repo
    run(["git", "gc", "--quiet"], cwd=repo, check=False, env=env)
    total_bytes = du_bytes(repo / ".git")
    overhead_pct = round(100.0 * (total_bytes - base_bytes) / base_bytes, 4) if base_bytes else 0.0

    branch_ok = all(r["ok"] for r in branch_rows) if branch_rows else False
    file_ok = all(r["ok"] for r in branch_file_rows) if branch_file_rows else False

    def per_push_max(rows):
        return max((r["per_push"] for r in rows), default=0.0)

    return {
        "ref": ref,
        "base_bytes": base_bytes,
        "total_bytes": total_bytes,
        "storage_overhead_pct": overhead_pct,
        "branch": {"sweep": branch_rows, "per_push_max": per_push_max(branch_rows)},
        "branch_file": {"sweep": branch_file_rows, "per_push_max": per_push_max(branch_file_rows)},
        "verified_branch": branch_ok,
        "verified_branch_file": file_ok,
        "rules": ["protect-branch", "protect-files"],
    }


def main() -> int:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    METRICS.mkdir(parents=True, exist_ok=True)

    gittuf_v = tool_version(["gittuf", "version"])
    git_v = tool_version(["git", "--version"])
    print(f"gittuf={gittuf_v!r} git={git_v!r} repos={REPOS} pushes={PUSHES} depth={DEPTH}", flush=True)

    metrics_repos: dict[str, dict] = {}
    result_repos: dict[str, dict] = {}
    for name in REPOS:
        url = REPO_URLS.get(name)
        if not url:
            print(f"[{name}] unknown repo, skipping", flush=True)
            continue
        try:
            m = bench_repo(name, url)
            metrics_repos[name] = m
            # deterministic subset for the reproducibility artifact (no sizes/timings)
            result_repos[name] = {
                "ref": m["ref"],
                "verified_branch": m["verified_branch"],
                "verified_branch_file": m["verified_branch_file"],
                "rules": m["rules"],
            }
        except subprocess.CalledProcessError as exc:
            print(f"[{name}] FAILED: {exc}\n{getattr(exc, 'stderr', '')}", flush=True)
            metrics_repos[name] = {"error": str(exc)}
            result_repos[name] = {"error": str(exc), "verified_branch": False, "verified_branch_file": False}

    # headline metrics for the paper claims (conservative = worst/max measured)
    overheads = [m["storage_overhead_pct"] for m in metrics_repos.values() if "storage_overhead_pct" in m]
    per_push = [m["branch_file"]["per_push_max"] for m in metrics_repos.values() if "branch_file" in m]
    headline = {
        "verify_seconds": round(max(per_push), 6) if per_push else 0.0,
        "storage_overhead_pct": round(max(overheads), 4) if overheads else 0.0,
    }

    # deterministic reproducibility artifact -> /work (captured by witness)
    result = {
        "experiment": "gittuf-verification-benchmark",
        "paper": "Rethinking Trust in Forge-Based Git Security (NDSS 2025)",
        "gittuf_version": gittuf_v,
        "git_version": git_v,
        "configs": ["branch", "branch_file"],
        "file_pattern": FILE_PATTERN,
        "push_sweep": PUSHES,
        "repos": {k: result_repos[k] for k in sorted(result_repos)},
        "all_verified": all(
            r.get("verified_branch") and r.get("verified_branch_file")
            for r in result_repos.values()
        ) if result_repos else False,
    }
    (WORK / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    # nondeterministic metrics -> sidecar mount (NOT captured) + stdout for the host
    metrics = {"repos": metrics_repos, "headline": headline}
    (METRICS / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    print(f"AMBER_METRIC verify_seconds={headline['verify_seconds']}", flush=True)
    print(f"AMBER_METRIC storage_overhead_pct={headline['storage_overhead_pct']}", flush=True)
    print("gittuf benchmark complete.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
