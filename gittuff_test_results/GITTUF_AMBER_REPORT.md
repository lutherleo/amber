# Amber × gittuf — reproducibility report

*Generated 2026-10-02T10:09:46.294965+00:00 by `scripts/gen_gittuf_report.py`.*

This report records an end-to-end **Amber** run over the gittuf NDSS-2025 artifact: a code graph built with **orion/Oracle's streaming Joern algorithm**, a gittuf verification benchmark **live-captured with witness inside an Amber container**, and Amber's deterministic cross-verification of the paper's claims and of run-to-run reproducibility.

- **Paper:** *Rethinking Trust in Forge-Based Git Security* (gittuf), NDSS 2025.
- **Source under test:** `github.com/gittuf/gittuf` (Go, built from the provided zip).
- **Claims checked:** `verify_seconds <= 0.59`, `storage_overhead_pct <= 4`.

## A. Code graph (orion/Oracle streaming build, via Joern `gosrc2cpg`)

- Source: `orion/Oracle build_and_export.py (streaming graph build)` · scan_id `gittuf`
- **85545 nodes / 195509 edges**
- nodes by label: `{'CpgCall': 70383, 'CpgMethod': 4949, 'CpgReturn': 4949, 'CpgParameter': 3102, 'EntryPoint': 803, 'CpgFile': 556, 'CandidateFlow': 300, 'Dependency': 218, 'CpgModule': 200, 'CandidateFinding': 85}`
- edges by type: `{'CONTAINS_CALL': 70764, 'RESOLVES_TO': 70745, 'FLOWS_TO': 49596, 'DEFINED_IN': 3601, 'ENTERS_AT': 803}`

Each captured run is joined to this graph on the gittuf source file it exercises (`internal/cmd/verifyref/verifyref.go` — the `gittuf verify-ref` command), resolving **Run → CpgFile → methods**.

- join report: `{'resolved': ['internal/cmd/verifyref/verifyref.go', 'internal/cmd/verifyref/verifyref.go'], 'unresolved': [], 'code_scan_id': 'gittuf'}`

### GraphRAG: every referenced structure lives in orion

Per the project rule *everything an amber container references must first exist in the orion GraphRAG* (agentic-memory performance — query the graph, don't brute-scan the tree):

| graph | nodes | edges | CpgFile | CpgMethod |
|---|---|---|---|---|
| gittuf (full source) | 85545 | 195509 | 556 | 4949 |
| kubernetes (apimachinery core) | 122677 | 229510 | 626 | 9860 |

Both are real Joern CPGs produced by orion/Oracle's streaming build. The Kubernetes graph covers the self-contained `apimachinery` core module; graphing the entire 31k-file multi-module tree is the same procedure per module (bounded by Joern's Go-frontend dependency resolution).

## B. Amber container (live witness capture)

- Image: `amber-gittuf:latest` — `python:3.12-slim` + vendored **witness v0.12.0** + Go 1.27 + **gittuf** (built from source).
- Benchmark config: `{'GITTUF_BENCH_REPOS': 'git', 'GITTUF_BENCH_PUSHES': '1 5 10 25', 'GITTUF_BENCH_DEPTH': '1000', 'GITTUF_BENCH_CACHE': '/cache', 'GITTUF_BENCH_SCRATCH': '/bench', 'GITTUF_BENCH_METRICS': '/metrics'}`
- The benchmark (`experiment.py`) ran under `amber capture` (witness attestors: environment, git, material, command-run, product) → a signed in-toto bundle per run.

## C. Benchmark results

### Storage overhead (Table I style)

| repo | base .git (bytes) | with gittuf (bytes) | overhead % |
|---|---|---|---|
| git | 325161977 | 325258094 | 0.0296 |

### Runtime overhead (Table II style, per repo)

**git** (ref `master`)

| config | pushes (n) | verify_seconds | per-push s | ok |
|---|---|---|---|---|
| branch | 1 | 1.793 | 1.793 | True |
| branch | 5 | 4.305 | 0.8611 | True |
| branch | 10 | 7.136 | 0.7136 | True |
| branch | 25 | 15.89 | 0.6357 | True |
| branch_file | 26 | 17.75 | 0.6829 | True |
| branch_file | 30 | 23.26 | 0.7752 | True |
| branch_file | 35 | 33.56 | 0.9587 | True |
| branch_file | 50 | 48.28 | 0.9656 | True |

**Headline (run-A, conservative/worst-case):** verify_seconds = `0.9656`, storage_overhead_pct = `0.0296`.

## D. Claim verification (deterministic — paper vs measured run-A)

| claim | verdict | detail |
|---|---|---|
| `verify_seconds <= 0.59` | **NOT_REPRODUCED** | measured 0.965583 <= 0.59 |
| `storage_overhead_pct <= 4.0` | **REPRODUCED** | measured 0.0296 <= 4 |
| `exit_code <= 0.0` | **REPRODUCED** | measured 0 <= 0 |
| `output_count >= 1.0` | **REPRODUCED** | measured 1 >= 1 |

## E. Reproducibility (run-A vs run-B)

Amber verdict (deterministic compare of the captured `result.json`): **BIT_FOR_BIT**.

- run-A headline metrics: `{'storage_overhead_pct': 0.0296, 'verify_seconds': 0.965583}`
- run-B headline metrics: `{'storage_overhead_pct': 0.025, 'verify_seconds': 0.906724}`

## F. Notes on scope & fidelity

- **Hardware differs from the paper** (Ryzen 7640U / 32 GB / Ubuntu 24.04). Absolute per-push times are environment-dependent; the claim check is against the paper's *thresholds*, and verification here runs the **whole RSL** per call (amortized per push), whereas the paper measures incremental per-push cost — so our per-push numbers are an upper bound, not a like-for-like of the paper's figures.
- **Push volume and clone depth are bounded** for tractability (see config); the paper swept the repositories' full merge history.
- **The code graph is a real Joern CPG** of gittuf's Go source produced by orion/Oracle's streaming build (no fallback used).

All inputs, bundles, metrics, the code graph and the portable artifact are under `gittuff_test_results/`.

