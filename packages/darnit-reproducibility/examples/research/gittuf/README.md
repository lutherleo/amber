# gittuf verification benchmark (Amber research example)

`experiment.py` is the artifact Amber **live-captures inside the per-project
container** for the gittuf NDSS-2025 paper, *Rethinking Trust in Forge-Based Git
Security*. It reproduces the methodology of the paper's performance evaluation
(§VI, Tables I & II) and emits the two metrics the paper claims:

| Paper claim | Metric | Threshold |
|---|---|---|
| "under 0.59 s of time to verify each push" | `verify_seconds` | `<= 0.59` |
| "less than 4% storage overhead" | `storage_overhead_pct` | `<= 4` |

## What it does

For each target repo (real **Git** and **Kubernetes** repositories, bounded by
clone depth), on a fresh gittuf root-of-trust + policy:

1. add a **branch-protection** rule (`git:refs/heads/<default>`), replay a sweep of
   pushes recorded in the RSL, and time `gittuf verify-ref` → branch-only per-push;
2. add a **file-protection** rule (`file:*`), continue the sweep, time again →
   branch+file per-push (the paper's more expensive configuration);
3. measure the storage added to `.git` by gittuf metadata vs the base repo.

## Capture-friendly layout

- Heavy work runs in `$GITTUF_BENCH_SCRATCH` (`/bench`), **not** the capture working
  dir `/work`, so witness's product attestor records only the small deterministic
  `result.json` — keeping the bundle tiny and run-A/run-B byte-for-byte comparable.
- `result.json` (→ `/work`) holds only deterministic facts (tool versions, repos,
  rule names, verified booleans): the **reproducibility artifact**.
- Timings/sizes (→ `$GITTUF_BENCH_METRICS` `/metrics`, a sidecar mount outside
  `/work`) are nondeterministic and are fed to Amber as run **metrics** via
  `--metric`, so timing jitter never breaks the reproducibility verdict.

## Config (env)

| Var | Default | Meaning |
|---|---|---|
| `GITTUF_BENCH_REPOS` | `git kubernetes` | subset to benchmark |
| `GITTUF_BENCH_PUSHES` | `1 5 10 25` | push-count sweep |
| `GITTUF_BENCH_DEPTH` | `1000` | clone depth (bounds size/time) |
| `GITTUF_BENCH_CACHE` | – | shared clone cache (clone once, reuse across runs) |
| `GITTUF_BENCH_SCRATCH` | `/bench` | heavy-work dir |
| `GITTUF_BENCH_METRICS` | `/metrics` | sidecar metrics dir |

Driven end-to-end by `run_gittuf_amber.py` at the repo root.
