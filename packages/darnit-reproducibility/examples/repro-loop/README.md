# Amber closed reproducibility loop

The payoff of capture: **prove** a computational result reproduces, and explain it when it doesn't.

```bash
DARNIT_PY=~/darnit-venv/bin/python bash run_loop.sh lorenz     # or sir / sklearn_wine / pysindy
```

Four stages (`run_loop.sh`):

1. **Capture** the experiment on the host → original bundle.
2. **Generate** a reproducible environment from the capture —
   `darnit_reproducibility.generate.environment` writes a pinned `requirements.lock` (from the
   *used* distributions) and a `Dockerfile` (base image from the captured Python, source at the
   captured commit).
3. **Rebuild & re-run** inside `docker build` + `docker run`, re-capturing with the pure-Python probe
   (no witness/git/root needed in the image — the baseline-first stance).
4. **Compare** the two captures → a reproducibility **verdict**
   (`darnit_reproducibility.analysis.compare`) and a signable in-toto attestation
   (`.../attestations/reproducibility/v1`).

## Real result (lorenz)

```
✅ REPRODUCED_WITH_DRIFT — all outputs identical despite environment differences (robust reproduction)
reproduction rate: 100%
artifacts:
  = result.json  sha256:39e598cf9a3a2 = sha256:39e598cf9a3a2
environment: python 3.12.3 -> 3.12.14; 0 drifted, 0 missing, 0 added
```

The 20 000-step Lorenz trajectory hashed **bit-for-bit identical** between the host venv and a freshly
built container — on a **different Python patch release (3.12.3 → 3.12.14)** — because the generated
environment pinned numpy/scipy exactly from the capture. The verdict recognizes the identical outputs
as a *robust* reproduction while still surfacing the interpreter drift.

## Verdict levels

| Level | Meaning |
|---|---|
| `BIT_FOR_BIT` | every output identical **and** the environment identical |
| `REPRODUCED_WITH_DRIFT` | outputs identical despite environment differences (a robust reproduction) |
| `NOT_REPRODUCED` | outputs differ; the environment differences are ranked as likely causes (or flagged as nondeterminism when the environment matches) |
| `INCONCLUSIVE` | no shared produced artifacts to compare |

## Honest limit

Baseline capture reconstructs the **Python** environment. A system/native library an extension wheel
linked against (a specific BLAS, a CUDA runtime) is invisible without the eBPF deep mode, so a
generated image can still miss a native dependency — exactly the gap Track 2 (eBPF total-capture)
closes. `compare` will flag such a case as `NOT_REPRODUCED` with "no environment difference detected",
pointing at native/nondeterministic causes.
