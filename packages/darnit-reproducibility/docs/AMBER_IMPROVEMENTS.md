# Amber capture — validation on real research code & improvement plan

## MVP status: milestones M0–M6 SHIPPED

The researcher-tool MVP roadmap is implemented and tested (213 tests, ruff + validate_sync green):
- **M0 Productize** — `amber` CLI (`capture|ingest|generate|verify|sbom|vulns|provenance`) + darnit
  controls `RE-01.03 RuntimeProvenanceCaptured`, `RE-03.02 ReproVerified`.
- **M1 Loop hardening** — semantic (FP-tolerance) verdict `SEMANTICALLY_REPRODUCED`, conda generator,
  a committed NOT_REPRODUCED example (cause = nondeterminism, verified live).
- **M2 CI runner + signing** — `capture --sign` (Sigstore keyless) + `.github/workflows/amber-capture.yml`
  (deep eBPF + signed on a native-Linux runner).
- **M3 Hardware/numerical** — `capture/hwprobe`-style capture of CPU/SIMD, GPU/CUDA, BLAS, thread env,
  hash seed; fed into the verdict's cause analysis and the generated Dockerfile (thread pins).
- **M4 Deep trace (portable)** — `/proc/self/maps` native shared objects (catches BLAS/CUDA/libstdc++
  that Python import misses, verified live) + a subprocess/dlopen audit hook; feeds apt hints into the
  generator. eBPF (Witness `--trace`, CI) remains for child-process file access.
- **M5 Make-sense** — CycloneDX SBOM, live OSV CVE check, and custom-vs-distributed (patched-vs-stock)
  detection against real PyPI RECORDs (numpy/scipy verified `stock`).
- **M6 Signing/verify** — `verify --require-signed` + `--attestation-out` (writes the reproducibility
  predicate, consumed by RE-03.02).

Post-MVP progress: the **completeness eval harness** is also done (`evaluation.py`, `amber eval`) —
scores dependency recall, native-lib capture, digest/commit binding and verdict accuracy against
ground truth over the committed fixtures (**100% completeness, 100% verdict accuracy, 8/8**). Remaining
vision: GUAC/Archivista publishing, cloud re-execution, multi-language (R/Julia/C), HPC/Slurm.

---


## What was validated

The Amber capture front-end was run end-to-end on **four real computational-research workloads**,
each in its own git repo with a pinned scientific stack, captured with `witness run` + the
introspective python-env attestor, then ingested:

| Example | Method | Stack | Result |
|---|---|---|---|
| `lorenz` | Lorenz attractor ODE integration | numpy, scipy | reproducible ✓ |
| `sir` | SIR epidemic model | numpy, scipy | reproducible ✓ |
| `sklearn_wine` | Random-Forest 5-fold CV on UCI Wine | numpy, scipy, scikit-learn | reproducible ✓ |
| `pysindy` | **downloaded** research package (SINDy model discovery) | pysindy + stack | reproducible ✓ |

Evidence is committed under `examples/research/<name>/` (`CAPTURE_REPORT.txt` + redacted
`fixtures/`). Each experiment was captured **twice in independent git repos**; the `result.json`
digests matched **bit-for-bit**, and the token-free tests in
`tests/darnit_reproducibility/test_amber_research_fixtures.py` ingest the real (redacted) bundles and
assert: correct dependency captured + hashed, experiment first-party & git-commit-bound, git commit
matches python-env, and the python-env digest verified. All 170 reproducibility-package tests pass.

Regenerate the evidence: `examples/research/capture_research.sh` (needs `witness`, the darnit venv,
and a scientific venv at `~/amber-research/.venv`).

---

## Improvements

### Track 1 — reproducibility loop (IMPLEMENTED — researcher-tool first build)

The full loop is built and demonstrated (`examples/repro-loop/run_loop.sh`): **capture → generate a
reproducible environment → rebuild in Docker → re-capture → verdict**.
- `analysis/compare.py` — `compare(original, reproduction) → ReproducibilityVerdict`
  (BIT_FOR_BIT / REPRODUCED_WITH_DRIFT / NOT_REPRODUCED / INCONCLUSIVE) with the environment
  differences ranked as likely causes.
- `generate/environment.py` — a pinned `requirements.lock` (from the *used* distributions) + a
  `Dockerfile` (base image from the captured Python, source at the captured commit).
- `attestation/reproducibility.py` — the `.../attestations/reproducibility/v1` predicate.
- *Result*: the Lorenz trajectory reproduced **bit-for-bit in a fresh container on a different Python
  patch (3.12.3 → 3.12.14)** — `REPRODUCED_WITH_DRIFT`, 100% artifact match. Capture stance is
  **baseline-first**: the loop runs anywhere Docker does (no witness/root inside the image); eBPF is
  the opt-in deep mode (Track 2). Tests: `test_amber_compare.py`, `test_amber_generate.py`.

### Implemented earlier (quick wins, with tests)

1. **Collection-type drift fixed** — `witness_attestation.py` keyed only on
   `witness.dev/attestation-collection/v0.1`, but witness v0.12 emits
   `witness.testifysec.com/attestation-collection/v0.1`. *Evidence*: every real bundle used the
   testifysec URL, so the existing CI consumer's `_nested_attestations` would have failed to unwrap
   current bundles. *Fix*: accept both (`_WITNESS_COLLECTION_TYPES`). Test added.

2. **Distribution attribution + "used" distributions** — many third-party modules reported
   `distribution: ?` (C-extension submodules like `_csparsetools`, `_loss` that
   `packages_distributions()` misses). *Fix*: path-based attribution via the site-packages directory
   (`_dist_for_path`), and a new `used_distributions` set (what the run actually exercised, versioned)
   distinct from everything installed. *Evidence*: sklearn report went from `_csparsetools (?)` to
   `_csparsetools (scipy)` and now prints `used deps: 6 exercised (…scikit-learn==1.5.1, scipy==1.13.1…)`.

### Recommended next (prioritized)

**P1 — capture faithfulness**

3. **Failed/errored runs produce no attestation.** *Evidence*: the first PySINDy run raised a
   `TypeError`; witness aborted the collection (`command-run failed: exit status 1`) and wrote **no
   bundle** — yet a failed reproduction is exactly what a researcher needs to debug. *Recommend*: run
   the traced command through a thin wrapper that always exits 0 while recording the real exit code
   (the python-env attestor already survives via `atexit`), or salvage a partial bundle, so
   non-zero-exit runs are still captured.

4. **`material` hashes the entire working directory** (incl. `.venv`, `.git`). *Evidence*: with an
   in-tree venv the demo showed "4203 files before"; moving the venv outside the repo root dropped it
   to 30. This is O(all files) and noisy. *Recommend*: keep the venv outside the captured root (the
   research runner already does), and add a material exclude-glob (witness supports it for `product`;
   request/《upstream》 it for `material`) or hash only the tracked source tree.

5. **eBPF network-trace under-counts on WSL2.** *Evidence*: a real `connect()` to `1.1.1.1:53`
   yielded `total_connections: 0` — the attestor loads and signs a valid trace, but its
   transparent-proxy redirect (`proxy_port 8888`) doesn't intercept raw sockets under the WSL2 kernel.
   *Recommend*: detect WSL and warn that network hermeticity is unreliable there; run network capture
   on a native Linux host / CI runner; verify the cgroup connect-redirect path.

**P2 — provenance depth**

6. **Per-distribution content hashes.** Today the python-env attestor hashes *loaded module files*;
   for SBOM-grade provenance also record each used distribution's `RECORD`/dist-info digest.
7. **Real signing.** Captures use an ephemeral file key. Wire Sigstore keyless (Fulcio + Rekor) via
   the harness's `--signer-flags` so bundles are independently verifiable (and consumable by the
   existing `witness_attestation._verify_bundle`).
8. **eBPF process/file tracer (the hybrid).** Fill `CaptureRecord.ebpf_file_access` from a
   process/file/dlopen trace and cross-check it against the introspective python-env attestor —
   catching libraries loaded outside the Python import system (native `dlopen`, subprocess tools).

**P3 — product surface**

9. **Inputs vs outputs.** Classify captured subjects into input data vs produced artifacts so data
   provenance is explicit (research runs are data-in / result-out).
10. **darnit integration.** Expose `capture`/`ingest` as darnit MCP tools + a control
    (`RE-01.03 RuntimeProvenanceCaptured`) that passes when a verifiable Amber bundle exists, folding
    capture into `darnit audit`.
11. **Reproducibility verdict.** ✅ **Done** — see Track 1 above (`analysis/compare.py` +
    `examples/repro-loop/`). Remaining extension: *semantic* reproducibility (floating-point tolerance
    / domain-aware comparison) on top of the current bit-for-bit + drift-explained verdict.

---

*All findings above are sourced from the real capture runs in this validation; the two implemented
fixes ship with tests and refreshed committed evidence.*
