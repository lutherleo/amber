# darnit-reproducibility

Scientific reproducibility for darnit — **compliance checks** *and* **Amber**, a provenance-capture and
reproducibility-verification toolchain for computational research.

## Amber (`amber` CLI)

Capture a run's full environment, verify it reproduces, and generate a reproducible environment — with
no changes to the experiment. Baseline capture is pure-Python (runs anywhere, no root); eBPF is an
opt-in deep mode on Linux/CI.

```bash
amber capture --step run -o .amber/bundle.json -- python experiment.py   # capture provenance
amber ingest  .amber/bundle.json                                         # normalized capture report
amber generate .amber/bundle.json --target docker --out-dir env/          # reproducible environment
amber verify   original.json reproduction.json                            # reproducibility verdict
amber sbom .amber/bundle.json                                            # CycloneDX SBOM of used deps
amber vulns .amber/bundle.json                                           # OSV known-vuln cross-check
amber provenance .amber/bundle.json                                     # patched-vs-stock detection
amber eval                                                              # score capture completeness (dev/CI)
```

**Capture modes.** *Baseline* (default) is pure-Python and runs anywhere with no privileges. *Deep
mode* adds Witness's eBPF attestors (`--experimental --trace`, needs root) and Sigstore keyless signing
(`--sign`, needs an OIDC token) — its home is CI: see `.github/workflows/amber-capture.yml`, which
captures a research example with eBPF, signs it via the Actions OIDC identity, verifies it, and uploads
the bundle.

A capture records system info, folder state (before/after digests), the git commit, and the **Python
library objects actually loaded** (hashed, first-party vs third-party, git-bound). `verify` compares
two captures to a verdict — `BIT_FOR_BIT` / `REPRODUCED_WITH_DRIFT` / `NOT_REPRODUCED` (with the
environment differences ranked as causes) — and emits a signable
`.../attestations/reproducibility/v1` predicate. See `examples/repro-loop/` for the full
capture → generate → rebuild-in-docker → verify loop, and `examples/research/` for captures of real
scientific code (numpy/scipy/scikit-learn/pysindy). Design & roadmap: `docs/AMBER_IMPROVEMENTS.md`.

## Compliance controls

Eight controls across three maturity levels (run via `darnit audit`):
- RE-01.01 (L1) DependenciesPinned — lock files
- RE-01.02 (L1) BuildEnvDeclared — Dockerfile, Nix flake, etc.
- RE-01.03 (L1) RuntimeProvenanceCaptured — a verifiable Amber capture bundle exists
- RE-02.01 (L2) HermeticBuild — no live network fetches (Witness/Nix/Bazel signal)
- RE-02.02 (L2) ProvenanceExists — sigstore/cosign or SLSA provenance
- RE-02.03 (L2) CapturedDepsNoKnownVulns — the captured run's used deps have no OSV advisories
- RE-03.01 (L3) BitForBitReproducible — SOURCE_DATE_EPOCH / reprotest
- RE-03.02 (L3) ReproVerified — an Amber reproducibility verdict attestation shows a reproduction
