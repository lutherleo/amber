# Vendored `witness` binary (for the Amber per-project container)

[`witness`](https://github.com/in-toto/witness) is the attestation/provenance engine the
Amber capture pipeline wraps (`amber capture` shells out to `witness run`). The Amber
per-project container (`darnit_reproducibility.research.container`) bakes it into the image.

To make container builds **network-free and version-pinned**, the signed upstream release
is vendored here instead of being downloaded from GitHub at build time.

| File | What it is |
|------|------------|
| `witness_0.12.0_linux_amd64.tar.gz` | Upstream release archive (contains the `witness` binary, its `LICENSE`, `README.md`) |
| `witness_0.12.0_checksums.txt` | Upstream SHA-256 checksums for all v0.12.0 assets |
| `witness_0.12.0_linux_amd64.tar.gz.sigstore.json` | Upstream Sigstore bundle (keyless signature) for the archive |
| `LICENSE` | Apache-2.0 (witness upstream license) |

- **Version:** v0.12.0 (matches the `WITNESS_VERSION` pinned in `research/container.py`).
- **Source:** https://github.com/in-toto/witness/releases/tag/v0.12.0
- **License:** Apache-2.0.
- **Platform:** `linux_amd64` (the container base is `python:3.12-slim-bookworm`, linux/amd64).
- **SHA-256 (`witness_0.12.0_linux_amd64.tar.gz`):**
  `543d05898731fe5b9c176443ec596a0242bd27f0b327d73aff60f6f7398b7dd0`
  — verified equal to the upstream `witness_0.12.0_checksums.txt` entry on vendoring.

## How the container uses it

The container Dockerfile `COPY`s the archive, re-verifies the SHA-256 against
`witness_0.12.0_checksums.txt`, extracts `witness` to `/usr/local/bin/witness`, and
`chmod +x`. No `curl`/network step for witness.

To refresh: download the new release's `*_linux_amd64.tar.gz`, `*_checksums.txt`, and
`*.sigstore.json`, re-verify, update the version here and in `research/container.py`.
