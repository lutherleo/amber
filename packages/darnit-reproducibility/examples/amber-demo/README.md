# Amber capture demo

End-to-end demonstration of **Amber's Problem 1 (Capture)**: run a Python experiment and produce a
signed in-toto attestation that records the system, the folder state, the git repo, the Python
library objects actually loaded, and (via eBPF) the network activity — with **no edit to the
experiment**.

## Run it

```bash
# unprivileged (no eBPF network trace):
DARNIT_PY=~/darnit-venv/bin/python bash run_demo.sh

# with eBPF network-trace + process tracing (needs root; prompts for sudo):
DARNIT_PY=~/darnit-venv/bin/python bash run_demo.sh --ebpf
```

`DARNIT_PY` is any Python that has `darnit-reproducibility` installed (it runs the capture harness and
the ingestor). `WITNESS` overrides the witness binary path; `WORK` overrides the working directory.

The script (see `run_demo.sh`): materializes a git working copy of `experiment.py`, builds a venv with
pinned `numpy`, captures the run with `witness run` + the introspective python-env attestor, then
ingests the bundle and prints the **Amber Capture Report**.

## What you get

```
AMBER CAPTURE REPORT
 SYSTEM        : linux host=… user=… (N env vars)
 REPO          : commit=… branch=… dirty=… matches python-env
 COMMAND       : ./.venv/bin/python experiment.py -> exit 0
 FOLDER STASIS : files-before; created/changed (with sha256)
 PYTHON ENV    : CPython 3.12  (digest verified)
   modules     : 1 first-party (experiment, git-commit-bound), 105 third-party (numpy, hashed), stdlib
 NETWORK (eBPF): captured=… clean/…
```

Artifacts in `$WORK`: `bundle.json` (signed DSSE collection), `amber-pylibs.json` (the python-env
predicate, hashed into the bundle by the product attestor), `result.json` (the experiment output).

## How the capture works

- **Transparency**: the harness (`darnit_reproducibility.capture.run`) writes a `sitecustomize.py`
  shim + a standalone `pyprobe.py` into a temp dir and prepends it to `PYTHONPATH`. Python auto-runs
  `sitecustomize` at startup; an `atexit` hook records the loaded modules. The experiment is unchanged.
- **Attestors** (witness v0.12): `environment` (system), `material`+`product` (folder before/after),
  `git` (repo), `command-run`, plus the experimental `network-trace` (eBPF) with `--trace`.
- **Repo linkage**: the python-env attestor marks each loaded module first-party (under the git
  worktree) vs third-party (site-packages) vs stdlib, and records the commit. The ingestor verifies
  the git attestor's commit equals the python-env commit ("matches python-env").
- **Integrity**: the ingestor recomputes `amber-pylibs.json`'s sha256 and checks it against the
  digest the `product` attestor recorded ("digest verified").

## Notes & limits

- **eBPF needs root** — the harness re-invokes witness under `sudo` (preserving the capture env);
  `--no-ebpf` runs unprivileged.
- **WSL2**: eBPF attestors load (kernel 6.6 + BTF), but the `network-trace` proxy-redirect may not
  intercept every raw socket connection under the WSL2 kernel — the trace is produced and signed, but
  can under-count connections there. On a native Linux host it captures normally.
- The `material` attestor hashes **every** file in the working directory, so a large `.venv` inflates
  the "files before" count; that is expected witness behaviour.
- `experiment.py` uses a fixed NumPy seed, so a faithful reproduction yields a bit-for-bit identical
  `result.json` — the property later Amber phases (analyze → regenerate env → re-execute → compare)
  build on.
