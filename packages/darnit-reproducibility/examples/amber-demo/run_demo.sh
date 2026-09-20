#!/usr/bin/env bash
# Amber capture demo — end to end on one Python experiment.
#
#   1. materialize a git working copy of the experiment (repo linkage needs a commit)
#   2. build a venv with pinned deps (numpy) so libraries are reproducible
#   3. capture the run with `witness run` + the introspective python-env attestor
#   4. ingest the signed bundle and print the Amber Capture Report
#
# Requires: witness on PATH (or $WITNESS), python3, git, openssl. eBPF attestors (network-trace +
# --trace) need root, so they are OFF by default; pass --ebpf (and expect a sudo prompt) to enable.
#
# Env overrides:
#   WITNESS    path to the witness binary          (default: `witness` on PATH, then ~/.local/bin)
#   DARNIT_PY  python that has darnit_reproducibility installed, used to run the harness + ingestor
#              (default: ~/darnit-venv/bin/python, then `python3`)
#   WORK       working directory                    (default: ~/amber-demo-run)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/amber-demo-run}"
WITNESS="${WITNESS:-$(command -v witness || echo "$HOME/.local/bin/witness")}"
DARNIT_PY="${DARNIT_PY:-$([ -x "$HOME/darnit-venv/bin/python" ] && echo "$HOME/darnit-venv/bin/python" || echo python3)}"

NO_EBPF="--no-ebpf"
if [ "${1:-}" = "--ebpf" ] || [ "${AMBER_EBPF:-}" = "1" ]; then NO_EBPF=""; fi

echo "== witness: $WITNESS"; "$WITNESS" version | head -1
echo "== harness/ingest python: $DARNIT_PY"

# 1. git working copy of the experiment
rm -rf "$WORK"; mkdir -p "$WORK"
cp "$HERE/experiment.py" "$HERE/requirements.txt" "$WORK/"
cd "$WORK"
git init -q
git -c user.email=demo@amber -c user.name="amber demo" add -A
git -c user.email=demo@amber -c user.name="amber demo" commit -qm "amber demo experiment"

# 2. pinned venv
python3 -m venv .venv
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -r requirements.txt

# 3. capture (harness copies the shim + pyprobe, wraps witness run)
echo "== capturing with witness ${NO_EBPF:-(eBPF ON)} =="
"$DARNIT_PY" -m darnit_reproducibility.capture.run \
    --step amber-demo -o "$WORK/bundle.json" --repo-root "$WORK" $NO_EBPF \
    -- ./.venv/bin/python experiment.py

# 4. ingest + report
echo
"$DARNIT_PY" -m darnit_reproducibility.ingest.witness "$WORK/bundle.json"
echo
echo "artifacts in $WORK: bundle.json, amber-pylibs.json, result.json"
