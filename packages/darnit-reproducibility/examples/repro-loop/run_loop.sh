#!/usr/bin/env bash
# Amber closed reproducibility loop, end to end:
#   1. capture an experiment on the host                     (original)
#   2. GENERATE a Dockerfile + pinned lockfile from it       (darnit_reproducibility.generate)
#   3. docker build the reproducible image and re-run inside (reproduction)
#   4. COMPARE the two captures -> reproducibility verdict   (darnit_reproducibility.analysis.compare)
#
# The reproduction is captured with the pure-Python probe (no witness/git/root needed inside the
# image), so the loop runs anywhere Docker does. Verdict = BIT_FOR_BIT / REPRODUCED_WITH_DRIFT /
# NOT_REPRODUCED (with the environment differences ranked as causes).
#
# Env: NAME (example under examples/research, default lorenz), DARNIT_PY, RVENV (host science venv).
set -euo pipefail

NAME="${1:-${NAME:-lorenz}}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PKG_SRC="$(cd "$HERE/../.." && pwd)/src"
CAP="$PKG_SRC/darnit_reproducibility/capture"
RESEARCH="$(cd "$HERE/.." && pwd)/research"
DARNIT_PY="${DARNIT_PY:-$([ -x "$HOME/darnit-venv/bin/python" ] && echo "$HOME/darnit-venv/bin/python" || echo python3)}"
RVENV="${RVENV:-$HOME/amber-research/.venv}"
WORK="${WORK:-$HOME/amber-loop/$NAME}"

command -v docker >/dev/null || { echo "docker required"; exit 1; }
[ -f "$RESEARCH/$NAME/experiment.py" ] || { echo "unknown example: $NAME"; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK"
# pure-Python capture shim (sitecustomize + pyprobe) for the in-container reproduction
SHIM="$WORK/shim"; mkdir -p "$SHIM"
cp "$CAP/_sitecustomize.py" "$SHIM/sitecustomize.py"; cp "$CAP/pyprobe.py" "$SHIM/pyprobe.py"

echo "== 1. ORIGINAL capture (host) =="
O="$WORK/original"; mkdir -p "$O"
cp "$RESEARCH/$NAME/experiment.py" "$O/"
[ -f "$RESEARCH/$NAME/requirements.txt" ] && cp "$RESEARCH/$NAME/requirements.txt" "$O/" || cp "$RESEARCH/requirements.txt" "$O/"
( cd "$O"
  git init -q; git -c user.email=a@a -c user.name=a add -A; git -c user.email=a@a -c user.name=a commit -qm orig
  "$DARNIT_PY" -m darnit_reproducibility.capture.run --step "orig-$NAME" -o "$O/bundle.json" \
      --repo-root "$O" --no-ebpf -- "$RVENV/bin/python" experiment.py >/dev/null 2>&1 )

echo "== 2. GENERATE reproducible environment =="
G="$WORK/repro"; mkdir -p "$G"
cp "$RESEARCH/$NAME/experiment.py" "$G/"
"$DARNIT_PY" -m darnit_reproducibility.generate.environment "$O/bundle.json" \
    --pylibs "$O/amber-pylibs.json" --target docker --out-dir "$G"

echo "== 3. docker build + re-run inside the image =="
docker build -q -t "amber-loop-$NAME" "$G" >/dev/null
mkdir -p "$G/out"
docker run --rm -v "$G/out:/out" -v "$SHIM:/shim:ro" "amber-loop-$NAME" \
    bash -c 'cd /work && PYTHONPATH=/shim AMBER_PYLIBS_OUT=/out/amber-pylibs.json AMBER_REPO_ROOT=/work \
             python experiment.py >/dev/null && cp result.json /out/result.json'

echo "== 4. COMPARE -> verdict =="
"$DARNIT_PY" - "$O/bundle.json" "$O/amber-pylibs.json" "$G/out/amber-pylibs.json" "$G/out/result.json" "$WORK/verdict.intoto.json" <<'PY'
import hashlib, json, sys, dataclasses
from darnit_reproducibility.ingest import witness as ing
from darnit_reproducibility.analysis import compare as cmp
from darnit_reproducibility.attestation import reproducibility as att
from darnit_reproducibility.models import CaptureRecord, PythonEnv, FolderStasis, FileDigest

bundleO, pyO, pyR, resR, verdict_out = sys.argv[1:6]
original = ing.load(bundleO, pyO)

pred = json.load(open(pyR))["predicate"]
sha = "sha256:" + hashlib.sha256(open(resR, "rb").read()).hexdigest()
reproduction = CaptureRecord(
    folder_stasis=FolderStasis(added=[FileDigest(path="result.json", sha256=sha)]),
    python_env=PythonEnv(captured=True, version=pred["python"]["version"],
                         platform=pred["python"]["platform"],
                         used_distributions=pred.get("used_distributions", [])),
)
verdict = cmp.compare(original, reproduction)
print(cmp.render(verdict))
json.dump(att.statement(original, reproduction, verdict), open(verdict_out, "w"), indent=2, default=str)
print("\nwrote reproducibility attestation:", verdict_out)
PY
