#!/usr/bin/env bash
# Capture Amber provenance for each research example, prove reproducibility, and (re)generate the
# committed evidence: CAPTURE_REPORT.txt + fixtures/{bundle,amber-pylibs}.redacted.json.
#
# Each example is captured in TWO fresh git repos; the two result.json digests are compared to
# demonstrate bit-for-bit reproducibility. Run A's (redacted) bundle becomes the test fixture.
#
# Env: DARNIT_PY (python with darnit_reproducibility installed), RVENV (shared scientific venv),
#      WITNESS (witness binary), OUT (scratch dir). Defaults target this machine's layout.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DARNIT_PY="${DARNIT_PY:-$([ -x "$HOME/darnit-venv/bin/python" ] && echo "$HOME/darnit-venv/bin/python" || echo python3)}"
RVENV="${RVENV:-$HOME/amber-research/.venv}"
export WITNESS="${WITNESS:-$(command -v witness || echo "$HOME/.local/bin/witness")}"
OUT="${OUT:-$HOME/amber-research/out}"
EXAMPLES="${EXAMPLES:-lorenz sir sklearn_wine pysindy}"

[ -x "$RVENV/bin/python" ] || { echo "shared venv missing at $RVENV (create it with the pinned requirements)"; exit 1; }

_capture() {  # <example> <dest> -> runs one capture, echoes result.json sha256
  local name="$1" dest="$2"
  rm -rf "$dest"; mkdir -p "$dest"
  # per-example requirements (e.g. pysindy) override the shared scientific stack; install into the
  # shared venv so the captured library objects match, and ship the file for the lockfiles attestor.
  local reqs="$HERE/requirements.txt"
  [ -f "$HERE/$name/requirements.txt" ] && reqs="$HERE/$name/requirements.txt"
  "$RVENV/bin/pip" install -q -r "$reqs" >/dev/null 2>&1 || true
  cp "$HERE/$name/experiment.py" "$reqs" "$dest/"
  ( cd "$dest"
    git init -q
    git -c user.email=demo@amber -c user.name="amber" add -A
    git -c user.email=demo@amber -c user.name="amber" commit -qm "$name experiment"
    "$DARNIT_PY" -m darnit_reproducibility.capture.run \
        --step "amber-$name" -o "$dest/bundle.json" --repo-root "$dest" --no-ebpf \
        -- "$RVENV/bin/python" experiment.py >/dev/null 2>&1 )
  sha256sum "$dest/result.json" | awk '{print $1}'
}

echo "== witness: $("$WITNESS" version | head -1)"
for name in $EXAMPLES; do
  echo "== $name =="
  a="$OUT/$name/A"; b="$OUT/$name/B"
  sha_a="$(_capture "$name" "$a")"
  sha_b="$(_capture "$name" "$b")"
  if [ "$sha_a" = "$sha_b" ]; then
    echo "   reproducible: result.json bit-for-bit identical across two captures ($sha_a)"
  else
    echo "   NOT reproducible: $sha_a != $sha_b"
  fi
  # redacted fixtures from run A, then a report rendered FROM the redacted fixture (so the committed
  # report leaks no hostname/username/home path).
  "$DARNIT_PY" "$HERE/_make_fixtures.py" "$a/bundle.json" "$a/amber-pylibs.json" "$HERE/$name/fixtures" >/dev/null
  "$DARNIT_PY" -m darnit_reproducibility.ingest.witness \
      "$HERE/$name/fixtures/bundle.redacted.json" --pylibs "$HERE/$name/fixtures/amber-pylibs.redacted.json" \
      > "$HERE/$name/CAPTURE_REPORT.txt"
  echo "reproducible_result_sha256: $sha_a (verified across two independent captures)" >> "$HERE/$name/CAPTURE_REPORT.txt"
  echo "   wrote $name/CAPTURE_REPORT.txt and $name/fixtures/"
done
echo "== done: research evidence regenerated under $HERE/*/"
