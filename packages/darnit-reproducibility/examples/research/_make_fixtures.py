#!/usr/bin/env python3
"""Turn a real Amber capture into a committable, privacy-safe test fixture.

A raw Witness bundle embeds the capturing machine's env-var *values*, home paths, hostname and
username. This redacts those while preserving the evidence that matters (attestor structure, file
digests, the installed distributions, the loaded library objects and their hashes, the git commit),
re-encodes the payload into an *unsigned* DSSE envelope (the ingestor verifies by digest, not
signature), and keeps the python-env digest self-consistent so ``digest_verified`` still holds.

    _make_fixtures.py <captured_bundle.json> <captured_amber-pylibs.json> <out_dir> [--home /home/x]

Writes ``bundle.redacted.json`` + ``amber-pylibs.redacted.json`` into <out_dir>.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

REDACTED = "<redacted>"


def _scrub_str(s: str, home: str) -> str:
    return s.replace(home, "~")


def _scrub(obj: Any, home: str) -> Any:
    if isinstance(obj, str):
        return _scrub_str(obj, home)
    if isinstance(obj, list):
        return [_scrub(x, home) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub(v, home) for k, v in obj.items()}
    return obj


def redact_bundle(bundle_path: Path, pylibs_path: Path, out_dir: Path, home: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. redact the python-env predicate (paths under home -> ~) and write it first, so we can pin
    #    its new digest into the product attestor below.
    pylibs = json.loads(pylibs_path.read_text())
    pylibs = _scrub(pylibs, home)
    red_pylibs = out_dir / "amber-pylibs.redacted.json"
    red_pylibs.write_text(json.dumps(pylibs, indent=2, sort_keys=True))
    new_pylibs_sha = hashlib.sha256(red_pylibs.read_bytes()).hexdigest()

    # 2. decode the DSSE payload -> in-toto collection statement
    env = json.loads(bundle_path.read_text())
    statement = json.loads(base64.b64decode(env["payload"]))

    for a in statement.get("predicate", {}).get("attestations", []):
        name = a.get("type", "")
        body = a.get("attestation", {})
        if "/environment/" in name and isinstance(body, dict):
            body["hostname"] = "host"
            body["username"] = "researcher"
            if isinstance(body.get("variables"), dict):
                body["variables"] = dict.fromkeys(body["variables"], REDACTED)
        elif "/product/" in name and isinstance(body, dict):
            # keep result.json's real digest; repin amber-pylibs.json to the redacted file's digest
            if "amber-pylibs.json" in body and isinstance(body["amber-pylibs.json"], dict):
                body["amber-pylibs.json"].setdefault("digest", {})["sha256"] = new_pylibs_sha
    statement = _scrub(statement, home)

    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    red_env = {"payload": payload, "payloadType": "application/vnd.in-toto+json", "signatures": []}
    (out_dir / "bundle.redacted.json").write_text(json.dumps(red_env, indent=2))
    print(f"wrote fixtures to {out_dir}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("bundle")
    p.add_argument("pylibs")
    p.add_argument("out_dir")
    p.add_argument("--home", default=os.path.expanduser("~"))
    args = p.parse_args(argv)
    redact_bundle(Path(args.bundle), Path(args.pylibs), Path(args.out_dir), args.home)
    return 0


if __name__ == "__main__":
    sys.exit(main())
