"""Known-vulnerability cross-check for a capture's *used* dependencies, via OSV.dev.

Answers "does this reproducible result depend on a library with a known vulnerability?" — the practical
safety question, and a bridge to darnit's compliance mission. Network access is isolated behind an
injectable poster so the logic is unit-tested offline; a network failure degrades to "unknown".
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ..models import CaptureRecord

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# A poster: (url, json_body) -> parsed json response.
Poster = Callable[[str, dict], dict]


def _default_post(url: str, body: dict) -> dict:
    import urllib.request
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 -- fixed OSV https endpoint
        return json.loads(resp.read())


def query_osv(used_distributions: list[dict[str, Any]], *, post: Poster | None = None) -> list[dict]:
    """Return [{package, version, vuln_ids:[...]}] for used deps OSV reports as vulnerable."""
    queries = [{"package": {"ecosystem": "PyPI", "name": d["name"]}, "version": d["version"]}
               for d in used_distributions if d.get("name") and d.get("version")]
    if not queries:
        return []
    resp = (post or _default_post)(OSV_BATCH_URL, {"queries": queries})
    results = resp.get("results", []) if isinstance(resp, dict) else []
    out: list[dict] = []
    for q, r in zip(queries, results, strict=False):
        vulns = (r or {}).get("vulns") or []
        if vulns:
            out.append({"package": q["package"]["name"], "version": q["version"],
                        "vuln_ids": [v.get("id") for v in vulns]})
    return out


def report(rec: CaptureRecord, *, post: Poster | None = None) -> dict[str, Any]:
    used = rec.python_env.used_distributions
    try:
        vulnerable = query_osv(used, post=post)
        status = "vulnerable" if vulnerable else "clean"
    except Exception as exc:  # noqa: BLE001 -- network/parse failure -> unknown, never a false clean
        return {"status": "unknown", "checked": len(used), "error": str(exc), "vulnerable": []}
    return {"status": status, "checked": len(used), "vulnerable": vulnerable}


def main(argv: list[str] | None = None) -> int:
    import argparse

    from ..ingest import witness as ing

    p = argparse.ArgumentParser(prog="amber-vulns",
                                description="Cross-check a capture's used deps against OSV.dev.")
    p.add_argument("bundle")
    p.add_argument("--pylibs", default=None)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    rec = ing.load(args.bundle, args.pylibs)
    rep = report(rec)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"OSV check: {rep['status']} — {rep['checked']} used deps, "
              f"{len(rep['vulnerable'])} vulnerable")
        for v in rep["vulnerable"]:
            print(f"  ! {v['package']}=={v['version']}: {', '.join(v['vuln_ids'])}")
    return 1 if rep["status"] == "vulnerable" else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
