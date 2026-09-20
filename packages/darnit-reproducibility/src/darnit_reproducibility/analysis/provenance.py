"""Custom-vs-distributed detection — is a used library a stock PyPI build, or locally patched?

The PDF's hard problem: two installs can share a version number yet differ in the actual code (a
locally rebuilt / patched wheel), which silently breaks reproducibility. We compare the hashes of the
module files the run *loaded* against the canonical PyPI wheel's ``RECORD`` hashes. All match → stock;
any mismatch → patched (flagged). Network is behind an injectable fetcher so the logic is unit-tested
offline.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..models import CaptureRecord

# A fetcher: (dist_name, version) -> {relative_path: "sha256:hex"} from the canonical wheel RECORD,
# or None when unavailable.
RecordFetcher = Callable[[str, str], "dict[str, str] | None"]


def _relpath_after_sitepackages(path: str) -> str | None:
    for seg in ("site-packages/", "dist-packages/"):
        i = path.find(seg)
        if i != -1:
            return path[i + len(seg):]
    return None


def classify(rec: CaptureRecord, *, record_fetcher: RecordFetcher | None = None) -> list[dict[str, Any]]:
    """Per used distribution: 'stock' | 'patched' | 'unknown', from loaded-file vs RECORD hashes."""
    fetch = record_fetcher or _default_record_fetcher
    versions = {d.get("name"): d.get("version") for d in rec.python_env.used_distributions}
    by_dist: dict[str, list] = {}
    for m in rec.python_env.third_party:
        if m.distribution and m.sha256:
            by_dist.setdefault(m.distribution, []).append(m)

    results: list[dict[str, Any]] = []
    for dist, mods in sorted(by_dist.items()):
        ver = versions.get(dist)
        record = fetch(dist, ver) if ver else None
        if not record:
            results.append({"distribution": dist, "version": ver, "status": "unknown",
                            "reason": "no canonical RECORD available", "checked": 0})
            continue
        mismatched: list[str] = []
        checked = 0
        for m in mods:
            rel = _relpath_after_sitepackages(m.path)
            if rel is None or rel not in record:
                continue
            checked += 1
            if record[rel] != m.sha256:
                mismatched.append(rel)
        status = "unknown" if checked == 0 else ("patched" if mismatched else "stock")
        results.append({"distribution": dist, "version": ver, "status": status,
                        "checked": checked, "mismatched": mismatched})
    return results


def _default_record_fetcher(name: str, version: str) -> dict[str, str] | None:  # pragma: no cover
    """Best-effort: download the matching PyPI wheel and read its RECORD → {relpath: sha256:hex}.

    Prefers a wheel whose tag matches this interpreter/platform; falls back to any wheel. Any failure
    (offline, no wheel, parse error) returns None → the distribution is reported 'unknown'."""
    import base64
    import csv
    import io
    import json
    import platform as _platform
    import sysconfig
    import urllib.request
    import zipfile

    try:
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        with urllib.request.urlopen(url, timeout=20) as r:  # noqa: S310
            meta = json.loads(r.read())
        wheels = [u for u in meta.get("urls", []) if u.get("packagetype") == "bdist_wheel"]
        if not wheels:
            return None
        # Match the wheel to THIS interpreter/platform. Comparing against a wrong-platform wheel yields
        # false "patched" results (platform-specific files differ), so if nothing matches we return None
        # (-> reported "unknown") rather than guess — conservative-by-default.
        pytag = f"cp{sysconfig.get_python_version().replace('.', '')}"
        arch = _platform.machine()  # e.g. x86_64

        def _compatible(fn: str) -> bool:
            if fn.endswith("none-any.whl"):
                return True  # pure-python wheel matches any platform
            return pytag in fn and arch in fn and "linux" in fn  # manylinux / musllinux

        compatible = [w for w in wheels if _compatible(w["filename"])]
        best = (next((w for w in compatible if w["filename"].endswith("none-any.whl")), None)
                or (compatible[0] if compatible else None))
        if best is None:
            return None
        with urllib.request.urlopen(best["url"], timeout=60) as r:  # noqa: S310
            blob = r.read()
        out: dict[str, str] = {}
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            record_name = next((n for n in zf.namelist() if n.endswith(".dist-info/RECORD")), None)
            if not record_name:
                return None
            for row in csv.reader(io.TextIOWrapper(zf.open(record_name), "utf-8")):
                if len(row) >= 2 and row[1].startswith("sha256="):
                    b64 = row[1][len("sha256="):]
                    digest = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)).hex()
                    out[row[0]] = "sha256:" + digest
        return out or None
    except Exception:  # noqa: BLE001 -- best-effort; unavailable RECORD -> unknown
        return None


def main(argv: list[str] | None = None) -> int:
    import argparse

    from ..ingest import witness as ing

    p = argparse.ArgumentParser(
        prog="amber-provenance",
        description="Detect locally-patched (vs stock PyPI) library builds in a capture.")
    p.add_argument("bundle")
    p.add_argument("--pylibs", default=None)
    args = p.parse_args(argv)

    rec = ing.load(args.bundle, args.pylibs)
    rows = classify(rec)
    patched = [r for r in rows if r["status"] == "patched"]
    print(f"custom-vs-distributed: {len(rows)} distributions checked, {len(patched)} patched")
    for r in rows:
        mark = {"stock": "✓", "patched": "✗", "unknown": "?"}[r["status"]]
        print(f"  {mark} {r['distribution']}=={r['version']}: {r['status']}"
              + (f" ({len(r['mismatched'])} files differ)" if r.get("mismatched") else ""))
    return 1 if patched else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
