"""CycloneDX SBOM from an Amber capture — the *used* distributions, as a standard supply-chain doc.

Unlike a static SBOM (everything installed), this lists only what the run actually imported, so it is
a precise bill of materials for the captured computation. Feeds any CycloneDX-aware tool (GUAC, vuln
scanners, policy).
"""
from __future__ import annotations

from typing import Any

from ..models import CaptureRecord


def to_cyclonedx(rec: CaptureRecord) -> dict[str, Any]:
    components = []
    for d in sorted(rec.python_env.used_distributions, key=lambda x: (x.get("name") or "").lower()):
        name, ver = d.get("name"), d.get("version")
        if not name:
            continue
        comp: dict[str, Any] = {"type": "library", "name": name, "bom-ref": f"pkg:pypi/{name}"}
        if ver:
            comp["version"] = ver
            comp["purl"] = f"pkg:pypi/{name}@{ver}"
        components.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "darnit", "name": "darnit-reproducibility", "version": "0.1.0"}],
            "component": {"type": "application",
                          "name": rec.repo.remotes.get("origin", rec.repo.commit or "captured-run"),
                          "version": rec.repo.commit or "unknown"},
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    from ..ingest import witness as ing

    p = argparse.ArgumentParser(prog="amber-sbom",
                                description="Emit a CycloneDX SBOM of the used distributions.")
    p.add_argument("bundle")
    p.add_argument("--pylibs", default=None)
    p.add_argument("-o", "--out", default=None, help="write to a file instead of stdout")
    args = p.parse_args(argv)

    rec = ing.load(args.bundle, args.pylibs)
    bom = to_cyclonedx(rec)
    text = json.dumps(bom, indent=2)
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(text)
        print(f"wrote {args.out} ({len(bom['components'])} components)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
