"""Reproducibility verdict: compare an original capture with a reproduction attempt.

This is the payoff of capture — it turns "we recorded the run" into "we proved (or disproved) that the
run reproduces, and here's why." Operates purely on two normalized ``CaptureRecord``s, so it works for
any capture (local, container, CI) without re-reading source.

Verdict levels:
- ``BIT_FOR_BIT``            every produced output has an identical digest.
- ``REPRODUCED_WITH_DRIFT``  outputs identical, but the environment differed (a *robust* reproduction).
- ``NOT_REPRODUCED``         outputs differ; ``discrepancies`` ranks the environment differences as
                             candidate causes.
- ``INCONCLUSIVE``           nothing comparable (no shared produced artifacts).
"""
from __future__ import annotations

import json
import math
from pathlib import Path

from ..models import (
    ArtifactComparison,
    CaptureRecord,
    EnvDiff,
    ReproducibilityVerdict,
    VersionDrift,
)

# Files Amber itself writes into the workdir — not part of the experiment's real output.
_TOOLING = frozenset({"amber-pylibs.json", "amber-ephemeral-key.pem", "bundle.json",
                      "requirements.lock", "Dockerfile"})


def _real_outputs(rec: CaptureRecord) -> dict[str, str | None]:
    """name -> sha256 for the files the run created/changed, excluding Amber's own tooling files."""
    out: dict[str, str | None] = {}
    for fd in rec.folder_stasis.added + rec.folder_stasis.changed:
        base = fd.path.rsplit("/", 1)[-1]
        if base in _TOOLING:
            continue
        out[fd.path] = fd.sha256
    return out


def _used_versions(rec: CaptureRecord) -> dict[str, str | None]:
    return {d.get("name"): d.get("version") for d in rec.python_env.used_distributions if d.get("name")}


def _env_diff(original: CaptureRecord, reproduction: CaptureRecord) -> EnvDiff:
    o, r = _used_versions(original), _used_versions(reproduction)
    drift = [VersionDrift(n, o[n], r[n]) for n in sorted(o.keys() & r.keys()) if o[n] != r[n]]
    missing = sorted(o.keys() - r.keys())
    added = sorted(r.keys() - o.keys())
    py = (original.python_env.version, reproduction.python_env.version)
    plat = (original.python_env.platform, reproduction.python_env.platform)
    identical = not drift and not missing and not added and py[0] == py[1]
    return EnvDiff(python_version=py, platform=plat, version_drift=drift,
                   missing=missing, added=added, identical=identical)


def _values_close(a: object, b: object, rel_tol: float) -> bool:
    """Structural equality where numbers may differ within ``rel_tol`` (floating-point tolerance)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isclose(float(a), float(b), rel_tol=rel_tol, abs_tol=abs(rel_tol))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_values_close(a[k], b[k], rel_tol) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_values_close(x, y, rel_tol) for x, y in zip(a, b, strict=True))
    return a == b


def bundle_is_signed(path: str | Path) -> bool:
    """True if a capture bundle carries a signature with a (keyless) certificate."""
    try:
        env = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return False
    return any(s.get("certificate") for s in (env.get("signatures") or []) if isinstance(s, dict))


def _semantic_equal_files(po: Path, pr: Path, rel_tol: float) -> bool | None:
    """True/False if both files are JSON and numerically equal within tolerance; None if not JSON."""
    try:
        a = json.loads(po.read_text())
        b = json.loads(pr.read_text())
    except (OSError, ValueError):
        return None
    return _values_close(a, b, rel_tol)


def _numerical_discrepancies(o: CaptureRecord, r: CaptureRecord) -> list[str]:
    """Numerical/hardware differences that commonly cause research non-reproducibility."""
    out: list[str] = []
    on, rn = o.numerical or {}, r.numerical or {}
    ob = (on.get("blas") or {}).get("name")
    rb = (rn.get("blas") or {}).get("name")
    if ob != rb:
        out.append(f"BLAS backend: {ob} -> {rb}")
    ote, rte = on.get("thread_env") or {}, rn.get("thread_env") or {}
    for k in sorted(set(ote) | set(rte)):
        if ote.get(k) != rte.get(k):
            out.append(f"thread cap {k}: {ote.get(k)} -> {rte.get(k)}")
    if on.get("pythonhashseed") != rn.get("pythonhashseed"):
        out.append(f"PYTHONHASHSEED: {on.get('pythonhashseed')} -> {rn.get('pythonhashseed')}")
    osimd = (o.hardware or {}).get("cpu", {}).get("simd")
    rsimd = (r.hardware or {}).get("cpu", {}).get("simd")
    if osimd is not None and rsimd is not None and osimd != rsimd:
        out.append(f"CPU SIMD: {osimd} -> {rsimd}")
    return out


def compare(original: CaptureRecord, reproduction: CaptureRecord, *,
            original_dir: str | Path | None = None, reproduction_dir: str | Path | None = None,
            rel_tol: float = 1e-9) -> ReproducibilityVerdict:
    o_out, r_out = _real_outputs(original), _real_outputs(reproduction)
    names = sorted(o_out.keys() | r_out.keys())

    artifacts: list[ArtifactComparison] = []
    matched = 0
    for name in names:
        osha, rsha = o_out.get(name), r_out.get(name)
        m = osha is not None and osha == rsha
        matched += int(m)
        sem: bool | None = None
        # When digests differ and both output files are on disk, try a semantic (numeric) compare.
        if not m and osha and rsha and original_dir and reproduction_dir:
            base = name.rsplit("/", 1)[-1]
            sem = _semantic_equal_files(Path(original_dir) / base, Path(reproduction_dir) / base, rel_tol)
        artifacts.append(ArtifactComparison(name=name, original_sha256=osha,
                                            reproduction_sha256=rsha, match=m, semantic_match=sem))

    env = _env_diff(original, reproduction)
    comparable = [a for a in artifacts if a.original_sha256 and a.reproduction_sha256]
    rate = (matched / len(names)) if names else 0.0
    bit_for_bit = bool(names) and matched == len(names)
    semantically = (bool(comparable) and all(a.match or a.semantic_match for a in comparable)
                    and any(a.semantic_match for a in comparable))

    if not comparable:
        level, summary = "INCONCLUSIVE", "no shared produced artifacts to compare"
    elif bit_for_bit and env.identical:
        level, summary = "BIT_FOR_BIT", "all outputs identical; environment identical"
    elif bit_for_bit:
        level, summary = ("REPRODUCED_WITH_DRIFT",
                          "all outputs identical despite environment differences (robust reproduction)")
    elif semantically:
        level, summary = ("SEMANTICALLY_REPRODUCED",
                          f"outputs differ byte-for-byte but are numerically equal within {rel_tol:g}")
    else:
        level, summary = "NOT_REPRODUCED", f"{matched}/{len(names)} outputs matched"

    discrepancies: list[str] = []
    if level == "NOT_REPRODUCED":
        # Rank environment differences as candidate causes of the divergence.
        for d in env.version_drift:
            discrepancies.append(f"dependency drift: {d.name} {d.original} -> {d.reproduction}")
        if env.python_version[0] != env.python_version[1]:
            discrepancies.append(f"python {env.python_version[0]} -> {env.python_version[1]}")
        for n in env.missing:
            discrepancies.append(f"dependency missing in reproduction: {n}")
        for n in env.added:
            discrepancies.append(f"dependency added in reproduction: {n}")
        discrepancies.extend(_numerical_discrepancies(original, reproduction))
        if not discrepancies:
            discrepancies.append("outputs differ but no environment difference detected — "
                                 "likely nondeterminism (unseeded RNG, timestamps, thread order)")

    return ReproducibilityVerdict(
        level=level, bit_for_bit=bit_for_bit, reproduction_rate=rate,
        artifacts=artifacts, env=env, discrepancies=discrepancies, summary=summary,
    )


def render(verdict: ReproducibilityVerdict) -> str:
    icon = {"BIT_FOR_BIT": "✅", "REPRODUCED_WITH_DRIFT": "✅", "SEMANTICALLY_REPRODUCED": "≈",
            "NOT_REPRODUCED": "❌", "INCONCLUSIVE": "⚠️"}.get(verdict.level, "?")
    L = ["=" * 68, "REPRODUCIBILITY VERDICT", "=" * 68,
         f"{icon} {verdict.level} — {verdict.summary}",
         f"reproduction rate: {verdict.reproduction_rate:.0%}", "", "artifacts:"]
    for a in verdict.artifacts:
        mark = "=" if a.match else ("≈" if a.semantic_match else "≠")
        L.append(f"  {mark} {a.name}  {(a.original_sha256 or '-')[:20]} {mark} {(a.reproduction_sha256 or '-')[:20]}")
    e = verdict.env
    L.append("")
    L.append(f"environment: python {e.python_version[0]} -> {e.python_version[1]}; "
             f"{len(e.version_drift)} drifted, {len(e.missing)} missing, {len(e.added)} added"
             + (" (identical)" if e.identical else ""))
    for d in e.version_drift[:10]:
        L.append(f"  ~ {d.name}: {d.original} -> {d.reproduction}")
    if verdict.discrepancies:
        L.append("")
        L.append("likely causes:")
        L.extend(f"  - {d}" for d in verdict.discrepancies)
    L.append("=" * 68)
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    import argparse

    from ..ingest import witness as ing

    p = argparse.ArgumentParser(prog="amber-verify",
                                description="Compare two Amber capture bundles to a reproducibility verdict.")
    p.add_argument("original")
    p.add_argument("reproduction")
    p.add_argument("--original-pylibs", default=None)
    p.add_argument("--reproduction-pylibs", default=None)
    p.add_argument("--original-dir", default=None,
                   help="dir holding the original output files (default: alongside the bundle)")
    p.add_argument("--reproduction-dir", default=None,
                   help="dir holding the reproduction output files (default: alongside the bundle)")
    p.add_argument("--rel-tol", type=float, default=1e-9,
                   help="relative tolerance for the semantic (numeric) comparison")
    p.add_argument("--require-signed", action="store_true",
                   help="fail unless BOTH capture bundles are Sigstore-signed")
    p.add_argument("--attestation-out", default=None,
                   help="write the reproducibility attestation (in-toto predicate) to this path")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if args.require_signed:
        unsigned = [b for b in (args.original, args.reproduction) if not bundle_is_signed(b)]
        if unsigned:
            import sys
            sys.stderr.write(f"verify: unsigned bundle(s): {', '.join(unsigned)}\n")
            return 3

    o = ing.load(args.original, args.original_pylibs)
    r = ing.load(args.reproduction, args.reproduction_pylibs)
    verdict = compare(
        o, r, rel_tol=args.rel_tol,
        original_dir=args.original_dir or str(Path(args.original).resolve().parent),
        reproduction_dir=args.reproduction_dir or str(Path(args.reproduction).resolve().parent),
    )
    if args.attestation_out:
        from ..attestation import reproducibility as att
        Path(args.attestation_out).write_text(
            json.dumps(att.statement(o, r, verdict), indent=2, default=str))
        print(f"wrote reproducibility attestation: {args.attestation_out}")

    if args.json:
        import dataclasses
        print(json.dumps(dataclasses.asdict(verdict), indent=2, default=str))
    else:
        print(render(verdict))
    # exit code: 0 reproduced (bit-for-bit / drift / semantic), 1 not reproduced, 2 inconclusive
    return {"BIT_FOR_BIT": 0, "REPRODUCED_WITH_DRIFT": 0, "SEMANTICALLY_REPRODUCED": 0,
            "NOT_REPRODUCED": 1, "INCONCLUSIVE": 2}.get(verdict.level, 2)


if __name__ == "__main__":
    import sys
    sys.exit(main())
