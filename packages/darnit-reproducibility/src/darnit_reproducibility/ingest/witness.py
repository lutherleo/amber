"""Witness ingestor: a signed capture bundle -> one normalized ``CaptureRecord`` (+ a text report).

Parses the DSSE-wrapped in-toto **collection** Witness emits (``witness run -o bundle.json``) and
maps each attestor to the normalized model in ``..models``:

- ``environment``  -> system info
- ``material`` + ``product`` -> folder stasis (before vs created/changed)
- ``git``          -> repo commit/branch/dirty (remotes come from the python-env attestor)
- ``command-run``  -> the executed command + exit code
- ``network-trace``-> eBPF network events (experimental attestor)
- sibling ``amber-pylibs.json`` (a product) -> python library objects, first/third-party, git-bound

Collection-type note: Witness v0.12 emits ``witness.testifysec.com/attestation-collection/v0.1``
while older bundles use ``witness.dev/attestation-collection/v0.1``; both are accepted here. (This is
also why we parse the collection directly instead of ``witness_attestation._nested_attestations``,
which keys on the older constant.) The network verdict reuses
``witness_attestation._check_network_cleanliness`` when that shared helper is importable.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from ..models import (
    CaptureRecord,
    CommandRun,
    FileDigest,
    FolderStasis,
    NetworkTrace,
    PyModule,
    PythonEnv,
    RepoInfo,
    SystemInfo,
)

_COLLECTION_TYPES = frozenset({
    "https://witness.testifysec.com/attestation-collection/v0.1",
    "https://witness.dev/attestation-collection/v0.1",
})


def _decode_dsse(raw: bytes) -> dict[str, Any] | None:
    """Return the in-toto statement inside a DSSE envelope, or None. Payload is base64 JSON."""
    try:
        env = json.loads(raw)
        payload = env.get("payload")
        if not payload:
            return env if env.get("predicateType") else None  # already-unwrapped statement
        return json.loads(base64.b64decode(payload))
    except (ValueError, TypeError):
        return None


def _attestor_key(type_uri: str) -> str:
    """Short attestor name from its type URI (…/attestations/<name>/vX or …/<name>/vX)."""
    if "/attestations/" in type_uri:
        return type_uri.split("/attestations/")[-1].split("/")[0]
    return type_uri.rstrip("/").rsplit("/", 2)[-2] if type_uri.count("/") >= 2 else type_uri


def _by_attestor(statement: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for a in statement.get("predicate", {}).get("attestations", []):
        t = a.get("type", "")
        out[_attestor_key(t)] = a.get("attestation", {}) or {}
    return out


def _material_sha(v: Any) -> str | None:
    if isinstance(v, dict):
        if isinstance(v.get("sha256"), str):
            return "sha256:" + v["sha256"]
        dig = v.get("digest")
        if isinstance(dig, dict) and isinstance(dig.get("sha256"), str):
            return "sha256:" + dig["sha256"]
    return None


def _folder_stasis(atts: dict[str, dict[str, Any]]) -> FolderStasis:
    material = atts.get("material", {}) or {}
    product = atts.get("product", {}) or {}
    before = {p: _material_sha(v) for p, v in material.items()}
    added: list[FileDigest] = []
    changed: list[FileDigest] = []
    for path, v in sorted(product.items()):
        sha = _material_sha(v)
        mime = v.get("mime_type") if isinstance(v, dict) else None
        fd = FileDigest(path=path, sha256=sha, mime_type=mime)
        if path not in before:
            added.append(fd)
        elif before[path] != sha:
            changed.append(fd)
    return FolderStasis(before_count=len(before), added=added, changed=changed)


def _repo(atts: dict[str, dict[str, Any]], py_pred: dict[str, Any] | None) -> RepoInfo:
    git = atts.get("git", {}) or {}
    commit = git.get("commithash") or git.get("commitDigest")
    status = git.get("status")
    dirty: bool | None
    if isinstance(status, (dict, list)):
        dirty = bool(status)
    else:
        dirty = None
    py_repo = (py_pred or {}).get("repo", {}) if py_pred else {}
    remotes = py_repo.get("remotes", {}) if isinstance(py_repo, dict) else {}
    matches: bool | None = None
    if commit and py_repo.get("commit"):
        matches = commit == py_repo["commit"]
    return RepoInfo(
        detected=bool(commit),
        commit=commit,
        branch=git.get("branch"),
        remotes=remotes or {},
        dirty=dirty if dirty is not None else py_repo.get("dirty"),
        commit_matches_python_env=matches,
    )


def _python_env(py_pred: dict[str, Any] | None, product: dict[str, Any],
                pylibs_path: Path | None) -> PythonEnv:
    if not py_pred:
        return PythonEnv(captured=False)
    py = py_pred.get("python", {})
    mods = py_pred.get("modules", [])
    fp = [PyModule(m["module"], m["path"], m.get("sha256"), "first_party", m.get("distribution"))
          for m in mods if m.get("category") == "first_party"]
    tp = [PyModule(m["module"], m["path"], m.get("sha256"), "third_party", m.get("distribution"))
          for m in mods if m.get("category") == "third_party"]
    stdlib = sum(1 for m in mods if m.get("category") == "stdlib")

    verified: bool | None = None
    recorded = product.get("amber-pylibs.json")
    if pylibs_path and pylibs_path.is_file() and isinstance(recorded, dict):
        want = (recorded.get("digest") or {}).get("sha256")
        if want:
            got = hashlib.sha256(pylibs_path.read_bytes()).hexdigest()
            verified = (got == want)
    return PythonEnv(
        captured=True,
        version=py.get("version"),
        implementation=py.get("implementation"),
        platform=py.get("platform"),
        distributions=py_pred.get("distributions", []),
        used_distributions=py_pred.get("used_distributions", []),
        first_party=fp,
        third_party=tp,
        stdlib_count=stdlib,
        digest_verified=verified,
    )


def _network(statement: dict[str, Any], atts: dict[str, dict[str, Any]]) -> NetworkTrace:
    nt = atts.get("network-trace")
    if isinstance(nt, dict):
        # Witness v0.12 shape: {"network_trace": {connections, summary:{total_connections,
        # unique_hosts, ...}, config:{proxy_port, ...}}}. Fall back to a flat shape defensively.
        trace = nt.get("network_trace") if isinstance(nt.get("network_trace"), dict) else nt
        summary = trace.get("summary") or {}
        conns = trace.get("connections") or trace.get("events") or []
        total = summary.get("total_connections")
        n = total if isinstance(total, int) else (len(conns) if isinstance(conns, list) else 0)
        hosts = summary.get("unique_hosts") or []
        detail = f"eBPF network-trace: {n} connection(s)"
        if hosts:
            detail += f", hosts={hosts}"
        return NetworkTrace(captured=True, clean=(n == 0), event_count=n, detail=detail)
    # No eBPF attestor: fall back to the shared command-run/runtime-trace network signal if present.
    try:
        from ..witness_attestation import _check_network_cleanliness  # reuse shared logic
        clean, detail = _check_network_cleanliness(statement)
        if clean is not None:
            return NetworkTrace(captured=True, clean=clean, detail=detail)
    except Exception:  # noqa: BLE001 -- shared helper unavailable; degrade gracefully
        pass
    return NetworkTrace(captured=False, clean=None, detail="no network-trace attestor in bundle")


def load(bundle_path: str | Path, pylibs_path: str | Path | None = None) -> CaptureRecord:
    """Parse a Witness capture bundle into a normalized ``CaptureRecord``.

    ``pylibs_path`` locates the python-env attestor JSON (default: ``amber-pylibs.json`` next to the
    bundle). Its digest is cross-checked against the product attestor when present.
    """
    bundle = Path(bundle_path)
    statement = _decode_dsse(bundle.read_bytes())
    if statement is None:
        raise ValueError(f"{bundle}: not a DSSE envelope / in-toto statement")
    ctype = statement.get("predicateType")
    if ctype not in _COLLECTION_TYPES:
        raise ValueError(f"{bundle}: unexpected predicateType {ctype!r} (not a Witness collection)")

    atts = _by_attestor(statement)
    env = atts.get("environment", {}) or {}
    variables = env.get("variables", {}) or {}

    pl = Path(pylibs_path) if pylibs_path else bundle.parent / "amber-pylibs.json"
    py_pred = None
    if pl.is_file():
        try:
            py_pred = json.loads(pl.read_text()).get("predicate")
        except (ValueError, OSError):
            py_pred = None

    cr = atts.get("command-run", {}) or {}
    return CaptureRecord(
        collection_type=ctype,
        attestor_types=sorted(atts.keys()),
        system=SystemInfo(
            os=env.get("os"), hostname=env.get("hostname"), username=env.get("username"),
            env_var_count=len(variables), env_vars=variables,
        ),
        repo=_repo(atts, py_pred),
        command=CommandRun(
            cmd=cr.get("cmd", []), exitcode=cr.get("exitcode"),
            stdout_excerpt=(cr.get("stdout") or "")[:200] or None,
        ),
        folder_stasis=_folder_stasis(atts),
        python_env=_python_env(py_pred, atts.get("product", {}) or {}, pl if pl.is_file() else None),
        network=_network(statement, atts),
        hardware=(py_pred or {}).get("hardware"),
        numerical=(py_pred or {}).get("numerical"),
        ebpf_file_access=(py_pred or {}).get("deep"),
    )


def render(rec: CaptureRecord) -> str:
    """Human-readable Amber capture report."""
    L: list[str] = []
    L.append("=" * 68)
    L.append("AMBER CAPTURE REPORT")
    L.append("=" * 68)
    L.append(f"collection      : {rec.collection_type}")
    L.append(f"attestors       : {', '.join(rec.attestor_types)}")

    s = rec.system
    L.append("")
    L.append(f"SYSTEM          : {s.os} host={s.hostname} user={s.username} "
             f"({s.env_var_count} env vars captured)")

    r = rec.repo
    match = {True: "matches python-env", False: "MISMATCH vs python-env", None: ""}[r.commit_matches_python_env]
    L.append(f"REPO            : commit={(r.commit or '-')[:12]} branch={r.branch} "
             f"dirty={r.dirty} {match}".rstrip())
    if r.remotes:
        L.append(f"  remotes       : {r.remotes}")

    c = rec.command
    L.append(f"COMMAND         : {' '.join(c.cmd)}  -> exit {c.exitcode}")

    fs = rec.folder_stasis
    L.append(f"FOLDER STASIS   : {fs.before_count} files before; "
             f"{len(fs.added)} created, {len(fs.changed)} changed")
    for fd in (fs.added + fs.changed)[:10]:
        L.append(f"  + {fd.path}  {(fd.sha256 or '')[:23]}  {fd.mime_type or ''}")

    pe = rec.python_env
    if pe.captured:
        ver = f"{pe.implementation} {pe.version}"
        vok = {True: " (digest verified)", False: " (DIGEST MISMATCH)", None: ""}[pe.digest_verified]
        L.append(f"PYTHON ENV      : {ver}{vok}")
        used = pe.used_distributions
        if used:
            names = ", ".join(f"{d.get('name')}=={d.get('version')}" for d in used[:12])
            L.append(f"  used deps      : {len(used)} exercised ({names}{'…' if len(used) > 12 else ''})")
        L.append(f"  distributions : {len(pe.distributions)} installed")
        L.append(f"  modules       : {len(pe.first_party)} first-party, "
                 f"{len(pe.third_party)} third-party, {pe.stdlib_count} stdlib")
        for m in pe.first_party[:8]:
            L.append(f"    [1st] {m.module}  {(m.sha256 or '')[:23]}")
        for m in pe.third_party[:8]:
            L.append(f"    [3rd] {m.module}  ({m.distribution or '?'})  {(m.sha256 or '')[:16]}")
    else:
        L.append("PYTHON ENV      : not captured (no amber-pylibs.json)")

    if rec.hardware or rec.numerical:
        hw = rec.hardware or {}
        num = rec.numerical or {}
        cpu = hw.get("cpu", {})
        gpu = hw.get("gpu") or []
        blas = (num.get("blas") or {}).get("name")
        L.append(f"HARDWARE        : {cpu.get('model', cpu.get('machine', '?'))} "
                 f"({cpu.get('count', '?')} cores, simd={','.join(cpu.get('simd', [])) or '-'}), "
                 f"{hw.get('memory_gb', '?')}GB"
                 + (f", GPU {gpu[0].get('name')} drv {gpu[0].get('driver')}" if gpu else ""))
        L.append(f"NUMERICAL       : blas={blas or '-'}, threads={num.get('thread_env') or '{}'}, "
                 f"PYTHONHASHSEED={num.get('pythonhashseed') or 'unset'}, tz={num.get('timezone')}")

    deep = rec.ebpf_file_access
    if deep:
        sos = deep.get("shared_objects", [])
        outside = [s for s in sos if not s.get("in_python_modules")]
        execs = deep.get("subprocess_execs", [])
        L.append(f"DEEP TRACE      : {len(sos)} native shared objects mapped "
                 f"({len(outside)} loaded outside the Python import system), {len(execs)} subprocess exec(s)")
        interesting = [s for s in outside if any(k in s["path"].lower()
                       for k in ("blas", "lapack", "cuda", "gomp", "gfortran", "stdc++", "mkl"))][:5]
        for s in interesting:
            L.append(f"    native: {s['path']}  {(s['sha256'] or '')[:16]}")

    n = rec.network
    clean = {True: "clean (no connections)", False: "connections recorded", None: "unknown"}[n.clean]
    L.append(f"NETWORK (eBPF)  : captured={n.captured} {clean} — {n.detail}")
    L.append("=" * 68)
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="amber-ingest",
                                description="Normalize a Witness capture bundle and print a report.")
    p.add_argument("bundle")
    p.add_argument("--pylibs", default=None, help="path to amber-pylibs.json (default: next to bundle)")
    p.add_argument("--json", action="store_true", help="emit the CaptureRecord as JSON instead")
    args = p.parse_args(argv)

    rec = load(args.bundle, args.pylibs)
    if args.json:
        import dataclasses
        print(json.dumps(dataclasses.asdict(rec), indent=2, default=str))
    else:
        print(render(rec))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
