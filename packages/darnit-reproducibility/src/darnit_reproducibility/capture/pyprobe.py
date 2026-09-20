"""Introspective Python-environment attestor for Amber capture.

Records the Python "library objects" a run actually used and links them back to the source repo,
producing a self-describing predicate (``https://darnit.dev/attestations/python-env/v0``). The
Witness ``product`` attestor then hashes the emitted JSON into the signed bundle, so this evidence
is covered by the same signature as the rest of the capture.

Two things Witness's own attestors do not give us:

1. **Which library objects were loaded** (not just what is installed): every ``sys.modules`` entry
   with a real file, hashed. This is the Amber goal of "secure hashes of all used libraries".
2. **First-party vs third-party, bound to the repo**: each loaded module is classified as
   first-party (the researcher's own code, under the git worktree), third-party (site-packages),
   or stdlib, and the git commit is recorded so first-party objects are commit-bound. This is the
   "check connection with repo" link.

Stdlib only, so it can run inside any traced interpreter without adding dependencies. Every entry
point is defensive: an attestor must never crash the program it observes (see ``_sitecustomize``).
"""
from __future__ import annotations

import hashlib
import importlib.metadata as im
import json
import os
import platform
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

PREDICATE_TYPE = "https://darnit.dev/attestations/python-env/v0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Files larger than this are recorded without a digest (a giant data file loaded as a "module" is
# not the point, and hashing it would dominate exit time). Real code (.py/.so/.pyd) is far smaller.
_MAX_HASH_BYTES = 64 * 1024 * 1024


def _sha256(path: Path) -> str | None:
    """sha256 of a file, or None if it is unreadable / oversized. Never raises."""
    try:
        if path.stat().st_size > _MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return "sha256:" + h.hexdigest()
    except OSError:
        return None


def _git(repo_root: Path, *args: str) -> str | None:
    """Run a git command in ``repo_root``; return trimmed stdout or None. Never raises."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _discover_repo_root(start: Path) -> Path | None:
    """The git worktree root at/above ``start`` (``git rev-parse --show-toplevel``), else the
    nearest ancestor containing a ``.git``. None when neither is found."""
    top = _git(start, "rev-parse", "--show-toplevel")
    if top:
        return Path(top)
    cur = start.resolve()
    for parent in (cur, *cur.parents):
        if (parent / ".git").exists():
            return parent
    return None


def _repo_info(repo_root: Path | None) -> dict[str, Any]:
    """Git identity for the run: commit, remotes, branch, dirtiness. Best-effort."""
    if repo_root is None:
        return {"detected": False}
    remotes_raw = _git(repo_root, "remote", "-v") or ""
    remotes: dict[str, str] = {}
    for line in remotes_raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] not in remotes:
            remotes[parts[0]] = parts[1]
    status = _git(repo_root, "status", "--porcelain")
    return {
        "detected": True,
        "root": str(repo_root),
        "commit": _git(repo_root, "rev-parse", "HEAD"),
        "branch": _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD"),
        "remotes": remotes,
        "dirty": bool(status) if status is not None else None,
    }


def _stdlib_dirs() -> tuple[str, ...]:
    """Resolved stdlib / platstdlib directories, used to classify a module path as stdlib."""
    dirs: list[str] = []
    for key in ("stdlib", "platstdlib"):
        try:
            p = sysconfig.get_paths().get(key)
            if p:
                dirs.append(str(Path(p).resolve()))
        except (KeyError, OSError):
            continue
    return tuple(dirs)


def _classify(path: Path, name: str, repo_root: Path | None,
              stdlib_dirs: tuple[str, ...]) -> str:
    """One of 'first_party' | 'third_party' | 'stdlib'.

    first_party  = under the git worktree AND not inside a vendored site-packages/venv there.
    stdlib       = ships with the interpreter (name in stdlib set, or under a stdlib dir but not
                   site-packages).
    third_party  = everything else (site-packages, other installed locations).
    """
    try:
        rp = str(path.resolve())
    except OSError:
        rp = str(path)
    in_site = "site-packages" in rp or "dist-packages" in rp

    if repo_root is not None and not in_site:
        try:
            path.resolve().relative_to(repo_root.resolve())
            if not any(seg in rp for seg in (os.sep + "site-packages", os.sep + ".venv", os.sep + "venv")):
                return "first_party"
        except ValueError:
            pass

    top = name.split(".", 1)[0]
    if top in getattr(sys, "stdlib_module_names", frozenset()):
        return "stdlib"
    if not in_site and any(rp.startswith(d) for d in stdlib_dirs):
        return "stdlib"
    return "third_party"


def _installed_distributions() -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    """Returns (installed dists [{name,version}], import-name->dist map, top-level-dir->dist map).

    The dir map lets us attribute a module by the site-packages directory its file lives in — this
    catches C-extension submodules (e.g. ``_csparsetools`` under ``scipy/``) that
    ``packages_distributions`` misses because they never appear as a top-level import name."""
    dists: list[dict[str, Any]] = []
    seen: set[str] = set()
    dir_to_dist: dict[str, str] = {}
    for dist in im.distributions():
        try:
            name = dist.metadata["Name"]
        except (KeyError, TypeError):
            name = None
        if not name:
            continue
        # top-level directory names owned by this distribution (top_level.txt, else file roots)
        tops: set[str] = set()
        try:
            tl = dist.read_text("top_level.txt")
            if tl:
                tops.update(t.strip() for t in tl.splitlines() if t.strip())
        except Exception:  # noqa: BLE001
            pass
        try:
            for f in dist.files or []:
                parts = f.parts
                if parts and not parts[0].endswith((".dist-info", ".egg-info")):
                    tops.add(parts[0].removesuffix(".py"))
        except Exception:  # noqa: BLE001
            pass
        for t in tops:
            dir_to_dist.setdefault(t, name)
        if name.lower() not in seen:
            seen.add(name.lower())
            dists.append({"name": name, "version": dist.version})
    dists.sort(key=lambda d: d["name"].lower())

    import_to_dist: dict[str, str] = {}
    try:
        for import_name, dist_names in im.packages_distributions().items():
            if dist_names:
                import_to_dist[import_name] = dist_names[0]
    except Exception:  # noqa: BLE001 -- packages_distributions is best-effort
        pass
    return dists, import_to_dist, dir_to_dist


def _dist_for_path(path: Path, dir_to_dist: dict[str, str]) -> str | None:
    """Attribute a file to a distribution by the site-packages directory it lives under."""
    parts = path.parts
    for i, seg in enumerate(parts):
        if seg in ("site-packages", "dist-packages") and i + 1 < len(parts):
            return dir_to_dist.get(parts[i + 1].removesuffix(".py"))
    return None


def _main_script() -> Path | None:
    """Path of the invoked main script from ``sys.argv[0]``.

    At interpreter shutdown CPython clears the ``__main__`` module's globals, so ``__main__.__file__``
    reads ``None`` inside an ``atexit`` handler (where this attestor runs) — the experiment's own file
    would otherwise be lost. ``sys.argv[0]`` survives shutdown, so we recover it from there. Returns
    None for ``-c``/REPL/``-`` invocations that have no script file."""
    argv0 = sys.argv[0] if sys.argv else ""
    if not argv0 or argv0 in ("-c", "-"):
        return None
    p = Path(argv0)
    return p if p.exists() else None


def _loaded_modules(repo_root: Path | None, import_to_dist: dict[str, str],
                    dir_to_dist: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Every sys.modules entry backed by a real file: path, digest, category, owning distribution.

    Two adjustments: the ``__main__`` script is recovered from ``sys.argv[0]`` (see ``_main_script``),
    and the attestor's own injected shim files (under ``$AMBER_SHIM_DIR``) are excluded so the observer
    does not report itself into the attestation."""
    stdlib_dirs = _stdlib_dirs()
    shim_dir = os.environ.get("AMBER_SHIM_DIR")
    shim_resolved = str(Path(shim_dir).resolve()) if shim_dir else None
    modules: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    def _add(name: str, path: Path) -> None:
        try:
            rp = str(path)
            if rp in seen_paths or not path.exists():
                return
            if shim_resolved and str(path.resolve()).startswith(shim_resolved):
                return  # self-exclusion: don't attest the shim we injected
        except OSError:
            return
        seen_paths.add(rp)
        category = _classify(path, name, repo_root, stdlib_dirs)
        entry: dict[str, Any] = {"module": name, "path": rp,
                                 "sha256": _sha256(path), "category": category}
        if category == "third_party":
            dist = import_to_dist.get(name.split(".", 1)[0]) or _dist_for_path(path, dir_to_dist or {})
            if dist:
                entry["distribution"] = dist
        modules.append(entry)

    main = _main_script()
    if main is not None:
        _add("__main__", main)
    for name, mod in list(sys.modules.items()):
        if name == "__main__":
            continue  # handled above from sys.argv[0] (its __file__ is cleared at shutdown)
        f = getattr(mod, "__file__", None)
        if f:
            _add(name, Path(f))
    modules.sort(key=lambda m: m["module"])
    return modules


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def _cpu_info() -> dict[str, Any]:
    """CPU model, core count, and the SIMD flags that drive numerical (BLAS) reproducibility."""
    info: dict[str, Any] = {"machine": platform.machine(), "count": os.cpu_count()}
    cpuinfo = _read_text("/proc/cpuinfo")
    for line in cpuinfo.splitlines():
        if line.startswith("model name"):
            info["model"] = line.split(":", 1)[1].strip()
            break
    for line in cpuinfo.splitlines():
        if line.startswith("flags") or line.startswith("Features"):
            flags = set(line.split(":", 1)[1].split())
            info["simd"] = sorted(f for f in ("sse4_2", "avx", "avx2", "avx512f", "fma") if f in flags)
            break
    return info


def _memory_gb() -> float | None:
    for line in _read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal"):
            return round(int(line.split()[1]) / 1024 / 1024, 1)
    try:
        return round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9, 1)
    except (ValueError, OSError, AttributeError):
        return None


def _gpu() -> list[dict[str, str]]:
    """NVIDIA GPU + driver via nvidia-smi (best-effort; empty when absent)."""
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0 or not out.stdout.strip():
        return []
    gpus = []
    for line in out.stdout.strip().splitlines():
        cols = [c.strip() for c in line.split(",")]
        gpus.append(dict(zip(("name", "driver", "memory"), cols, strict=False)))
    return gpus


def _blas() -> dict[str, Any] | None:
    """BLAS backend numpy is linked against — only if numpy is already loaded (no hard dependency)."""
    np = sys.modules.get("numpy")
    if np is None:
        return None
    try:
        cfg = np.show_config(mode="dicts")  # numpy >= 1.25
        blas = cfg.get("Build Dependencies", {}).get("blas", {})
        return {"name": blas.get("name"), "version": blas.get("version")}
    except Exception:  # noqa: BLE001 -- show_config shape varies; best-effort
        return None


_THREAD_ENV_KEYS = ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                    "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS")


def _numerical() -> dict[str, Any]:
    """Settings that change numerical output: thread caps, hash seed, locale, timezone, BLAS."""
    import locale as _locale
    import time as _time
    try:
        loc = _locale.setlocale(_locale.LC_ALL)
    except Exception:  # noqa: BLE001
        loc = None
    return {
        "thread_env": {k: os.environ[k] for k in _THREAD_ENV_KEYS if k in os.environ},
        "pythonhashseed": os.environ.get("PYTHONHASHSEED"),
        "locale": loc or os.environ.get("LC_ALL") or os.environ.get("LANG"),
        "timezone": os.environ.get("TZ") or "/".join(_time.tzname),
        "blas": _blas(),
    }


def _hardware() -> dict[str, Any]:
    return {"cpu": _cpu_info(), "memory_gb": _memory_gb(), "gpu": _gpu()}


# ── Deep trace (portable, no root/eBPF): native shared objects + subprocess/dlopen audit ─────────
# The introspective attestor sees only Python-imported modules. This captures native libraries the
# process actually mapped (BLAS/CUDA/libstdc++ — loaded by the dynamic linker, invisible to `import`)
# via /proc/self/maps, plus subprocess execs and ctypes.dlopen via an audit hook. eBPF (Witness
# --trace, on CI) additionally sees *child* processes' file access; this covers this process portably.
_AUDIT: dict[str, list[str]] = {"subprocess_execs": [], "dlopen": []}


def _audit_hook(event: str, args: tuple) -> None:  # pragma: no cover -- exercised via real runs
    try:
        if event == "subprocess.Popen" and args:
            # event args are (executable, args, cwd, env); the argv is the informative part
            cmd = args[1] if len(args) > 1 and args[1] else args[0]
            _AUDIT["subprocess_execs"].append(str(cmd))
        elif event in ("os.exec", "os.posix_spawn") and args:
            _AUDIT["subprocess_execs"].append(str(args[0]))
        elif event == "ctypes.dlopen" and args:
            _AUDIT["dlopen"].append(str(args[0]))
    except Exception:  # noqa: BLE001 -- an audit hook must never raise
        pass


def install_audit_hook() -> None:
    """Install the subprocess/dlopen audit hook (called once at interpreter startup by the shim)."""
    try:
        sys.addaudithook(_audit_hook)
    except Exception:  # noqa: BLE001
        pass


def _shared_objects() -> list[dict[str, Any]]:
    """Native shared objects mapped into the process (from /proc/self/maps), hashed and classified.

    ``in_python_modules`` marks a .so that is a known Python extension file; the rest were loaded by
    the dynamic linker outside the import system (the M4 blind spot for baseline capture)."""
    maps = _read_text("/proc/self/maps")
    if not maps:
        return []
    module_files = {getattr(m, "__file__", None) for m in sys.modules.values()}
    module_files.discard(None)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for line in maps.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        path = parts[5]
        if ".so" not in path or path in seen:
            continue
        p = Path(path)
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        seen.add(path)
        cat = ("site-packages" if ("site-packages" in path or "dist-packages" in path)
               else "system" if path.startswith(("/usr", "/lib")) else "other")
        out.append({"path": path, "sha256": _sha256(p), "category": cat,
                    "in_python_modules": path in module_files})
        if len(out) >= 400:
            break
    return out


def _deep_trace() -> dict[str, Any]:
    return {
        "shared_objects": _shared_objects(),
        "subprocess_execs": sorted(set(_AUDIT["subprocess_execs"]))[:200],
        "dlopen": sorted(set(_AUDIT["dlopen"]))[:200],
    }


def collect(repo_root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Build the python-env predicate for the current interpreter state.

    ``repo_root`` pins the first-party boundary; when omitted it is taken from ``AMBER_REPO_ROOT``
    or discovered from the current working directory's git worktree.
    """
    root: Path | None
    if repo_root is not None:
        root = Path(repo_root)
    elif os.environ.get("AMBER_REPO_ROOT"):
        root = Path(os.environ["AMBER_REPO_ROOT"])
    else:
        root = _discover_repo_root(Path.cwd())

    distributions, import_to_dist, dir_to_dist = _installed_distributions()
    modules = _loaded_modules(root, import_to_dist, dir_to_dist)
    counts = {"first_party": 0, "third_party": 0, "stdlib": 0}
    for m in modules:
        counts[m["category"]] = counts.get(m["category"], 0) + 1

    # Distributions actually EXERCISED by the run (attributed from loaded third-party modules) — the
    # provenance-relevant subset, distinct from everything merely installed in the environment.
    used = sorted({m["distribution"] for m in modules if m.get("distribution")})
    ver_by_name = {d["name"]: d["version"] for d in distributions}
    used_distributions = [{"name": n, "version": ver_by_name.get(n)} for n in used]

    return {
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "platform": platform.platform(),
        },
        "repo": _repo_info(root),
        "hardware": _hardware(),
        "numerical": _numerical(),
        "deep": _deep_trace(),
        "distributions": distributions,
        "used_distributions": used_distributions,
        "modules": modules,
        "summary": {
            "distributions": len(distributions),
            "distributions_used": len(used_distributions),
            "modules_loaded": len(modules),
            **counts,
        },
    }


def statement(repo_root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """An in-toto Statement wrapping the predicate. The subject is the first-party repo commit
    (when known) so the attestation is anchored to the researcher's code, not an anonymous blob."""
    predicate = collect(repo_root)
    repo = predicate["repo"]
    subject: list[dict[str, Any]] = []
    if repo.get("detected") and repo.get("commit"):
        subject = [{"name": repo.get("root", "repo"), "digest": {"gitCommit": repo["commit"]}}]
    return {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def write(out_path: str | os.PathLike[str], repo_root: str | os.PathLike[str] | None = None) -> str:
    """Write the python-env statement JSON to ``out_path``; return the path written. Never raises
    out of an attestor context — the caller (``_sitecustomize``) still guards it."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(statement(repo_root), indent=2, sort_keys=False))
    return str(out)


if __name__ == "__main__":
    # `python -m darnit_reproducibility.capture.pyprobe [out.json]` — capture THIS interpreter.
    target = sys.argv[1] if len(sys.argv) > 1 else "amber-pylibs.json"
    print("wrote", write(target))
