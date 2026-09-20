"""TEMPLATE: injected as ``sitecustomize.py`` to auto-run the python-env attestor at exit.

This file is NOT imported under its own name. The capture harness (``capture/run.py``) copies it to
``<shim-dir>/sitecustomize.py`` and prepends ``<shim-dir>`` to ``PYTHONPATH`` before launching the
traced command. Python then imports ``sitecustomize`` automatically at interpreter startup, with no
edit to the experiment — Amber's transparency requirement.

At exit it writes the python-env predicate (see ``pyprobe``) to ``$AMBER_PYLIBS_OUT``. Every step is
guarded: an observability shim must never change the outcome or the exit status of the program it
observes.
"""
import atexit
import os
import sys


def _amber_dump() -> None:
    try:
        out = os.environ.get("AMBER_PYLIBS_OUT", "amber-pylibs.json")
        repo_root = os.environ.get("AMBER_REPO_ROOT") or None
        # ``pyprobe.py`` is copied into this same shim dir by the harness, so a bare import works
        # with zero package/deps in the traced interpreter (Amber transparency). Fall back to the
        # installed package if that layout ever changes.
        try:
            import pyprobe  # type: ignore[import-not-found]
        except ImportError:
            from darnit_reproducibility.capture import pyprobe  # type: ignore[no-redef]

        pyprobe.write(out, repo_root)
    except Exception:  # noqa: BLE001 -- never let the attestor break the traced program
        pass


def _chain_downstream_sitecustomize() -> None:
    """Best-effort: run any OTHER ``sitecustomize.py`` this shim shadowed on ``sys.path`` so we do
    not silently disable a real one the environment relies on. Fully guarded."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        for entry in sys.path:
            try:
                cand = os.path.join(entry or ".", "sitecustomize.py")
                if os.path.abspath(cand) == os.path.abspath(__file__):
                    continue
                if os.path.dirname(os.path.abspath(cand)) == here:
                    continue
                if os.path.isfile(cand):
                    with open(cand, "rb") as fh:
                        code = compile(fh.read(), cand, "exec")
                    exec(code, {"__file__": cand, "__name__": "sitecustomize"})
                    break
            except Exception:  # noqa: BLE001 -- one bad path must not abort the chain
                continue
    except Exception:  # noqa: BLE001
        pass


def _amber_install_audit_hook() -> None:
    """Install pyprobe's subprocess/dlopen audit hook at startup (before the experiment runs)."""
    try:
        try:
            import pyprobe  # type: ignore[import-not-found]
        except ImportError:
            from darnit_reproducibility.capture import pyprobe  # type: ignore[no-redef]
        pyprobe.install_audit_hook()
    except Exception:  # noqa: BLE001 -- never let the shim break the traced program
        pass


atexit.register(_amber_dump)
_amber_install_audit_hook()
_chain_downstream_sitecustomize()
