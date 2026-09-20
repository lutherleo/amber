"""Token-free tests for the introspective Python attestor (``capture.pyprobe``)."""
from __future__ import annotations

from pathlib import Path

import pytest
from darnit_reproducibility.capture import pyprobe


def test_classify_first_party(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    mod = repo / "pkg" / "mine.py"
    mod.write_text("x = 1")
    cat = pyprobe._classify(mod, "pkg.mine", repo, pyprobe._stdlib_dirs())
    assert cat == "first_party"


def test_classify_third_party_site_packages(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    sp = tmp_path / "venv" / "lib" / "site-packages" / "numpy" / "__init__.py"
    sp.parent.mkdir(parents=True)
    sp.write_text("")
    assert pyprobe._classify(sp, "numpy", repo, pyprobe._stdlib_dirs()) == "third_party"


def test_classify_stdlib_by_name(tmp_path: Path) -> None:
    # a name in the interpreter's stdlib set classifies as stdlib even from an odd path
    some = tmp_path / "json" / "__init__.py"
    some.parent.mkdir(parents=True)
    some.write_text("")
    assert pyprobe._classify(some, "json", None, pyprobe._stdlib_dirs()) == "stdlib"


def test_main_script_from_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    script = tmp_path / "exp.py"
    script.write_text("print('hi')")
    monkeypatch.setattr(pyprobe.sys, "argv", [str(script)])
    assert pyprobe._main_script() == script


def test_main_script_none_for_dash_c(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pyprobe.sys, "argv", ["-c"])
    assert pyprobe._main_script() is None


def test_shim_self_exclusion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text("")
    monkeypatch.setenv("AMBER_SHIM_DIR", str(shim))
    # a fake module whose file is inside the shim dir must not appear
    import types
    fake = types.ModuleType("sitecustomize")
    fake.__file__ = str(shim / "sitecustomize.py")
    monkeypatch.setitem(pyprobe.sys.modules, "sitecustomize", fake)
    mods = pyprobe._loaded_modules(tmp_path, {})
    assert not any(m["module"] == "sitecustomize" for m in mods)


def test_dist_for_path_attributes_by_site_packages_dir() -> None:
    # a C-extension submodule that packages_distributions misses is attributed by its top dir
    p = Path("/x/lib/python3.12/site-packages/scipy/sparse/_csparsetools.cpython-312.so")
    assert pyprobe._dist_for_path(p, {"scipy": "scipy"}) == "scipy"
    assert pyprobe._dist_for_path(Path("/x/site-packages/numpy/core/x.py"), {"numpy": "numpy"}) == "numpy"
    assert pyprobe._dist_for_path(Path("/x/not-here/foo.py"), {"scipy": "scipy"}) is None


def test_collect_shape(tmp_path: Path) -> None:
    pred = pyprobe.collect(tmp_path)
    for key in ("python", "repo", "distributions", "used_distributions", "modules", "summary"):
        assert key in pred
    for key in ("first_party", "third_party", "stdlib", "modules_loaded", "distributions_used"):
        assert key in pred["summary"]
    assert pred["python"]["implementation"]  # e.g. CPython
    # used distributions are a subset of installed
    installed = {d["name"] for d in pred["distributions"]}
    assert all(d["name"] in installed for d in pred["used_distributions"])


def test_collect_hardware_numerical(tmp_path: Path) -> None:
    pred = pyprobe.collect(tmp_path)
    assert "hardware" in pred and "numerical" in pred
    assert "cpu" in pred["hardware"] and "gpu" in pred["hardware"]
    num = pred["numerical"]
    for key in ("thread_env", "pythonhashseed", "locale", "timezone", "blas"):
        assert key in num


def test_deep_trace_shape(tmp_path: Path) -> None:
    pred = pyprobe.collect(tmp_path)
    assert "deep" in pred
    deep = pred["deep"]
    assert isinstance(deep["shared_objects"], list)
    # the interpreter always maps some shared object (libc / libpython)
    assert any(".so" in s["path"] for s in deep["shared_objects"])
    assert "subprocess_execs" in deep and "dlopen" in deep


def test_audit_hook_records_subprocess() -> None:
    import subprocess

    pyprobe._AUDIT["subprocess_execs"].clear()
    pyprobe.install_audit_hook()
    subprocess.run(["true"], check=False)
    assert any("true" in e for e in pyprobe._AUDIT["subprocess_execs"])


def test_statement_predicate_type(tmp_path: Path) -> None:
    st = pyprobe.statement(tmp_path)
    assert st["predicateType"] == pyprobe.PREDICATE_TYPE
    assert st["_type"] == pyprobe.STATEMENT_TYPE


def test_write_roundtrip(tmp_path: Path) -> None:
    out = tmp_path / "pylibs.json"
    pyprobe.write(out, tmp_path)
    import json
    data = json.loads(out.read_text())
    assert data["predicateType"] == pyprobe.PREDICATE_TYPE
    assert "modules" in data["predicate"]
