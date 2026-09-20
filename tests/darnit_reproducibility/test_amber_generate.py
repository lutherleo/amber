"""Token-free tests for the environment generator (``generate.environment``)."""
from __future__ import annotations

from darnit_reproducibility.generate import environment as gen
from darnit_reproducibility.models import CaptureRecord, CommandRun, PythonEnv, RepoInfo


def _rec() -> CaptureRecord:
    return CaptureRecord(
        python_env=PythonEnv(
            captured=True, version="3.12.3",
            used_distributions=[{"name": "scipy", "version": "1.13.1"},
                                {"name": "numpy", "version": "1.26.4"}],
        ),
        repo=RepoInfo(detected=True, commit="deadbeef"),
        command=CommandRun(cmd=["/home/x/.venv/bin/python", "experiment.py"], exitcode=0),
    )


def test_requirements_lock_pins_used_deps() -> None:
    env = gen.generate(_rec(), target="requirements")
    lock = env.files["requirements.lock"]
    assert "numpy==1.26.4" in lock and "scipy==1.13.1" in lock
    # sorted, case-insensitive: numpy before scipy
    assert lock.index("numpy==") < lock.index("scipy==")


def test_dockerfile_uses_captured_python_and_normalizes_interpreter() -> None:
    env = gen.generate(_rec(), target="docker")
    df = env.files["Dockerfile"]
    assert "FROM python:3.12-slim" in df
    assert "pip install --no-cache-dir -r /tmp/requirements.lock" in df
    assert 'CMD ["python", "experiment.py"]' in df  # interpreter path normalized to `python`
    assert "deadbeef" in df  # records the source commit
    assert "requirements.lock" in env.files


def test_python_tag_fallback() -> None:
    assert gen._python_tag("3.11.9") == "3.11"
    assert gen._python_tag(None) == "3.12"
    assert gen._python_tag("weird") == "3.12"


def test_notes_warn_about_native_libs() -> None:
    env = gen.generate(_rec())
    assert any("native" in n.lower() for n in env.notes)


def test_dockerfile_pins_threads_and_hashseed() -> None:
    rec = _rec()
    rec.numerical = {"thread_env": {"OMP_NUM_THREADS": "4"}, "pythonhashseed": "7", "timezone": "UTC"}
    df = gen.generate(rec, target="docker").files["Dockerfile"]
    assert "ENV OMP_NUM_THREADS=4" in df
    assert "PYTHONHASHSEED=7" in df
    assert "ENV MKL_NUM_THREADS=1" in df  # defaulted for determinism


def test_native_apt_hints_in_dockerfile() -> None:
    rec = _rec()
    rec.ebpf_file_access = {"shared_objects": [
        {"path": "/usr/lib/libopenblas.so.0", "in_python_modules": False},
        {"path": "/usr/lib/libgomp.so.1", "in_python_modules": False},
        {"path": "/site/numpy/_x.cpython.so", "in_python_modules": True},  # ignored (a py ext)
    ]}
    df = gen.generate(rec, target="docker").files["Dockerfile"]
    assert "libopenblas0" in df and "libgomp1" in df
    assert "apt-get install" in df


def test_conda_env_target() -> None:
    env = gen.generate(_rec(), target="conda")
    y = env.files["environment.yml"]
    assert "name: reproduced" in y
    assert "python=3.12.3" in y
    assert "- numpy==1.26.4" in y and "- scipy==1.13.1" in y
