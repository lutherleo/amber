"""Token-free tests for the reproducibility verdict (``analysis.compare``)."""
from __future__ import annotations

import json
from pathlib import Path

from darnit_reproducibility.analysis import compare as cmp
from darnit_reproducibility.models import (
    CaptureRecord,
    CommandRun,
    FileDigest,
    FolderStasis,
    PythonEnv,
    RepoInfo,
)


def _rec(outputs: dict[str, str], deps: list[tuple[str, str]], py: str = "3.12.3",
         commit: str = "abc") -> CaptureRecord:
    added = [FileDigest(path=n, sha256=s) for n, s in outputs.items()]
    used = [{"name": n, "version": v} for n, v in deps]
    return CaptureRecord(
        folder_stasis=FolderStasis(added=added),
        python_env=PythonEnv(captured=True, version=py, used_distributions=used),
        repo=RepoInfo(detected=True, commit=commit),
        command=CommandRun(cmd=["/venv/bin/python", "experiment.py"], exitcode=0),
    )


def test_bit_for_bit_identical() -> None:
    a = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    b = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    v = cmp.compare(a, b)
    assert v.level == "BIT_FOR_BIT"
    assert v.bit_for_bit is True and v.reproduction_rate == 1.0
    assert v.env.identical is True


def test_reproduced_with_drift() -> None:
    a = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    b = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.3")])  # same output, dep drifted
    v = cmp.compare(a, b)
    assert v.level == "REPRODUCED_WITH_DRIFT"
    assert v.bit_for_bit is True
    assert v.env.version_drift[0].name == "numpy"


def test_not_reproduced_blames_dependency_drift() -> None:
    a = _rec({"result.json": "sha256:AAA"}, [("scipy", "1.13.1")])
    b = _rec({"result.json": "sha256:BBB"}, [("scipy", "1.13.0")])  # different output + dep drift
    v = cmp.compare(a, b)
    assert v.level == "NOT_REPRODUCED"
    assert v.bit_for_bit is False
    assert any("scipy 1.13.1 -> 1.13.0" in d for d in v.discrepancies)


def test_not_reproduced_flags_nondeterminism_when_env_identical() -> None:
    a = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    b = _rec({"result.json": "sha256:ZZZ"}, [("numpy", "1.26.4")])  # differs, identical env
    v = cmp.compare(a, b)
    assert v.level == "NOT_REPRODUCED"
    assert any("nondeterminism" in d for d in v.discrepancies)


def test_inconclusive_without_shared_outputs() -> None:
    a = _rec({"result.json": "sha256:AAA"}, [])
    b = _rec({}, [])  # no outputs on the reproduction side
    v = cmp.compare(a, b)
    assert v.level == "INCONCLUSIVE"


def test_tooling_files_are_excluded() -> None:
    a = _rec({"result.json": "sha256:AAA", "amber-pylibs.json": "sha256:P1"}, [("numpy", "1.26.4")])
    b = _rec({"result.json": "sha256:AAA", "amber-pylibs.json": "sha256:P2"}, [("numpy", "1.26.4")])
    v = cmp.compare(a, b)
    # amber-pylibs.json must not count against the verdict
    assert [art.name for art in v.artifacts] == ["result.json"]
    assert v.level == "BIT_FOR_BIT"


def test_render_is_stringy() -> None:
    a = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    v = cmp.compare(a, a)
    text = cmp.render(v)
    assert "REPRODUCIBILITY VERDICT" in text and "BIT_FOR_BIT" in text


def test_semantically_reproduced_within_tolerance(tmp_path: Path) -> None:
    od, rd = tmp_path / "o", tmp_path / "r"
    od.mkdir()
    rd.mkdir()
    (od / "result.json").write_text(json.dumps({"x": 1.0000000001, "y": [1, 2, 3]}))
    (rd / "result.json").write_text(json.dumps({"x": 1.0000000002, "y": [1, 2, 3]}))
    a = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    b = _rec({"result.json": "sha256:BBB"}, [("numpy", "1.26.4")])  # different digest
    v = cmp.compare(a, b, original_dir=str(od), reproduction_dir=str(rd), rel_tol=1e-6)
    assert v.level == "SEMANTICALLY_REPRODUCED"
    assert v.artifacts[0].semantic_match is True


def test_semantic_mismatch_is_not_reproduced(tmp_path: Path) -> None:
    od, rd = tmp_path / "o", tmp_path / "r"
    od.mkdir()
    rd.mkdir()
    (od / "result.json").write_text(json.dumps({"x": 1.0}))
    (rd / "result.json").write_text(json.dumps({"x": 2.0}))  # far apart
    a = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    b = _rec({"result.json": "sha256:BBB"}, [("numpy", "1.26.4")])
    v = cmp.compare(a, b, original_dir=str(od), reproduction_dir=str(rd), rel_tol=1e-9)
    assert v.level == "NOT_REPRODUCED"
    assert v.artifacts[0].semantic_match is False


def test_bundle_is_signed(tmp_path: Path) -> None:
    signed = tmp_path / "s.json"
    signed.write_text(json.dumps({"signatures": [{"certificate": "CERTDATA"}]}))
    unsigned = tmp_path / "u.json"
    unsigned.write_text(json.dumps({"signatures": []}))
    assert cmp.bundle_is_signed(signed) is True
    assert cmp.bundle_is_signed(unsigned) is False
    assert cmp.bundle_is_signed(tmp_path / "missing.json") is False


def test_numerical_drift_in_discrepancies() -> None:
    a = _rec({"result.json": "sha256:AAA"}, [("numpy", "1.26.4")])
    b = _rec({"result.json": "sha256:BBB"}, [("numpy", "1.26.4")])
    a.numerical = {"blas": {"name": "openblas"}, "thread_env": {"OMP_NUM_THREADS": "1"},
                   "pythonhashseed": "0"}
    b.numerical = {"blas": {"name": "mkl"}, "thread_env": {"OMP_NUM_THREADS": "8"},
                   "pythonhashseed": "0"}
    v = cmp.compare(a, b)  # no dirs -> byte-differ -> NOT_REPRODUCED
    assert v.level == "NOT_REPRODUCED"
    assert any("BLAS backend: openblas -> mkl" in d for d in v.discrepancies)
    assert any("OMP_NUM_THREADS: 1 -> 8" in d for d in v.discrepancies)


def test_values_close() -> None:
    assert cmp._values_close({"a": 1.0}, {"a": 1.0 + 1e-12}, 1e-9) is True
    assert cmp._values_close([1, 2], [1, 3], 1e-9) is False
    # the bool guard blocks tolerance-based matching (True is not "close to" 1.0000001)
    assert cmp._values_close(True, 1.0000001, 1e-3) is False
