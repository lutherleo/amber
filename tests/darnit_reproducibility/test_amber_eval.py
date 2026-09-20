"""Tests for the capture-completeness eval (``evaluation``), run against the committed fixtures."""
from __future__ import annotations

from pathlib import Path

from darnit_reproducibility import evaluation as ev

_ROOT = Path(__file__).resolve().parents[2]
_RESEARCH = _ROOT / "packages" / "darnit-reproducibility" / "examples" / "research"


def test_corpus_completeness_is_high() -> None:
    report = ev.evaluate_corpus(_RESEARCH)
    assert report.completeness_score >= 0.9
    assert report.verdict_accuracy == 1.0
    for c in report.completeness:
        assert not c.missing_deps, f"{c.example} missing {c.missing_deps}"
        assert c.native_libs_ok, f"{c.example}: no native libs captured"
        assert c.digest_verified and c.commit_bound and c.hardware_captured


def test_render_is_stringy() -> None:
    text = ev.render(ev.evaluate_corpus(_RESEARCH))
    assert "CAPTURE-COMPLETENESS EVAL" in text and "completeness score" in text


def test_completeness_flags_missing_dep() -> None:
    rec = ev._load_fixture(_RESEARCH, "lorenz")
    comp = ev.capture_completeness(rec, {"deps": {"numpy", "nonexistent-xyz"},
                                         "expect_native_libs": True})
    assert comp.deps_recall < 1.0
    assert "nonexistent-xyz" in comp.missing_deps
