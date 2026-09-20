"""Tests for the Go-module reproducibility checker (RE-01.04, repro_go_module_pinned)."""
from __future__ import annotations

from pathlib import Path

from darnit_reproducibility import handlers

from darnit.sieve.handler_registry import HandlerContext, HandlerResultStatus


def _run(tmp: Path):
    return handlers.repro_go_module_pinned_handler({}, HandlerContext(local_path=str(tmp)))


def test_pinned_go_module_passes(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.26.0\n")
    (tmp_path / "go.sum").write_text("example.com/dep v1.0.0 h1:abc=\n")
    res = _run(tmp_path)
    assert res.status == HandlerResultStatus.PASS
    assert res.evidence["go_version"] == "1.26.0"
    assert res.evidence["go_sum_present"] is True


def test_toolchain_and_trimpath_credited(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module m\n\ngo 1.26.0\n\ntoolchain go1.26.1\n")
    (tmp_path / "go.sum").write_text("m/dep v1 h1:x=\n")
    (tmp_path / ".goreleaser.yml").write_text("builds:\n  - flags:\n      - -trimpath\n")
    res = _run(tmp_path)
    assert res.status == HandlerResultStatus.PASS
    assert res.evidence["toolchain"] == "go1.26.1"
    assert "-trimpath" in res.evidence["reproducible_flags"]
    assert "-trimpath" in res.message


def test_go_mod_without_go_sum_fails(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module m\n\ngo 1.26.0\n")
    res = _run(tmp_path)
    assert res.status == HandlerResultStatus.FAIL
    assert "go.sum" in res.message


def test_vendored_without_go_sum_passes(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module m\n\ngo 1.26.0\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "modules.txt").write_text("# example.com/dep v1.0.0\n")
    res = _run(tmp_path)
    assert res.status == HandlerResultStatus.PASS
    assert res.evidence["vendored"] is True


def test_go_mod_without_go_directive_is_inconclusive(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module m\n")  # no `go <version>` line
    (tmp_path / "go.sum").write_text("m/dep v1 h1:x=\n")
    res = _run(tmp_path)
    assert res.status == HandlerResultStatus.INCONCLUSIVE
    assert "not pinned" in res.message


def test_no_go_mod_is_inconclusive(tmp_path: Path) -> None:
    res = _run(tmp_path)
    assert res.status == HandlerResultStatus.INCONCLUSIVE
    assert "not a Go module" in res.message
