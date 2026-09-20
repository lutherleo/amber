"""Tests for the `amber` CLI and the two new darnit controls (RE-01.03, RE-03.02)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from darnit_reproducibility import cli, handlers

from darnit.sieve.handler_registry import HandlerContext, HandlerResultStatus

_ROOT = Path(__file__).resolve().parents[2]
_FIX = _ROOT / "packages" / "darnit-reproducibility" / "examples" / "research" / "lorenz" / "fixtures"


def _repo_with_bundle(tmp_path: Path) -> Path:
    amber = tmp_path / ".amber"
    amber.mkdir()
    shutil.copy(_FIX / "bundle.redacted.json", amber / "bundle.json")
    shutil.copy(_FIX / "amber-pylibs.redacted.json", amber / "amber-pylibs.json")
    return tmp_path


# ── RE-01.03 RuntimeProvenanceCaptured ─────────────────────────────────────────

def test_runtime_provenance_pass_with_bundle(tmp_path: Path) -> None:
    repo = _repo_with_bundle(tmp_path)
    res = handlers.repro_runtime_provenance_handler({}, HandlerContext(local_path=str(repo)))
    assert res.status == HandlerResultStatus.PASS
    assert "used deps" in res.message


def test_runtime_provenance_inconclusive_without_bundle(tmp_path: Path) -> None:
    res = handlers.repro_runtime_provenance_handler({}, HandlerContext(local_path=str(tmp_path)))
    assert res.status == HandlerResultStatus.INCONCLUSIVE


# ── RE-03.02 ReproVerified ─────────────────────────────────────────────────────

def _write_verdict(tmp_path: Path, level: str) -> None:
    amber = tmp_path / ".amber"
    amber.mkdir(exist_ok=True)
    (amber / "verdict.reproducibility.json").write_text(json.dumps(
        {"predicateType": "https://darnit.dev/attestations/reproducibility/v1",
         "predicate": {"verdict": {"level": level, "reproduction_rate": 1.0}}}))


def test_repro_verified_pass(tmp_path: Path) -> None:
    _write_verdict(tmp_path, "REPRODUCED_WITH_DRIFT")
    res = handlers.repro_verified_handler({}, HandlerContext(local_path=str(tmp_path)))
    assert res.status == HandlerResultStatus.PASS


def test_repro_verified_fail_on_not_reproduced(tmp_path: Path) -> None:
    _write_verdict(tmp_path, "NOT_REPRODUCED")
    res = handlers.repro_verified_handler({}, HandlerContext(local_path=str(tmp_path)))
    assert res.status == HandlerResultStatus.FAIL


def test_repro_verified_inconclusive_without_attestation(tmp_path: Path) -> None:
    res = handlers.repro_verified_handler({}, HandlerContext(local_path=str(tmp_path)))
    assert res.status == HandlerResultStatus.INCONCLUSIVE


# ── RE-02.03 CapturedDepsNoKnownVulns ──────────────────────────────────────────

def test_deps_no_known_vulns_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo_with_bundle(tmp_path)
    monkeypatch.setattr("darnit_reproducibility.analysis.vuln.report",
                        lambda rec, **kw: {"status": "clean", "checked": 2, "vulnerable": []})
    res = handlers.repro_deps_no_known_vulns_handler({}, HandlerContext(local_path=str(repo)))
    assert res.status == HandlerResultStatus.PASS


def test_deps_no_known_vulns_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo_with_bundle(tmp_path)
    monkeypatch.setattr(
        "darnit_reproducibility.analysis.vuln.report",
        lambda rec, **kw: {"status": "vulnerable", "checked": 2,
                           "vulnerable": [{"package": "x", "version": "1", "vuln_ids": ["CVE-1"]}]})
    res = handlers.repro_deps_no_known_vulns_handler({}, HandlerContext(local_path=str(repo)))
    assert res.status == HandlerResultStatus.FAIL


def test_deps_no_known_vulns_inconclusive_without_bundle(tmp_path: Path) -> None:
    res = handlers.repro_deps_no_known_vulns_handler({}, HandlerContext(local_path=str(tmp_path)))
    assert res.status == HandlerResultStatus.INCONCLUSIVE


def test_deps_no_known_vulns_config_disables(tmp_path: Path) -> None:
    repo = _repo_with_bundle(tmp_path)
    res = handlers.repro_deps_no_known_vulns_handler({"check_osv": False},
                                                     HandlerContext(local_path=str(repo)))
    assert res.status == HandlerResultStatus.INCONCLUSIVE


# ── amber CLI dispatch ─────────────────────────────────────────────────────────

def test_cli_no_args_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 2


def test_cli_help_returns_0() -> None:
    assert cli.main(["--help"]) == 0


def test_cli_unknown_command_returns_2() -> None:
    assert cli.main(["frobnicate"]) == 2


def test_cli_ingest_real_bundle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _repo_with_bundle(tmp_path)
    rc = cli.main(["ingest", str(repo / ".amber" / "bundle.json")])
    assert rc == 0
    assert "AMBER CAPTURE REPORT" in capsys.readouterr().out


def test_cli_verify_identical_is_reproduced(capsys: pytest.CaptureFixture[str]) -> None:
    bundle = str(_FIX / "bundle.redacted.json")
    pylibs = str(_FIX / "amber-pylibs.redacted.json")
    rc = cli.main(["verify", bundle, bundle,
                   "--original-pylibs", pylibs, "--reproduction-pylibs", pylibs])
    assert rc == 0  # bit-for-bit
    assert "REPRODUCIBILITY VERDICT" in capsys.readouterr().out


def test_cli_verify_require_signed_rejects_unsigned() -> None:
    bundle = str(_FIX / "bundle.redacted.json")
    pylibs = str(_FIX / "amber-pylibs.redacted.json")
    rc = cli.main(["verify", bundle, bundle, "--original-pylibs", pylibs,
                   "--reproduction-pylibs", pylibs, "--require-signed"])
    assert rc == 3  # redacted fixtures are unsigned


def test_cli_verify_writes_attestation(tmp_path: Path) -> None:
    bundle = str(_FIX / "bundle.redacted.json")
    pylibs = str(_FIX / "amber-pylibs.redacted.json")
    out = tmp_path / "att.json"
    rc = cli.main(["verify", bundle, bundle, "--original-pylibs", pylibs,
                   "--reproduction-pylibs", pylibs, "--attestation-out", str(out)])
    assert rc == 0 and out.is_file()
    data = json.loads(out.read_text())
    assert data["predicateType"] == "https://darnit.dev/attestations/reproducibility/v1"
    assert data["predicate"]["verdict"]["level"] in ("BIT_FOR_BIT", "REPRODUCED_WITH_DRIFT")
