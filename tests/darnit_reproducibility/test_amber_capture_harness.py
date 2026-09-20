"""Token-free tests for the capture harness command/env construction (``capture.run``)."""
from __future__ import annotations

import argparse
from pathlib import Path

from darnit_reproducibility.capture import run


def _args(**kw: object) -> argparse.Namespace:
    base = {"step": "s", "outfile": "/tmp/b.json", "no_ebpf": True,
            "command": ["python", "x.py"], "sign": False, "signer_flags": None}
    base.update(kw)
    return argparse.Namespace(**base)


def _build(args: argparse.Namespace, signer: list[str] | None = None):
    return run.build_command(args, Path("/shim"), Path("/tmp/pylibs.json"), Path("/repo"),
                             "witness", signer or ["-k", "key.pem"])


def test_baseline_no_ebpf_no_sudo() -> None:
    argv, env = _build(_args(no_ebpf=True))
    assert argv[0] == "witness"
    assert "--experimental" not in argv and "--trace" not in argv
    assert "network-trace" not in argv
    assert "environment" in argv and "git" in argv
    assert env["AMBER_SHIM_DIR"] == "/shim"
    assert env["AMBER_REPO_ROOT"] == "/repo"


def test_ebpf_uses_sudo_and_experimental() -> None:
    argv, _ = _build(_args(no_ebpf=False))
    assert argv[0] == "sudo"
    assert "--experimental" in argv and "--trace" in argv
    assert "network-trace" in argv


def test_signer_flags_passed_before_command() -> None:
    argv, _ = _build(_args(no_ebpf=True), signer=["-k", "mykey.pem"])
    assert "-k" in argv and "mykey.pem" in argv
    assert argv.index("mykey.pem") < argv.index("--")


def test_sign_selects_fulcio_keyless(tmp_path: Path) -> None:
    flags = run._ensure_signer(_args(sign=True, signer_flags=None), tmp_path)
    assert "--signer-fulcio-url" in flags
    assert "https://fulcio.sigstore.dev" in flags
    # no ephemeral key was minted
    assert not (tmp_path / "amber-ephemeral-key.pem").exists()


def test_explicit_signer_flags_win(tmp_path: Path) -> None:
    flags = run._ensure_signer(_args(sign=True, signer_flags=["-k", "x.pem"]), tmp_path)
    assert flags == ["-k", "x.pem"]
