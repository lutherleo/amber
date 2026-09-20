"""Tests for the Sigstore sidecar verification helper.

The ``verify`` function is deliberately isolated so the sandboxing
follow-up (issue #375) can extend it without touching the pool. These
tests lock the four operator-observable outcomes: sidecar absent,
sidecar malformed, sigstore SDK unavailable, and (implicitly, via
mcp_handler coverage) success/failure verification.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from darnit.sieve.mcp_trust import verify


def _has_sigstore() -> bool:
    try:
        importlib.import_module("sigstore.models")
        importlib.import_module("sigstore.verify")
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# T033: no sidecar -> (False, reason)
# ---------------------------------------------------------------------------


def test_no_sidecar_returns_false_with_reason(tmp_path):
    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(b"fake elf")
    ok, reason = verify(binary, "https://github.com/example/example")
    assert ok is False
    assert "no Sigstore sidecar" in reason
    assert str(binary) in reason


# ---------------------------------------------------------------------------
# T034: malformed sidecar -> (False, "Sigstore verification failed: ...")
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_sigstore(),
    reason="sigstore extra not installed in this environment",
)
def test_malformed_sidecar_returns_false(tmp_path):
    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(b"fake elf")
    sidecar = tmp_path / "scorecard-mcp.sigstore"
    sidecar.write_text('{"not": "a bundle"}')
    ok, reason = verify(binary, "https://github.com/example/example")
    assert ok is False
    assert "Sigstore verification failed" in reason


# ---------------------------------------------------------------------------
# T035: sigstore SDK unavailable -> (False, "install darnit-core[attestation]")
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Subject-digest binding: DSSE path must reject bundles whose in-toto
# statement doesn't cover the on-disk binary (review of PR #380, finding 1).
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_sigstore(),
    reason="sigstore extra not installed in this environment",
)
def test_dsse_subject_digest_mismatch_rejected(tmp_path, monkeypatch):
    """A valid bundle whose in-toto subject digest does not match the binary
    on disk MUST be rejected. Prevents the substituted-binary attack Marc
    flagged: any valid bundle from the trusted repo's workflow would
    otherwise pass regardless of which binary sat beside it."""
    import hashlib as _hashlib
    import json as _json

    from darnit.sieve import mcp_trust as _mcp_trust

    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(b"actual on-disk bytes")
    sidecar = tmp_path / "scorecard-mcp.sigstore"
    sidecar.write_text('{"placeholder": true}')

    other_digest = _hashlib.sha256(b"a completely different artifact").hexdigest()
    fake_statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{"name": "somebinary", "digest": {"sha256": other_digest}}],
        "predicate": {},
    }

    class _FakeBundle:
        @classmethod
        def from_json(cls, _bytes):
            return cls()

    class _FakeVerifier:
        @classmethod
        def production(cls):
            return cls()

        def verify_artifact(self, hashed, bundle, policy):
            raise RuntimeError("not a direct-artifact signature")

        def verify_dsse(self, bundle, policy):
            return "application/vnd.in-toto+json", _json.dumps(fake_statement).encode()

    monkeypatch.setattr(_mcp_trust, "_find_sidecar", lambda p: sidecar)
    # Patch the sigstore surfaces that verify() imports lazily.
    import sigstore.models as _sm
    import sigstore.verify as _sv

    monkeypatch.setattr(_sm, "Bundle", _FakeBundle)
    monkeypatch.setattr(_sv, "Verifier", _FakeVerifier)

    ok, reason = _mcp_trust.verify(binary, "https://github.com/example/repo")
    assert ok is False
    assert "no subject.digest.sha256 matches" in reason


@pytest.mark.skipif(
    not _has_sigstore(),
    reason="sigstore extra not installed in this environment",
)
def test_dsse_subject_digest_match_accepted(tmp_path, monkeypatch):
    """A DSSE bundle whose in-toto subject digest equals the binary's
    SHA-256 MUST pass; balances the negative test above."""
    import hashlib as _hashlib
    import json as _json

    from darnit.sieve import mcp_trust as _mcp_trust

    payload = b"the exact bytes that got signed"
    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(payload)
    sidecar = tmp_path / "scorecard-mcp.sigstore"
    sidecar.write_text('{"placeholder": true}')

    matching_digest = _hashlib.sha256(payload).hexdigest()
    good_statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [
            {"name": "somewhere_else", "digest": {"sha256": "0" * 64}},
            {"name": "scorecard-mcp", "digest": {"sha256": matching_digest}},
        ],
        "predicate": {},
    }

    class _FakeBundle:
        @classmethod
        def from_json(cls, _bytes):
            return cls()

    class _FakeVerifier:
        @classmethod
        def production(cls):
            return cls()

        def verify_artifact(self, hashed, bundle, policy):
            raise RuntimeError("not a direct-artifact signature")

        def verify_dsse(self, bundle, policy):
            return "application/vnd.in-toto+json", _json.dumps(good_statement).encode()

    monkeypatch.setattr(_mcp_trust, "_find_sidecar", lambda p: sidecar)
    import sigstore.models as _sm
    import sigstore.verify as _sv

    monkeypatch.setattr(_sm, "Bundle", _FakeBundle)
    monkeypatch.setattr(_sv, "Verifier", _FakeVerifier)

    ok, reason = _mcp_trust.verify(binary, "https://github.com/example/repo")
    assert ok is True, reason
    assert "DSSE in-toto attestation" in reason


@pytest.mark.skipif(
    not _has_sigstore(),
    reason="sigstore extra not installed in this environment",
)
def test_direct_artifact_signature_accepted(tmp_path, monkeypatch):
    """A direct-artifact bundle (cosign sign-blob shape) MUST pass without
    entering the DSSE fallback. verify_artifact does the binding for us."""
    from darnit.sieve import mcp_trust as _mcp_trust

    payload = b"artifact bytes"
    binary = tmp_path / "cli-tool"
    binary.write_bytes(payload)
    sidecar = tmp_path / "cli-tool.sigstore"
    sidecar.write_text('{"placeholder": true}')

    class _FakeBundle:
        @classmethod
        def from_json(cls, _bytes):
            return cls()

    dsse_called = False

    class _FakeVerifier:
        @classmethod
        def production(cls):
            return cls()

        def verify_artifact(self, hashed, bundle, policy):
            return None  # success

        def verify_dsse(self, bundle, policy):
            nonlocal dsse_called
            dsse_called = True
            raise AssertionError("should not run when verify_artifact succeeds")

    monkeypatch.setattr(_mcp_trust, "_find_sidecar", lambda p: sidecar)
    import sigstore.models as _sm
    import sigstore.verify as _sv

    monkeypatch.setattr(_sm, "Bundle", _FakeBundle)
    monkeypatch.setattr(_sv, "Verifier", _FakeVerifier)

    ok, reason = _mcp_trust.verify(binary, "https://github.com/example/repo")
    assert ok is True, reason
    assert "direct-artifact signature" in reason
    assert dsse_called is False


def test_sigstore_unavailable_returns_false(tmp_path, monkeypatch):
    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(b"fake elf")
    sidecar = tmp_path / "scorecard-mcp.sigstore"
    sidecar.write_text("{}")

    # Blot out any pre-imported sigstore submodules so the ImportError
    # branch runs deterministically even when the extra is installed.
    for name in list(sys.modules):
        if name == "sigstore" or name.startswith("sigstore."):
            monkeypatch.setitem(sys.modules, name, None)

    ok, reason = verify(binary, "https://github.com/example/example")
    assert ok is False
    assert "sigstore not installed" in reason
    assert "darnit-core[attestation]" in reason
