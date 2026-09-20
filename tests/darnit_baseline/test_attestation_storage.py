"""Tests for storage backend wiring in the attestation generator."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from darnit.storage.backends import MemoryBackend
from darnit_baseline.attestation.generator import generate_attestation_from_results


def make_audit_result(tmp_path: Path) -> MagicMock:
    """Create a minimal AuditResult mock."""
    result = MagicMock()
    result.owner = "org"
    result.repo = "repo"
    result.commit = "abc123def456"
    result.ref = "refs/heads/main"
    result.level = 1
    result.all_results = []
    result.project_config = None
    result.local_path = str(tmp_path)
    return result


@pytest.mark.unit
class TestAttestationStorageWiring:
    """Tests that the storage backend is called correctly from the generator."""

    def test_stores_attestation_via_memory_backend(self, tmp_path: Path) -> None:
        """With a MemoryBackend, the attestation should be stored and retrievable."""
        backend = MemoryBackend()
        audit_result = make_audit_result(tmp_path)

        with patch("darnit.storage.backends.get_backend", return_value=backend), \
             patch("darnit_baseline.attestation.generator.ATTESTATION_AVAILABLE", False):

            generate_attestation_from_results(
                audit_result=audit_result,
                sign=False,
                storage_config={"backend": "memory"},
            )

        stored = backend.retrieve_attestation(
            "https://github.com/org/repo", "abc123def456"
        )
        assert stored is not None
        assert stored["subject"][0]["digest"]["gitCommit"] == "abc123def456"

    def test_storage_failure_does_not_raise(self, tmp_path: Path) -> None:
        """If the storage backend fails, the generator should still return the attestation."""
        broken_backend = MagicMock()
        broken_backend.store_attestation.side_effect = RuntimeError("backend down")
        audit_result = make_audit_result(tmp_path)

        with patch("darnit.storage.backends.get_backend", return_value=broken_backend), \
             patch("darnit_baseline.attestation.generator.ATTESTATION_AVAILABLE", False):

            result = generate_attestation_from_results(
                audit_result=audit_result,
                sign=False,
                storage_config={"backend": "memory"},
            )

        # Should still return the attestation despite storage failure
        assert "abc123def456" in result

    def test_no_storage_config_uses_file_backend(self, tmp_path: Path) -> None:
        """Without storage_config, falls back to default FileBackend."""
        audit_result = make_audit_result(tmp_path)

        with patch("darnit_baseline.attestation.generator.ATTESTATION_AVAILABLE", False):
            result = generate_attestation_from_results(
                audit_result=audit_result,
                sign=False,
                storage_config=None,
            )

        assert "abc123def456" in result

    def test_storage_ref_logged_on_success(self, tmp_path: Path) -> None:
        """A successful store should log the storage reference."""
        backend = MemoryBackend()
        audit_result = make_audit_result(tmp_path)

        with patch("darnit.storage.backends.get_backend", return_value=backend), \
             patch("darnit_baseline.attestation.generator.ATTESTATION_AVAILABLE", False), \
             patch("darnit_baseline.attestation.generator.logger") as mock_logger:

            generate_attestation_from_results(
                audit_result=audit_result,
                sign=False,
                storage_config={"backend": "memory"},
            )

        # The generator emits multiple info logs (file save + storage backend).
        # Verify the storage backend log is among them.
        assert mock_logger.info.called
        log_messages = [
            call.args[0] for call in mock_logger.info.call_args_list if call.args
        ]
        assert any("memory://" in msg for msg in log_messages), (
            f"Expected a log message containing 'memory://', got: {log_messages}"
        )
