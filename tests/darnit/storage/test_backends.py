"""Tests for storage backends."""

from pathlib import Path

import pytest

from darnit.storage.backends import (
    ArchivistaBackend,
    FileBackend,
    MemoryBackend,
    get_backend,
)

SAMPLE_ATTESTATION = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "git+https://github.com/org/repo", "digest": {"gitCommit": "abc123"}}],
    "predicateType": "https://openssf.org/baseline/assessment/v1",
    "predicate": {"result": "pass"},
}

SAMPLE_METADATA = {
    "name": "my-project",
    "ci": {"provider": "github_actions"},
}

SAMPLE_RESULT = {
    "control": "RE-01.01",
    "status": "PASS",
    "details": "uv.lock found",
}

REPO_URL = "https://github.com/org/repo"
COMMIT = "abc123def456"

@pytest.mark.unit
class TestMemoryBackend:
    """Tests for MemoryBackend — simplest to test, no filesystem."""

    def setup_method(self):
        self.backend = MemoryBackend()

    def test_store_and_retrieve_attestation(self):
        ref = self.backend.store_attestation(REPO_URL, COMMIT, SAMPLE_ATTESTATION)
        assert ref is not None
        result = self.backend.retrieve_attestation(REPO_URL, COMMIT)
        assert result == SAMPLE_ATTESTATION

    def test_retrieve_missing_attestation_returns_none(self):
        result = self.backend.retrieve_attestation(REPO_URL, "nonexistent")
        assert result is None

    def test_store_and_retrieve_metadata(self):
        success = self.backend.store_metadata(REPO_URL, SAMPLE_METADATA)
        assert success is True
        result = self.backend.retrieve_metadata(REPO_URL)
        assert result == SAMPLE_METADATA

    def test_retrieve_missing_metadata_returns_none(self):
        result = self.backend.retrieve_metadata("https://github.com/nobody/nothing")
        assert result is None

    def test_store_and_retrieve_research_result(self):
        success = self.backend.store_research_result(REPO_URL, COMMIT, SAMPLE_RESULT)
        assert success is True
        result = self.backend.retrieve_research_result(REPO_URL, COMMIT)
        assert result == SAMPLE_RESULT

    def test_retrieve_missing_research_result_returns_none(self):
        result = self.backend.retrieve_research_result(REPO_URL, "nonexistent")
        assert result is None

    def test_different_commits_are_independent(self):
        self.backend.store_attestation(REPO_URL, "commit1", {"data": "first"})
        self.backend.store_attestation(REPO_URL, "commit2", {"data": "second"})
        assert self.backend.retrieve_attestation(REPO_URL, "commit1") == {"data": "first"}
        assert self.backend.retrieve_attestation(REPO_URL, "commit2") == {"data": "second"}

    def test_different_repos_are_independent(self):
        repo2 = "https://github.com/org/other-repo"
        self.backend.store_metadata(REPO_URL, {"name": "repo1"})
        self.backend.store_metadata(repo2, {"name": "repo2"})
        assert self.backend.retrieve_metadata(REPO_URL)["name"] == "repo1"
        assert self.backend.retrieve_metadata(repo2)["name"] == "repo2"

@pytest.mark.unit
class TestFileBackend:
    """Tests for FileBackend — uses tmp_path, no real filesystem pollution."""

    def test_store_and_retrieve_attestation(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        ref = backend.store_attestation(REPO_URL, COMMIT, SAMPLE_ATTESTATION)
        assert ref is not None
        assert Path(ref).exists()
        result = backend.retrieve_attestation(REPO_URL, COMMIT)
        assert result == SAMPLE_ATTESTATION

    def test_retrieve_missing_attestation_returns_none(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        result = backend.retrieve_attestation(REPO_URL, "nonexistent")
        assert result is None

    def test_store_and_retrieve_metadata(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        success = backend.store_metadata(REPO_URL, SAMPLE_METADATA)
        assert success is True
        result = backend.retrieve_metadata(REPO_URL)
        assert result == SAMPLE_METADATA

    def test_retrieve_missing_metadata_returns_none(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        result = backend.retrieve_metadata("https://github.com/nobody/nothing")
        assert result is None

    def test_store_and_retrieve_research_result(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        success = backend.store_research_result(REPO_URL, COMMIT, SAMPLE_RESULT)
        assert success is True
        result = backend.retrieve_research_result(REPO_URL, COMMIT)
        assert result == SAMPLE_RESULT

    def test_creates_directories_automatically(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / "deep" / "nested" / ".darnit"))
        backend.store_attestation(REPO_URL, COMMIT, SAMPLE_ATTESTATION)
        result = backend.retrieve_attestation(REPO_URL, COMMIT)
        assert result == SAMPLE_ATTESTATION

    def test_repo_slug_handles_special_chars(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        backend.store_metadata("https://github.com/my-org/my-repo", {"name": "test"})
        result = backend.retrieve_metadata("https://github.com/my-org/my-repo")
        assert result == {"name": "test"}

    def test_different_commits_stored_separately(self, tmp_path: Path):
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        backend.store_attestation(REPO_URL, "commit1", {"data": "first"})
        backend.store_attestation(REPO_URL, "commit2", {"data": "second"})
        assert backend.retrieve_attestation(REPO_URL, "commit1") == {"data": "first"}
        assert backend.retrieve_attestation(REPO_URL, "commit2") == {"data": "second"}

    def test_repo_slug_no_collision_between_slash_and_underscore(self, tmp_path: Path) -> None:
        """org/repo and org_repo should produce different slugs."""
        backend = FileBackend(base_dir=str(tmp_path / ".darnit"))
        backend.store_metadata("https://github.com/org/repo", {"name": "slash"})
        backend.store_metadata("https://github.com/org_repo", {"name": "underscore"})
        assert backend.retrieve_metadata("https://github.com/org/repo")["name"] == "slash"
        assert backend.retrieve_metadata("https://github.com/org_repo")["name"] == "underscore"

@pytest.mark.unit
class TestArchivistaBackend:
    """Tests for ArchivistaBackend.

    We don't make real HTTP calls — we verify that it falls back to
    FileBackend correctly when Archivista is unavailable.
    """

    def test_falls_back_to_file_on_connection_error(self, tmp_path: Path):
        backend = ArchivistaBackend(
            archivista_url="http://localhost:99999",
            base_dir=str(tmp_path / ".darnit"),
        )
        ref = backend.store_attestation(REPO_URL, COMMIT, SAMPLE_ATTESTATION)
        # Should fall back to file storage
        assert ref is not None
        assert Path(ref).exists()

    def test_metadata_always_uses_file(self, tmp_path: Path):
        backend = ArchivistaBackend(
            archivista_url="http://localhost:99999",
            base_dir=str(tmp_path / ".darnit"),
        )
        success = backend.store_metadata(REPO_URL, SAMPLE_METADATA)
        assert success is True
        result = backend.retrieve_metadata(REPO_URL)
        assert result == SAMPLE_METADATA

    def test_research_always_uses_file(self, tmp_path: Path):
        backend = ArchivistaBackend(
            archivista_url="http://localhost:99999",
            base_dir=str(tmp_path / ".darnit"),
        )
        success = backend.store_research_result(REPO_URL, COMMIT, SAMPLE_RESULT)
        assert success is True
        result = backend.retrieve_research_result(REPO_URL, COMMIT)
        assert result == SAMPLE_RESULT

@pytest.mark.unit
class TestGetBackendFactory:
    """Tests for the get_backend() factory function."""

    def test_returns_file_backend_by_default(self):
        backend = get_backend()
        assert isinstance(backend, FileBackend)

    def test_returns_file_backend_explicitly(self):
        backend = get_backend({"backend": "file"})
        assert isinstance(backend, FileBackend)

    def test_returns_memory_backend(self):
        backend = get_backend({"backend": "memory"})
        assert isinstance(backend, MemoryBackend)

    def test_returns_archivista_backend(self):
        backend = get_backend({"backend": "archivista"})
        assert isinstance(backend, ArchivistaBackend)

    def test_archivista_url_passed_through(self):
        backend = get_backend({
            "backend": "archivista",
            "archivista_url": "http://my-archivista:8082",
        })
        assert isinstance(backend, ArchivistaBackend)
        assert backend.archivista_url == "http://my-archivista:8082"

    def test_unknown_backend_falls_back_to_file(self):
        backend = get_backend({"backend": "something_weird"})
        assert isinstance(backend, FileBackend)

    def test_none_config_returns_file(self):
        backend = get_backend(None)
        assert isinstance(backend, FileBackend)

    def test_empty_config_returns_file(self):
        backend = get_backend({})
        assert isinstance(backend, FileBackend)
