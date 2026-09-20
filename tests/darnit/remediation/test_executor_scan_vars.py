"""Tests for ${scan.*} variable substitution in RemediationExecutor."""

from darnit.remediation.executor import RemediationExecutor


class TestScanVarSubstitution:
    """Tests for ${scan.*} namespace in _get_substitutions and _substitute."""

    def test_scan_vars_resolved(self):
        executor = RemediationExecutor(
            local_path="/tmp/test-repo",
            owner="test-org",
            repo="test-repo",
            scan_values={
                "scan.primary_language": "python",
                "scan.test_command": "uv run pytest",
                "scan.dependency_tool": "Dependabot",
            },
        )
        subs = executor._get_substitutions("OSPS-TEST-01")
        assert subs["${scan.primary_language}"] == "python"
        assert subs["${scan.test_command}"] == "uv run pytest"
        assert subs["${scan.dependency_tool}"] == "Dependabot"

    def test_scan_vars_in_substitute(self):
        executor = RemediationExecutor(
            local_path="/tmp/test-repo",
            owner="test-org",
            repo="test-repo",
            scan_values={
                "scan.test_command": "uv run pytest",
            },
        )
        result = executor._substitute(
            "Run tests with: << scan.test_command >>", "OSPS-TEST-01"
        )
        assert result == "Run tests with: uv run pytest"

    def test_unresolved_scan_vars_become_empty(self):
        executor = RemediationExecutor(
            local_path="/tmp/test-repo",
            owner="test-org",
            repo="test-repo",
            scan_values={},
        )
        result = executor._substitute(
            "Tool: << scan.missing_var >>", "OSPS-TEST-01"
        )
        assert result == "Tool: "

    def test_scan_vars_coexist_with_context_and_project(self):
        executor = RemediationExecutor(
            local_path="/tmp/test-repo",
            owner="test-org",
            repo="test-repo",
            context_values={"platform": "github"},
            project_values={"name": "my-project"},
            scan_values={"scan.primary_language": "python"},
        )
        subs = executor._get_substitutions("OSPS-TEST-01")
        assert subs["${context.platform}"] == "github"
        assert subs["${project.name}"] == "my-project"
        assert subs["${scan.primary_language}"] == "python"

    def test_empty_scan_values_ignored(self):
        executor = RemediationExecutor(
            local_path="/tmp/test-repo",
            owner="test-org",
            repo="test-repo",
            scan_values={"scan.empty_val": ""},
        )
        subs = executor._get_substitutions("OSPS-TEST-01")
        # Empty strings should not be added
        assert "${scan.empty_val}" not in subs

    def test_no_scan_values_param(self):
        executor = RemediationExecutor(
            local_path="/tmp/test-repo",
            owner="test-org",
            repo="test-repo",
        )
        # Should work fine with no scan_values at all
        subs = executor._get_substitutions("OSPS-TEST-01")
        assert "$OWNER" in subs
        # No scan vars present
        assert not any(k.startswith("${scan.") for k in subs)
