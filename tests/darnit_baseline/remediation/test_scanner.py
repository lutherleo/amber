"""Tests for the repository scanner module."""



from darnit_baseline.remediation.scanner import (
    APP_CAPABILITY_MAP,
    DirectoryTree,
    RepoScanContext,
    _scan_ci_workflows,
    _scan_dependency_tool,
    _scan_directory_structure,
    _scan_existing_docs,
    _scan_languages_and_commands,
    _scan_package_manager,
    flatten_scan_context,
    scan_repository,
)

# =============================================================================
# RepoScanContext and flatten_scan_context tests (T012)
# =============================================================================


class TestRepoScanContext:
    """Tests for RepoScanContext dataclass creation."""

    def test_empty_context(self):
        ctx = RepoScanContext()
        assert ctx.languages == []
        assert ctx.primary_language is None
        assert ctx.package_manager is None
        assert ctx.test_commands == {}
        assert ctx.ci_tools == {}
        assert ctx.directory_tree.top_level == []
        assert ctx.existing_docs == {}

    def test_populated_context(self):
        ctx = RepoScanContext(
            languages=["python", "go"],
            primary_language="python",
            package_manager="uv",
            test_commands={"python": "uv run pytest", "go": "go test ./..."},
            lint_commands={"python": "uv run ruff check ."},
            ci_tools={"sast": ["CodeQL"]},
            dependency_update_tool="Dependabot",
        )
        assert ctx.languages == ["python", "go"]
        assert ctx.primary_language == "python"
        assert ctx.ci_tools["sast"] == ["CodeQL"]


class TestFlattenScanContext:
    """Tests for flatten_scan_context()."""

    def test_empty_context_returns_empty_dict(self):
        ctx = RepoScanContext()
        result = flatten_scan_context(ctx)
        assert result == {}

    def test_language_fields(self):
        ctx = RepoScanContext(
            languages=["python", "go"],
            primary_language="python",
            package_manager="uv",
            test_commands={"python": "uv run pytest"},
            lint_commands={"python": "uv run ruff check ."},
        )
        result = flatten_scan_context(ctx)
        assert result["scan.languages"] == "python, go"
        assert result["scan.primary_language"] == "python"
        assert result["scan.package_manager"] == "uv"
        assert result["scan.test_command"] == "uv run pytest"
        assert result["scan.lint_command"] == "uv run ruff check ."

    def test_ci_tools(self):
        ctx = RepoScanContext(
            ci_tools={
                "sast": ["CodeQL", "Semgrep"],
                "sca": ["GitHub Dependency Review"],
            }
        )
        result = flatten_scan_context(ctx)
        assert result["scan.ci_sast_tools"] == "CodeQL, Semgrep"
        assert result["scan.ci_sca_tools"] == "GitHub Dependency Review"
        assert "scan.ci_sbom_tools" not in result

    def test_dependency_tool(self):
        ctx = RepoScanContext(dependency_update_tool="Dependabot")
        result = flatten_scan_context(ctx)
        assert result["scan.dependency_tool"] == "Dependabot"

    def test_directory_tree(self):
        tree = DirectoryTree(
            top_level=["packages/", "tests/"],
            source_dirs={"packages/": ["darnit/", "darnit-baseline/"]},
        )
        ctx = RepoScanContext(directory_tree=tree)
        result = flatten_scan_context(ctx)
        assert "scan.directory_tree" in result
        assert "packages" in result["scan.directory_tree"]

    def test_doc_links(self):
        ctx = RepoScanContext(doc_links=["https://docs.example.com"])
        result = flatten_scan_context(ctx)
        assert "https://docs.example.com" in result["scan.doc_links"]

    def test_governance_context(self):
        ctx = RepoScanContext(governance_context="governed by Kusari, Inc")
        result = flatten_scan_context(ctx)
        assert result["scan.governance_context"] == "governed by Kusari, Inc"

    def test_community_links(self):
        ctx = RepoScanContext(
            code_of_conduct_path="CODE_OF_CONDUCT.md",
            security_policy_path="SECURITY.md",
        )
        result = flatten_scan_context(ctx)
        assert "CODE_OF_CONDUCT.md" in result["scan.code_of_conduct_link"]
        assert "SECURITY.md" in result["scan.security_policy_link"]

    def test_multi_language_test_commands(self):
        ctx = RepoScanContext(
            languages=["python", "go"],
            primary_language="python",
            test_commands={"python": "uv run pytest", "go": "go test ./..."},
            lint_commands={"python": "uv run ruff check .", "go": "golangci-lint run"},
        )
        result = flatten_scan_context(ctx)
        all_cmds = result["scan.test_commands_all"]
        assert "uv run pytest" in all_cmds
        assert "go test" in all_cmds
        assert "### Python" in all_cmds
        assert "### Go" in all_cmds


# =============================================================================
# Package manager detection tests (T016)
# =============================================================================


class TestScanPackageManager:
    """Tests for _scan_package_manager()."""

    def test_uv_lock(self, tmp_path):
        (tmp_path / "uv.lock").touch()
        assert _scan_package_manager(str(tmp_path)) == "uv"

    def test_poetry_lock(self, tmp_path):
        (tmp_path / "poetry.lock").touch()
        assert _scan_package_manager(str(tmp_path)) == "poetry"

    def test_npm_lock(self, tmp_path):
        (tmp_path / "package-lock.json").touch()
        assert _scan_package_manager(str(tmp_path)) == "npm"

    def test_yarn_lock(self, tmp_path):
        (tmp_path / "yarn.lock").touch()
        assert _scan_package_manager(str(tmp_path)) == "yarn"

    def test_cargo_lock(self, tmp_path):
        (tmp_path / "Cargo.lock").touch()
        assert _scan_package_manager(str(tmp_path)) == "cargo"

    def test_no_lockfile(self, tmp_path):
        assert _scan_package_manager(str(tmp_path)) is None

    def test_uv_takes_priority_over_npm(self, tmp_path):
        (tmp_path / "uv.lock").touch()
        (tmp_path / "package-lock.json").touch()
        assert _scan_package_manager(str(tmp_path)) == "uv"


# =============================================================================
# Directory structure scanning tests (T020)
# =============================================================================


class TestScanDirectoryStructure:
    """Tests for _scan_directory_structure()."""

    def test_monorepo(self, tmp_path):
        (tmp_path / "packages" / "darnit").mkdir(parents=True)
        (tmp_path / "packages" / "darnit-baseline").mkdir(parents=True)
        (tmp_path / "tests").mkdir()
        (tmp_path / "docs").mkdir()

        tree = _scan_directory_structure(str(tmp_path))
        assert "packages/" in tree.top_level
        assert "tests/" in tree.top_level
        assert "docs/" in tree.top_level
        assert "packages/" in tree.source_dirs
        assert "darnit/" in tree.source_dirs["packages/"]
        assert "darnit-baseline/" in tree.source_dirs["packages/"]

    def test_go_conventional(self, tmp_path):
        (tmp_path / "cmd" / "server").mkdir(parents=True)
        (tmp_path / "pkg" / "auth").mkdir(parents=True)
        (tmp_path / "internal" / "repo").mkdir(parents=True)

        tree = _scan_directory_structure(str(tmp_path))
        assert "cmd/" in tree.top_level
        assert "pkg/" in tree.top_level
        assert "internal/" in tree.top_level
        assert "cmd/" in tree.source_dirs

    def test_flat_structure(self, tmp_path):
        (tmp_path / "main.py").touch()
        (tmp_path / "utils.py").touch()

        tree = _scan_directory_structure(str(tmp_path))
        assert tree.top_level == []
        assert tree.source_dirs == {}

    def test_excludes_hidden_dirs(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".github").mkdir()
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "src" / "main").mkdir(parents=True)

        tree = _scan_directory_structure(str(tmp_path))
        assert ".git/" not in tree.top_level
        assert ".github/" not in tree.top_level
        assert "node_modules/" not in tree.top_level
        assert "src/" in tree.top_level

    def test_formatted_output(self, tmp_path):
        (tmp_path / "packages" / "core").mkdir(parents=True)
        (tmp_path / "tests").mkdir()

        tree = _scan_directory_structure(str(tmp_path))
        formatted = tree.formatted
        assert "packages" in formatted
        assert "core" in formatted
        assert "|" in formatted  # markdown table


# =============================================================================
# Language and command detection tests (T027)
# =============================================================================


class TestScanLanguagesAndCommands:
    """Tests for _scan_languages_and_commands()."""

    def test_python_with_uv(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "uv.lock").touch()

        langs, test_cmds, lint_cmds, build_cmds = _scan_languages_and_commands(
            str(tmp_path)
        )
        assert "python" in langs
        assert test_cmds["python"] == "uv run pytest"
        assert lint_cmds["python"] == "uv run ruff check ."

    def test_go_project(self, tmp_path):
        (tmp_path / "go.mod").touch()

        langs, test_cmds, lint_cmds, _ = _scan_languages_and_commands(str(tmp_path))
        assert "go" in langs
        assert test_cmds["go"] == "go test ./..."
        assert lint_cmds["go"] == "golangci-lint run"

    def test_multi_language(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "package.json").touch()

        langs, test_cmds, _, _ = _scan_languages_and_commands(str(tmp_path))
        assert "python" in langs
        assert "javascript" in langs
        assert "python" in test_cmds
        assert "javascript" in test_cmds

    def test_no_language(self, tmp_path):
        langs, test_cmds, _, _ = _scan_languages_and_commands(str(tmp_path))
        assert langs == []
        assert test_cmds == {}

    def test_rust_project(self, tmp_path):
        (tmp_path / "Cargo.toml").touch()

        langs, test_cmds, _, _ = _scan_languages_and_commands(str(tmp_path))
        assert "rust" in langs
        assert test_cmds["rust"] == "cargo test"


# =============================================================================
# Dependency tool detection tests
# =============================================================================


class TestScanDependencyTool:
    """Tests for _scan_dependency_tool()."""

    def test_dependabot(self, tmp_path):
        (tmp_path / ".github").mkdir()
        (tmp_path / ".github" / "dependabot.yml").touch()
        assert _scan_dependency_tool(str(tmp_path)) == "Dependabot"

    def test_renovate(self, tmp_path):
        (tmp_path / ".github").mkdir()
        (tmp_path / ".github" / "renovate.json").touch()
        assert _scan_dependency_tool(str(tmp_path)) == "Renovate"

    def test_no_tool(self, tmp_path):
        assert _scan_dependency_tool(str(tmp_path)) is None


# =============================================================================
# CI workflow parsing tests (T033)
# =============================================================================


class TestScanCIWorkflows:
    """Tests for _scan_ci_workflows()."""

    def test_codeql_detection(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "sast.yml").write_text(
            "jobs:\n  analyze:\n    steps:\n"
            "      - uses: github/codeql-action/init@v3\n"
            "      - uses: github/codeql-action/analyze@v3\n"
        )

        tools = _scan_ci_workflows(str(tmp_path))
        assert "sast" in tools
        assert "CodeQL" in tools["sast"]

    def test_multiple_tools(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "security.yml").write_text(
            "jobs:\n  scan:\n    steps:\n"
            "      - uses: github/codeql-action/init@v3\n"
            "      - uses: anchore/sbom-action@v0\n"
            "      - uses: sigstore/cosign-installer@v3\n"
        )

        tools = _scan_ci_workflows(str(tmp_path))
        assert "CodeQL" in tools.get("sast", [])
        assert "Syft (Anchore)" in tools.get("sbom", [])
        assert "Cosign" in tools.get("signing", [])

    def test_unknown_actions_ignored(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "jobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: custom-org/custom-action@v1\n"
        )

        tools = _scan_ci_workflows(str(tmp_path))
        # checkout and custom actions are not in ACTION_TOOL_MAP
        assert tools == {}

    def test_no_workflows_dir(self, tmp_path):
        tools = _scan_ci_workflows(str(tmp_path))
        assert tools == {}

    def test_deduplication(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "sast.yml").write_text(
            "jobs:\n  analyze:\n    steps:\n"
            "      - uses: github/codeql-action/init@v3\n"
        )
        (wf_dir / "pr.yml").write_text(
            "jobs:\n  check:\n    steps:\n"
            "      - uses: github/codeql-action/analyze@v3\n"
        )

        tools = _scan_ci_workflows(str(tmp_path))
        # CodeQL should appear only once even though found in two files
        assert tools["sast"].count("CodeQL") == 1


# =============================================================================
# Existing docs scanning tests (T039)
# =============================================================================


class TestScanExistingDocs:
    """Tests for _scan_existing_docs()."""

    def test_readme_with_links(self, tmp_path):
        (tmp_path / "README.md").write_text(
            "# My Project\n\n"
            "See docs at https://docs.example.com\n"
            "Also check https://api.example.com/v1\n"
        )

        docs = _scan_existing_docs(str(tmp_path))
        assert docs["README.md"].exists
        assert "https://docs.example.com" in docs["README.md"].links
        assert "https://api.example.com/v1" in docs["README.md"].links

    def test_contributing_with_governance(self, tmp_path):
        (tmp_path / "CONTRIBUTING.md").write_text(
            "# Contributing\n\n"
            "This project is governed by Kusari, Inc\n"
        )

        docs = _scan_existing_docs(str(tmp_path))
        assert docs["CONTRIBUTING.md"].exists
        assert len(docs["CONTRIBUTING.md"].governance_mentions) > 0
        assert "governed by Kusari" in docs["CONTRIBUTING.md"].governance_mentions[0]

    def test_missing_docs(self, tmp_path):
        docs = _scan_existing_docs(str(tmp_path))
        assert not docs["README.md"].exists
        assert not docs["CONTRIBUTING.md"].exists
        assert docs["README.md"].links == []

    def test_code_of_conduct_existence(self, tmp_path):
        (tmp_path / "CODE_OF_CONDUCT.md").write_text("# Code of Conduct\n")

        docs = _scan_existing_docs(str(tmp_path))
        assert docs["CODE_OF_CONDUCT.md"].exists


# =============================================================================
# Full scan_repository integration test
# =============================================================================


class TestScanRepository:
    """Integration tests for scan_repository()."""

    def test_empty_repo(self, tmp_path):
        ctx = scan_repository(str(tmp_path))
        assert ctx.languages == []
        assert ctx.primary_language is None
        assert ctx.ci_tools == {}
        assert ctx.directory_tree.top_level == []

    def test_python_repo(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "uv.lock").touch()
        (tmp_path / "src" / "main").mkdir(parents=True)
        gh_dir = tmp_path / ".github"
        gh_dir.mkdir()
        (gh_dir / "dependabot.yml").touch()
        (tmp_path / "SECURITY.md").write_text("# Security\n")
        (tmp_path / "README.md").write_text(
            "# Project\nDocs: https://docs.example.com\n"
        )

        ctx = scan_repository(str(tmp_path))
        assert "python" in ctx.languages
        assert ctx.package_manager == "uv"
        assert ctx.test_commands["python"] == "uv run pytest"
        assert ctx.dependency_update_tool == "Dependabot"
        assert ctx.security_policy_path == "SECURITY.md"
        assert "https://docs.example.com" in ctx.doc_links
        assert "src/" in ctx.directory_tree.top_level


# =============================================================================
# GitHub Apps detection and capability merging (T041)
# =============================================================================


class TestGitHubAppsCapabilityMerge:
    """Tests for GitHub Apps capability merging into scan context."""

    def test_app_capability_map_has_kusari_inspector(self):
        assert "kusari-inspector" in APP_CAPABILITY_MAP
        name, caps = APP_CAPABILITY_MAP["kusari-inspector"]
        assert name == "Kusari Inspector"
        assert "sast" in caps
        assert "sca" in caps

    def test_flatten_merges_app_capabilities_into_ci_tools(self):
        """GitHub App capabilities merge into scan.ci_*_tools keys."""
        ctx = RepoScanContext(
            ci_tools={"sast": ["CodeQL"]},
            github_apps=[
                {"name": "Kusari Inspector", "slug": "kusari-inspector",
                 "capabilities": ["sast", "sca", "secrets", "license"]},
            ],
        )
        flat = flatten_scan_context(ctx)

        # SAST should contain both CodeQL (from workflows) and Kusari Inspector (from apps)
        assert "CodeQL" in flat["scan.ci_sast_tools"]
        assert "Kusari Inspector" in flat["scan.ci_sast_tools"]
        # SCA should be set from app alone (no workflow SCA detected)
        assert flat["scan.ci_sca_tools"] == "Kusari Inspector"
        # Secrets and license should be new keys
        assert flat["scan.ci_secrets_tools"] == "Kusari Inspector"
        assert flat["scan.ci_license_tools"] == "Kusari Inspector"
        # App names list
        assert flat["scan.github_apps"] == "Kusari Inspector"

    def test_flatten_no_duplicate_app_in_existing_tools(self):
        """If an app name already appears in CI tools, don't duplicate it."""
        ctx = RepoScanContext(
            ci_tools={"sast": ["Kusari Inspector"]},
            github_apps=[
                {"name": "Kusari Inspector", "slug": "kusari-inspector",
                 "capabilities": ["sast"]},
            ],
        )
        flat = flatten_scan_context(ctx)
        # Should appear once, not twice
        assert flat["scan.ci_sast_tools"].count("Kusari Inspector") == 1

    def test_flatten_empty_apps(self):
        """No github_apps produces no scan.github_apps key."""
        ctx = RepoScanContext()
        flat = flatten_scan_context(ctx)
        assert "scan.github_apps" not in flat
