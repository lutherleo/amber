"""Invariant tests for darnit_baseline.threat_model.discovery_models.

The ranking test file covers CandidateFinding / TrimmedOverflow; this file
covers the rest of the discovery data model: DiscoveredEntryPoint,
DiscoveredDataStore, DataFlowTrace, FileScanStats, and the auto-generated
asset IDs.
"""

from __future__ import annotations

import pytest

from darnit_baseline.threat_model.discovery_models import (
    DataFlowStep,
    DataFlowTrace,
    DataStoreKind,
    DiscoveredDataStore,
    DiscoveredEntryPoint,
    EntryPointKind,
    FileScanStats,
    Location,
)


def _loc(file: str = "src/app.py", line: int = 10) -> Location:
    return Location(file=file, line=line, column=1, end_line=line, end_column=20)


# ---------------------------------------------------------------------------
# DiscoveredEntryPoint
# ---------------------------------------------------------------------------


class TestDiscoveredEntryPoint:
    def test_id_is_auto_generated_from_kind_language_location(self) -> None:
        ep = DiscoveredEntryPoint(
            kind=EntryPointKind.HTTP_ROUTE,
            name="get_user",
            location=_loc(line=42),
            language="python",
            framework="fastapi",
            route_path="/users/{id}",
            http_method="GET",
            has_auth_decorator=False,
            source_query="python.entry.fastapi_route",
        )
        assert ep.id == "ep:python:src/app.py:42"

    def test_id_is_stable_across_runs(self) -> None:
        """Two DiscoveredEntryPoint with identical inputs produce identical IDs."""
        kwargs = {
            "kind": EntryPointKind.HTTP_ROUTE,
            "name": "get_user",
            "location": _loc(),
            "language": "python",
            "framework": "fastapi",
            "route_path": "/users",
            "http_method": "GET",
            "has_auth_decorator": False,
            "source_query": "q",
        }
        a = DiscoveredEntryPoint(**kwargs)
        b = DiscoveredEntryPoint(**kwargs)
        assert a.id == b.id

    def test_http_route_requires_framework(self) -> None:
        with pytest.raises(ValueError, match="framework"):
            DiscoveredEntryPoint(
                kind=EntryPointKind.HTTP_ROUTE,
                name="h",
                location=_loc(),
                language="python",
                framework=None,
                route_path="/",
                http_method="GET",
                has_auth_decorator=False,
                source_query="q",
            )

    def test_mcp_tool_requires_framework(self) -> None:
        with pytest.raises(ValueError, match="framework"):
            DiscoveredEntryPoint(
                kind=EntryPointKind.MCP_TOOL,
                name="t",
                location=_loc(),
                language="python",
                framework=None,
                route_path=None,
                http_method=None,
                has_auth_decorator=False,
                source_query="q",
            )

    def test_cli_command_allows_no_framework(self) -> None:
        """CLI handlers don't carry framework metadata — None is OK."""
        ep = DiscoveredEntryPoint(
            kind=EntryPointKind.CLI_COMMAND,
            name="run",
            location=_loc(),
            language="python",
            framework=None,
            route_path=None,
            http_method=None,
            has_auth_decorator=False,
            source_query="q",
        )
        assert ep.framework is None


# ---------------------------------------------------------------------------
# DiscoveredDataStore
# ---------------------------------------------------------------------------


class TestDiscoveredDataStore:
    def test_id_is_auto_generated(self) -> None:
        ds = DiscoveredDataStore(
            kind=DataStoreKind.RELATIONAL_DB,
            technology="postgresql",
            location=_loc(file="src/db.py", line=7),
            language="python",
            import_evidence="psycopg",
            dependency_manifest_evidence="psycopg2",
            source_query="python.datastore.psycopg",
        )
        assert ds.id == "ds:python:src/db.py:7"

    def test_at_least_one_evidence_required(self) -> None:
        with pytest.raises(ValueError, match="evidence"):
            DiscoveredDataStore(
                kind=DataStoreKind.RELATIONAL_DB,
                technology="postgresql",
                location=_loc(),
                language="python",
                import_evidence=None,
                dependency_manifest_evidence=None,
                source_query="q",
            )

    def test_import_evidence_alone_is_sufficient(self) -> None:
        ds = DiscoveredDataStore(
            kind=DataStoreKind.KEY_VALUE,
            technology="redis",
            location=_loc(),
            language="python",
            import_evidence="redis",
            dependency_manifest_evidence=None,
            source_query="q",
        )
        assert ds.import_evidence == "redis"

    def test_dependency_evidence_alone_is_sufficient(self) -> None:
        ds = DiscoveredDataStore(
            kind=DataStoreKind.DOCUMENT_DB,
            technology="mongodb",
            location=_loc(),
            language="python",
            import_evidence=None,
            dependency_manifest_evidence="pymongo",
            source_query="q",
        )
        assert ds.dependency_manifest_evidence == "pymongo"


# ---------------------------------------------------------------------------
# DataFlowTrace
# ---------------------------------------------------------------------------


class TestDataFlowTrace:
    def test_same_file_trace_ok(self) -> None:
        loc = _loc(file="app.py", line=5)
        trace = DataFlowTrace(
            source=DataFlowStep(location=loc, content="user_input"),
            intermediate=(DataFlowStep(location=loc, content="cmd"),),
            sink=DataFlowStep(location=loc, content="subprocess.run(cmd)"),
        )
        assert trace.source.location.file == "app.py"

    def test_cross_file_source_sink_raises(self) -> None:
        with pytest.raises(ValueError, match="same file"):
            DataFlowTrace(
                source=DataFlowStep(
                    location=_loc(file="a.py"), content="user_input"
                ),
                intermediate=(),
                sink=DataFlowStep(
                    location=_loc(file="b.py"), content="subprocess.run"
                ),
            )

    def test_cross_file_intermediate_raises(self) -> None:
        with pytest.raises(ValueError, match="same file"):
            DataFlowTrace(
                source=DataFlowStep(
                    location=_loc(file="a.py"), content="source"
                ),
                intermediate=(
                    DataFlowStep(location=_loc(file="b.py"), content="step"),
                ),
                sink=DataFlowStep(location=_loc(file="a.py"), content="sink"),
            )


# ---------------------------------------------------------------------------
# FileScanStats
# ---------------------------------------------------------------------------


class TestFileScanStats:
    def test_valid_stats(self) -> None:
        stats = FileScanStats(
            total_files_seen=10,
            excluded_dir_count=2,
            unsupported_file_count=3,
            in_scope_files=7,
            by_language={"python": 5, "yaml": 2},
            shallow_mode=False,
            shallow_threshold=500,
        )
        assert stats.total_files_seen == 10

    def test_invariant_total_equals_unsupported_plus_in_scope(self) -> None:
        with pytest.raises(ValueError, match="total_files_seen"):
            FileScanStats(
                total_files_seen=10,
                excluded_dir_count=2,
                unsupported_file_count=3,
                in_scope_files=5,  # 3 + 5 = 8, not 10
                by_language={},
                shallow_mode=False,
                shallow_threshold=500,
            )
