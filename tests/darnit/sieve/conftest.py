"""Shared fixtures for sieve tests.

The mcp-handler integration tests spawn an in-repo mock MCP server via the
Python interpreter running the test. Fixtures here isolate each test's
counter file so mock lifecycle events do not collide across tests.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


@pytest.fixture()
def mock_mcp_server_command() -> list[str]:
    """Return the command to launch the mock MCP server as a stdio subprocess.

    Used as the ``command`` field on a ``[mcp_servers.mock]`` block in test
    framework configs.
    """
    return [sys.executable, "-m", "tests.darnit.sieve.fixtures.mock_mcp_server"]


@pytest.fixture()
def mcp_counter_file(tmp_path: Path) -> Path:
    """Return a fresh counter-file path unique to this test."""
    return tmp_path / "mcp_counter.jsonl"
