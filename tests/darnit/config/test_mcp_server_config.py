"""Framework/User schema coverage for the ``mcp_servers`` block.

Locks the operator-facing shape of ``[mcp_servers.<name>]`` at schema load
time. Merger-precedence tests live in ``test_merger.py``.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from darnit.config.framework_schema import (
    FrameworkConfig,
    FrameworkMetadata,
    McpServerConfig,
)

# ---------------------------------------------------------------------------
# T023: full-block parse
# ---------------------------------------------------------------------------


def test_mcp_servers_block_parses():
    config = McpServerConfig(
        command=["scorecard-mcp", "--stdio"],
        env={"GITHUB_TOKEN": "$GITHUB_TOKEN"},
        trusted_publisher="https://github.com/uwu-tools/scorecard-mcp",
        optional=False,
        install_hint="brew install scorecard-mcp",
    )
    assert config.command == ["scorecard-mcp", "--stdio"]
    assert config.env == {"GITHUB_TOKEN": "$GITHUB_TOKEN"}
    assert config.trusted_publisher == "https://github.com/uwu-tools/scorecard-mcp"
    assert config.optional is False
    assert config.install_hint == "brew install scorecard-mcp"


def test_framework_config_carries_mcp_servers_block():
    fw = FrameworkConfig(
        metadata=FrameworkMetadata(
            name="test",
            display_name="Test",
            version="0.0.1",
            spec_version="v0",
        ),
        mcp_servers={
            "scorecard": McpServerConfig(command=["scorecard-mcp"]),
        },
    )
    assert "scorecard" in fw.mcp_servers
    assert fw.mcp_servers["scorecard"].command == ["scorecard-mcp"]


# ---------------------------------------------------------------------------
# T024: missing `command` field is a validation error
# ---------------------------------------------------------------------------


def test_mcp_servers_command_required():
    with pytest.raises(ValidationError) as exc:
        McpServerConfig(env={"X": "1"})
    assert "command" in str(exc.value)


# ---------------------------------------------------------------------------
# T025: empty `command` list is a validation error
# ---------------------------------------------------------------------------


def test_mcp_servers_command_nonempty():
    with pytest.raises(ValidationError) as exc:
        McpServerConfig(command=[])
    # Message should note the empty/too-short list.
    msg = str(exc.value).lower()
    assert "at least 1" in msg or "empty" in msg or "too_short" in msg


# ---------------------------------------------------------------------------
# T031a: unknown field on `McpServerConfig` -> ValidationError (FR-015 lock)
# ---------------------------------------------------------------------------


def test_mcp_servers_rejects_unknown_field():
    with pytest.raises(ValidationError) as exc:
        McpServerConfig(command=["x"], transport="http")  # type: ignore[call-arg]
    assert "transport" in str(exc.value)
