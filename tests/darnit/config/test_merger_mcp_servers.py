"""Merger precedence coverage for the ``mcp_servers`` block (spec FR-016)."""

from __future__ import annotations

from darnit.config.framework_schema import (
    FrameworkConfig,
    FrameworkMetadata,
    McpServerConfig,
)
from darnit.config.merger import merge_configs
from darnit.config.user_schema import UserConfig


def _framework(**servers: McpServerConfig) -> FrameworkConfig:
    return FrameworkConfig(
        metadata=FrameworkMetadata(
            name="test",
            display_name="Test",
            version="0.0.1",
            spec_version="v0",
        ),
        mcp_servers=dict(servers),
    )


# ---------------------------------------------------------------------------
# T026: baseline replaces per-name (no deep merge)
# ---------------------------------------------------------------------------


def test_mcp_servers_baseline_wins():
    fw = _framework(foo=McpServerConfig(command=["fw-cmd"]))
    user = UserConfig(mcp_servers={"foo": McpServerConfig(command=["bl-cmd"])})
    eff = merge_configs(fw, user)
    assert eff.mcp_servers["foo"].command == ["bl-cmd"]


# ---------------------------------------------------------------------------
# T027: disjoint names coexist
# ---------------------------------------------------------------------------


def test_mcp_servers_disjoint_names_coexist():
    fw = _framework(a=McpServerConfig(command=["fw-a"]))
    user = UserConfig(mcp_servers={"b": McpServerConfig(command=["bl-b"])})
    eff = merge_configs(fw, user)
    assert set(eff.mcp_servers) == {"a", "b"}
    assert eff.mcp_servers["a"].command == ["fw-a"]
    assert eff.mcp_servers["b"].command == ["bl-b"]
