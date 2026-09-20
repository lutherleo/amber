"""Runnable mock MCP server entrypoint.

Invoked by the pool as ``[sys.executable, "-m", "tests.darnit.sieve.fixtures.mock_mcp_server"]``.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path


def _log_event(kind: str, payload: dict[str, object] | None = None) -> None:
    """Append a single JSON line to the counter file, if configured."""
    path = os.environ.get("DARNIT_MOCK_MCP_COUNTER_FILE")
    if not path:
        return
    record: dict[str, object] = {"kind": kind, "ts": time.time(), "pid": os.getpid()}
    if payload:
        record.update(payload)
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:  # noqa: BLE001 -- counter file MUST NOT crash the mock
        pass


def _make_server():  # -> FastMCP
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.exceptions import ToolError

    srv = FastMCP("darnit-mock-mcp")

    @srv.tool(description="Echo text back to the caller.")
    def echo(text: str) -> dict[str, str]:
        _log_event("tool_call", {"tool": "echo", "args": {"text": text}})
        return {"text": text}

    @srv.tool(description="Return a deterministic score for a repo URL.")
    def get_score(repo_url: str = "") -> dict:
        _log_event("tool_call", {"tool": "get_score", "args": {"repo_url": repo_url}})
        raw = os.environ.get("DARNIT_MOCK_MCP_SCORE", "8.5")
        try:
            score = float(raw)
        except ValueError:
            score = 8.5
        return {"score": score, "repo_url": repo_url}

    @srv.tool(description="Deliberately return an isError=True MCP response.")
    def raise_error(reason: str = "test") -> dict[str, str]:
        _log_event("tool_call", {"tool": "raise_error", "args": {"reason": reason}})
        raise ToolError(f"raise_error: reason {reason!r}")

    @srv.tool(description="Sleep forever; used to exercise per-call timeout.")
    async def sleep_forever() -> dict[str, str]:
        _log_event("tool_call", {"tool": "sleep_forever"})
        await asyncio.Event().wait()
        return {"unreachable": "true"}

    return srv


def main() -> None:
    _log_event("spawn")
    try:
        srv = _make_server()
        asyncio.run(srv.run_stdio_async())
    finally:
        _log_event("teardown")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
