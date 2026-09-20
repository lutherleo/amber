"""In-repo mock MCP server used by the mcp-handler integration tests.

Exposes four deterministic tools:

* ``echo(text)`` -- returns ``{"text": text}``
* ``get_score(repo_url)`` -- returns ``{"score": float}`` where the score
  is parameterisable via env ``DARNIT_MOCK_MCP_SCORE`` (default ``8.5``)
* ``raise_error(reason)`` -- raises ``ToolError`` so the MCP layer sends
  the response with ``isError=True``
* ``sleep_forever()`` -- suspends indefinitely (used to exercise the
  handler's per-call timeout)

The server appends a single JSON line to the file named by env
``DARNIT_MOCK_MCP_COUNTER_FILE`` on every lifecycle event (``spawn``,
``teardown``, ``tool_call``). Tests inspect that file to make mechanical
assertions about the pool's spawn/teardown semantics (spec SC-002).
"""

from __future__ import annotations

__all__ = ["main"]


def main() -> None:
    from .__main__ import main as _run

    _run()
