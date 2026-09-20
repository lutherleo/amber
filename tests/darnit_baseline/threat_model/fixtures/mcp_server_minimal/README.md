# Fixture: mcp_server_minimal

Minimal FastMCP server exposing two tools via `@server.tool(...)` decorators.
Used by discovery tests to verify MCP tool handlers are detected as
`EntryPoint(kind=MCP_TOOL, framework="mcp")`. This is the attack surface the
old regex pipeline missed entirely.
