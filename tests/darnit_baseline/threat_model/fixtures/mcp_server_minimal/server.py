"""Minimal FastMCP fixture used by discovery tests.

Expected discovery:
- Two MCP_TOOL entry points with framework="mcp"
- greet and echo are registered via @server.tool() decorators
"""

from mcp.server.fastmcp import FastMCP

server = FastMCP("example")


@server.tool()
def greet(name: str) -> str:
    return f"hello {name}"


@server.tool()
def echo(text: str) -> str:
    return text
