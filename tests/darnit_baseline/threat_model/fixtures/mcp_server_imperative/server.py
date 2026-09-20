"""Minimal imperative MCP fixture.

Expected discovery:
- Two MCP_TOOL entry points with framework="mcp"
- greet_handler and echo_handler registered via server.add_tool()
"""

from mcp.server.fastmcp import FastMCP

server = FastMCP("example")


def greet_handler(name: str) -> str:
    return f"hello {name}"


def echo_handler(text: str) -> str:
    return text


server.add_tool(greet_handler, name="greet", description="Greet someone")
server.add_tool(echo_handler, name="echo", description="Echo text")
