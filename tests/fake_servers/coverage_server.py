"""A tiny MCP server for tests/test_coverage.py (#23), run on the host, never sandboxed.

One tool for each coverage outcome: one that works, one that returns an MCP
error, one whose input schema we can't satisfy (a string pattern), and one
slower than the test's per-call timeout. It touches no files and no network.
"""

import time
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

server = MCPServer("coverage_server")


@server.tool(description="Always works.")
def ok_tool(name: str) -> str:
    return f"hi {name}"


@server.tool(description="Always returns an MCP error, like a tool that needs a real account.")
def error_tool(name: str) -> str:
    raise ToolError("not logged in: this tool needs an account")


@server.tool(description="Needs a three-letter code; Sandglass can't build one from a pattern.")
def pattern_tool(code: Annotated[str, Field(pattern="^[A-Z]{3}$")]) -> str:
    return code


@server.tool(description="Takes 3 seconds, longer than the test's 1 s call timeout.")
def slow_tool(name: str) -> str:
    time.sleep(3)
    return "done"


if __name__ == "__main__":
    server.run(transport="stdio")
