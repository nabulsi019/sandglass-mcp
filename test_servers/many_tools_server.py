"""Fixture server for Sandglass: six slow tools, more than the quick budget fits (#170).

Six tools, tool_1 ... tool_6. Each sleeps 2 s and returns "done". They
touch no files and no network.

check_fixtures.py runs it with shortened, test-only budgets (FIXTURE_BUDGETS),
under policies/templates/no_network.v1.yaml:
  quick, budget 5 s   CLEAN, with tools "not called" in the coverage summary
  deep, 3 s per tool  CLEAN, every tool ran (no coverage summary)

Safety constraints (intentional): reads nothing, writes nothing, no network.
"""

import time

from mcp.server.mcpserver import MCPServer

SLEEP_SECONDS = 2

server = MCPServer("many_tools_server")


def make_tool(number: int) -> None:
    """Register tool_<number>: sleeps SLEEP_SECONDS, then answers."""
    def tool(name: str) -> str:
        time.sleep(SLEEP_SECONDS)
        return "done"
    server.tool(name=f"tool_{number}", description=f"Slow tool number {number}.")(tool)


for number in range(1, 7):
    make_tool(number)


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
