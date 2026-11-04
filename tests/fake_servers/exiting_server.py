"""A tiny MCP server for tests/test_observation.py (#175), run on the host, never sandboxed.

One tool, finish(), with no arguments: it answers, then the process exits
half a second later, so a deep scan's observation window must end early.
It touches no files and no network.
"""

import os
import threading
import time

from mcp.server.mcpserver import MCPServer

server = MCPServer("exiting_server")


def _exit_soon() -> None:
    time.sleep(0.5)
    os._exit(0)


@server.tool(description="Answer, then exit half a second later.")
def finish() -> str:
    threading.Thread(target=_exit_soon, daemon=True).start()
    return "bye"


if __name__ == "__main__":
    server.run(transport="stdio")
