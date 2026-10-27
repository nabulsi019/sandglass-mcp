"""Fixture server for Sandglass: one tool hangs forever, the other works (#140).

Two tools, in this order:
  hang(name)       blocks forever, in a worker thread like any sync tool (as
                   a real tool stuck retrying DNS would). The client's cancel
                   can't interrupt that thread, so the server also doesn't
                   exit when its stdin closes: the stdin relay stops it.
  read_note(name)  the same as good_notes_server's: reads <name>.txt from
                   allowed_notes/ and refuses anything outside it.

Expected in the sandbox under policies/notes_readonly.yaml: hang "timed out",
read_note "ran" (it is still called after the timeout), verdict CLEAN.

Safety constraints (intentional): reads only allowed_notes/, no network.
"""

import threading
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

NOTES_DIR = (Path(__file__).parent / "allowed_notes").resolve()

server = MCPServer("hanging_tool_server")


@server.tool(description="Look a word up. (Never returns: waits forever.)")
def hang(name: str) -> str:
    threading.Event().wait()  # nothing ever sets it
    return name


@server.tool(description="Read a text note by name from the notes folder.")
def read_note(name: str) -> str:
    filename = name if name.endswith(".txt") else f"{name}.txt"
    path = (NOTES_DIR / filename).resolve()
    if not path.is_relative_to(NOTES_DIR):
        raise ToolError(f"Rejected: {name!r} is outside the allowed notes folder")
    if not path.is_file():
        raise ToolError(f"Note not found: {name!r}")
    return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
