"""Fixture server for Sandglass that needs a program the sandbox doesn't have (#148).

Like mcp-server-git (which needs `git`), it runs a program at startup and
exits if it isn't installed. Python's subprocess looks for the program in
every PATH folder with execve, so the trace shows a PATH search that never
finds it, then the server's exit.

Expected in the sandbox (notes_readonly): INCOMPLETE, no violations (the
failed execs are only "attempted"), and the reasons include "the server needs
a program the sandbox doesn't have: sandglass-missing-program".

Safety: runs nothing that exists, reads nothing outside allowed_notes/.
"""

import subprocess
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

NOTES_DIR = (Path(__file__).parent / "allowed_notes").resolve()

try:
    # A name no image will ever have: the search fails in every PATH folder.
    subprocess.run(["sandglass-missing-program", "--version"], capture_output=True)
except FileNotFoundError:
    sys.exit("sandglass-missing-program is not installed; this server needs it")

server = MCPServer("missing_program_server")


@server.tool(description="Read a text note by name from the notes folder.")
def read_note(name: str) -> str:
    path = (NOTES_DIR / f"{name}.txt").resolve()
    if not path.is_relative_to(NOTES_DIR):
        raise ValueError(f"Rejected: {name!r} is outside the allowed notes folder")
    return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    server.run(transport="stdio")
