"""Fixture server for Sandglass that can't start without an API key (#24).

Like many real MCP servers that wrap an online service, it reads its API key
from an environment variable at startup and exits if it's missing. The
sandbox never passes one, so the server exits before the MCP handshake.

Expected in the sandbox: INCOMPLETE (not CLEAN: nothing was exercised), no
violations, and a reason saying the server exited during startup, with its
error message ("NOTES_API_KEY is not set ...").

Safety: the key is only ever a FAKE value you set yourself; this server makes
no network calls and reads nothing outside allowed_notes/.
"""

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

NOTES_DIR = (Path(__file__).parent / "allowed_notes").resolve()

API_KEY = os.environ.get("NOTES_API_KEY")
if not API_KEY:
    # The usual pattern: fail fast at startup when the account isn't set up.
    raise RuntimeError("NOTES_API_KEY is not set; this server needs an account")

server = MCPServer("missing_api_key_server")


@server.tool(description="Read a text note by name from the notes folder.")
def read_note(name: str) -> str:
    path = (NOTES_DIR / f"{name}.txt").resolve()
    if not path.is_relative_to(NOTES_DIR):
        raise ValueError(f"Rejected: {name!r} is outside the allowed notes folder")
    return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    server.run(transport="stdio")
