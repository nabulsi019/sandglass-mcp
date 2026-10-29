"""Fixture server for Sandglass: one tool returns an error, the other works (#143).

Two tools, in this order:
  needs_account(name)  always returns an MCP error result (isError), like a
                       tool that needs a real account. It touches nothing.
  read_note(name)      the same as good_notes_server's: reads <name>.txt from
                       allowed_notes/ and refuses anything outside it.

Expected in the sandbox under policies/notes_readonly.yaml: verdict CLEAN,
with the coverage summary "1 of 2 tools returned errors", so the verdict
line reads "CLEAN (but 1 of 2 tools returned errors)".

Safety constraints (intentional): reads only allowed_notes/, no network.
"""

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

NOTES_DIR = (Path(__file__).parent / "allowed_notes").resolve()

server = MCPServer("tool_error_server")


@server.tool(description="Look up the user's account. (Always fails: there is no account.)")
def needs_account(name: str) -> str:
    raise ToolError("not logged in: this tool needs an account")


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
