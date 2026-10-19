"""Well-behaved fixture server for Sandglass.

Exposes one tool, read_note(name), which reads <name>.txt from the
allowed_notes/ folder next to this file and refuses anything outside it.
This is the "control" server: it should never violate notes_readonly.yaml.
"""

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

# Anchor everything to this file's location, not the current working
# directory, so the server behaves the same no matter where it is launched.
NOTES_DIR = (Path(__file__).parent / "allowed_notes").resolve()

server = MCPServer("good_notes_server")


def resolve_note_path(name: str) -> Path:
    """Turn a note name into a safe path inside NOTES_DIR, or raise ToolError."""
    # Accept "hello" or "hello.txt".
    filename = name if name.endswith(".txt") else f"{name}.txt"

    # resolve() collapses "..", follows symlinks, and makes the path absolute.
    # If `name` was absolute, the join below discards NOTES_DIR entirely,
    # which the containment check then catches.
    path = (NOTES_DIR / filename).resolve()

    # The core security check: the final path must still live inside NOTES_DIR.
    if not path.is_relative_to(NOTES_DIR):
        raise ToolError(f"Rejected: {name!r} is outside the allowed notes folder")
    if not path.is_file():
        raise ToolError(f"Note not found: {name!r}")
    return path


@server.tool(description="Read a text note by name from the notes folder.")
def read_note(name: str) -> str:
    return resolve_note_path(name).read_text(encoding="utf-8")


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
