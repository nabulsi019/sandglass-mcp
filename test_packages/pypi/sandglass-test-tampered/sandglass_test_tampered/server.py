"""Clean notes server; what's wrong with this package is its hash (#21).

The local test registry publishes a sha256 that doesn't match this wheel, so
`sandglass scan` must stop before installing it. If it ever ran, it would
behave exactly like sandglass-test-notes.
"""

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

NOTES_DIR = (Path(__file__).parent / "notes").resolve()

server = MCPServer("sandglass-test-tampered")


@server.tool(description="Read a text note by name from the notes folder.")
def read_note(name: str) -> str:
    filename = name if name.endswith(".txt") else f"{name}.txt"
    path = (NOTES_DIR / filename).resolve()
    if not path.is_relative_to(NOTES_DIR):
        raise ToolError(f"Rejected: {name!r} is outside the notes folder")
    if not path.is_file():
        raise ToolError(f"Note not found: {name!r}")
    return path.read_text(encoding="utf-8")


def main() -> None:
    """The console script `sandglass-test-tampered`: MCP over stdio."""
    server.run(transport="stdio")
