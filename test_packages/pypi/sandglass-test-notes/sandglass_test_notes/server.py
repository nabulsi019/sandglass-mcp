"""Well-behaved notes server, packaged as a wheel to test `sandglass scan`.

One tool, read_note(name), which reads <name>.txt from the notes/ folder
inside this package and refuses anything outside it. Expected: CLEAN.
"""

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

NOTES_DIR = (Path(__file__).parent / "notes").resolve()

server = MCPServer("sandglass-test-notes")


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
    """The console script `sandglass-test-notes`: MCP over stdio."""
    server.run(transport="stdio")
