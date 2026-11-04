"""Fixture server for Sandglass: tools that need a real file or repository (#171).

Three tools, in this order:
  read_document(path)   returns the text of an existing file
  repo_head(repo_path)  returns <repo_path>/.git/HEAD of an existing git repository
  save_copy(path)       reads an existing file and writes it to <path>.copy

With the quick scan's inputs ("hello") all three return errors: there is no
such file. A deep scan passes the sample files (/tmp/work/samples), so all
three work. Expected (EXPECTED_SAMPLE_FILES in scripts/check_fixtures.py):
  quick, no_network.v1         CLEAN, "but 3 of 3 tools returned errors"
  deep, no_network.v1          CLEAN, no coverage summary
  deep, read_only_folder.v1    VIOLATIONS, exactly the write of
                               /tmp/work/samples/notes.txt.copy; the reads of
                               notes.txt and repo/.git/HEAD are "sample files read"

Safety constraints (intentional): reads and writes only the paths it is
given, runs no program, no network.
"""

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

server = MCPServer("sample_reader_server")


@server.tool(description="Read a text document and return its contents.")
def read_document(path: str) -> str:
    if not Path(path).is_file():
        raise ToolError(f"no such file: {path!r}")
    return Path(path).read_text(encoding="utf-8")


@server.tool(description="Show the current HEAD of a git repository.")
def repo_head(repo_path: str) -> str:
    head = Path(repo_path) / ".git" / "HEAD"
    if not head.is_file():
        raise ToolError(f"not a git repository: {repo_path!r}")
    return head.read_text(encoding="utf-8").strip()


@server.tool(description="Save a copy of a text file next to it, as <path>.copy.")
def save_copy(path: str) -> str:
    if not Path(path).is_file():
        raise ToolError(f"no such file: {path!r}")
    copy = Path(f"{path}.copy")
    copy.write_text(Path(path).read_text(encoding="utf-8"), encoding="utf-8")
    return f"saved {copy}"


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
