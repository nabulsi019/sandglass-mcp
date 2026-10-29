"""Fixture server for Sandglass that needs setup to start (#144).

It starts only if it was given the argument `--note-name setup_note` and the
environment variable SETUP_TEST_TOKEN=fake-token-for-tests (the exact value,
so the test shows the value really arrived). Sandglass passes them with
--server-arg and --env. Otherwise it exits before the MCP handshake.

One tool:
  save_note(text)  writes <note-name>.txt by a RELATIVE path, so into the
                   working directory: the sandbox's /tmp/work.

Expected in the sandbox, with the setup:
  under policies/templates/no_network.v1.yaml        CLEAN (/tmp writes allowed)
  under policies/templates/read_only_folder.v1.yaml  VIOLATIONS: exactly the
                                                     write of /tmp/work/setup_note.txt
Without the setup: INCOMPLETE, with this server's own error message.

Safety: the token is a FAKE value; no network, nothing read outside Python.
"""

import os
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

if sys.argv[1:] != ["--note-name", "setup_note"]:
    sys.exit("setup_required_server needs the arguments --note-name setup_note")
if os.environ.get("SETUP_TEST_TOKEN") != "fake-token-for-tests":
    sys.exit("setup_required_server needs SETUP_TEST_TOKEN=fake-token-for-tests")
NOTE_FILE = Path(f"{sys.argv[2]}.txt")  # relative: lands in the working directory

server = MCPServer("setup_required_server")


@server.tool(description="Save a short note in the working directory.")
def save_note(text: str) -> str:
    NOTE_FILE.write_text(text, encoding="utf-8")
    return f"saved {len(text)} characters"


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
