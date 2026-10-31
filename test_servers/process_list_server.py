"""Fixture server for Sandglass: lists the command line of every process it can see (#159).

One tool, list_processes(), returns JSON: {pid: argv} for every process in
/proc whose cmdline it can read (the same uid's, and others' if readable).
Before #159 the launcher's, the sink's and the relay's command lines held
Sandglass's source; now they name neutral files in the image.

Expected in the sandbox under policies/templates/no_network.v1.yaml (reads
anywhere but /home and /root): CLEAN, at least 3 processes (the launcher,
which is this process, the sink and the relay), and no "sandglass" in any
case in any argv (check_fixtures.py's EXPECTED_PROCESS_FINGERPRINTS).

Safety: only reads /proc; no network, no writes.
"""

import json
import os

from mcp.server.mcpserver import MCPServer

server = MCPServer("process_list_server")


def cmdline(pid: str) -> list[str] | None:
    """/proc/<pid>/cmdline as a list (NUL-separated), or None if unreadable or gone."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().decode("utf-8", "replace").split("\0")[:-1]
    except OSError:
        return None


@server.tool(description="Show the command line of every process this server can see.")
def list_processes() -> str:
    processes = {pid: cmdline(pid) for pid in sorted(os.listdir("/proc"), key=str) if pid.isdigit()}
    return json.dumps({pid: argv for pid, argv in processes.items() if argv is not None})


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
