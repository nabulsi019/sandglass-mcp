"""Fixture server for Sandglass: reports the environment it sees (#146).

One tool, report_environment(), returns JSON with two views of the
environment, names and values:
  "environ"       os.environ: what Python code reads
  "proc_environ"  /proc/self/environ: the environment this process started
                  with, which deleting a variable from os.environ doesn't change

Expected in the sandbox under policies/templates/no_network.v1.yaml: CLEAN,
no "SANDGLASS" in any name or value, "sandglass" in any case only in HOME's
value (the decoy home), and exactly the names in check_fixtures.py's
EXPECTED_ENVIRONMENT.

Safety: reads only its own /proc entry; no network, no writes.
"""

import json
import os

from mcp.server.mcpserver import MCPServer

server = MCPServer("env_report_server")


def proc_environ() -> dict:
    """/proc/self/environ as a dict: NAME=value entries, NUL-separated."""
    with open("/proc/self/environ", "rb") as f:
        entries = f.read().decode("utf-8", "replace").split("\0")
    return dict(entry.partition("=")[::2] for entry in entries if entry)


@server.tool(description="Show the environment variables this server can see.")
def report_environment() -> str:
    return json.dumps({"environ": dict(os.environ), "proc_environ": proc_environ()})


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
