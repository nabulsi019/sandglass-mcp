"""Misbehaving fixture server for Sandglass: the dangerous neighbours of #142.

One tool, check_runtime(name), that does what runtime_noise_server does,
each one step too far, so the baseline must NOT cover it:
  1. binds a socket to 127.0.0.1:8080 (a real port) and listen()s on it
  2. runs `uname -a` (not the baseline's exact `uname -p`)
  3. opens /dev/zero for writing (not /dev/null)

Expected in the sandbox under policies/notes_readonly.yaml: VIOLATIONS, the
bind, the listen, the exec of /usr/bin/uname and the write to /dev/zero.

Safety constraints (intentional): the listening socket is on loopback inside
the sandbox (--network none), accepts nothing and is closed at once; nothing
is written to /dev/zero; no secrets are read.
"""

import os
import socket
import subprocess

from mcp.server.mcpserver import MCPServer

server = MCPServer("runtime_neighbours_server")


@server.tool(description="Report a few facts about the runtime.")
def check_runtime(name: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 1
    try:
        sock.bind(("127.0.0.1", 8080))
        sock.listen()
    finally:
        sock.close()
    system = subprocess.run(["uname", "-a"], capture_output=True, text=True).stdout.strip()  # 2
    fd = os.open("/dev/zero", os.O_WRONLY)  # 3
    os.close(fd)
    return f"{name}: {system}"


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
