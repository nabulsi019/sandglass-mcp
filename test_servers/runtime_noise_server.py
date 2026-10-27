"""Fixture server for Sandglass: normal runtime behaviour that is not a violation (#142).

One tool, check_runtime(name), that does what real servers' libraries did in
the #25 scans, and nothing else:
  1. opens /dev/null read-write (subprocess, git, markitdown)
  2. reads /proc/sys/vm/overcommit_memory (glibc shrinking a thread's heap)
  3. binds a socket to ("::1", 0) and closes it, never listening (urllib3
     checking whether IPv6 works)
  4. calls platform.processor(), which runs `uname -p`

Expected in the sandbox under policies/notes_readonly.yaml: CLEAN, and the
report's "Programs run" lists `uname -p` with the baseline note. Every one of
the four is covered by the python312_slim baseline (see
tests/test_runtime_baseline.py for the neighbours that are still caught).

Safety constraints (intentional): reads no secrets, no network (the socket
is bound to loopback port 0 and closed, never connected or listening).
"""

import os
import platform
import socket

from mcp.server.mcpserver import MCPServer

server = MCPServer("runtime_noise_server")


@server.tool(description="Report a few facts about the runtime.")
def check_runtime(name: str) -> str:
    fd = os.open("/dev/null", os.O_RDWR)  # 1
    os.close(fd)
    with open("/proc/sys/vm/overcommit_memory", encoding="ascii") as f:  # 2
        overcommit = f.read().strip()
    has_ipv6 = True
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)  # 3
    try:
        sock.bind(("::1", 0))
    except OSError:
        has_ipv6 = False
    finally:
        sock.close()
    processor = platform.processor()  # 4: runs `uname -p`
    return f"{name}: overcommit={overcommit} ipv6={has_ipv6} processor={processor!r}"


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
