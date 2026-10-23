"""The stdin relay: marks in the trace where the tool calls start (#91).

Started by the launcher inside the sandbox, as its own process:
`python -I -S -c <this source>`, like the network sink (sandglass/netsink.py).

It sits between the client and the server: it reads the client's MCP messages
from its stdin (fd 0) and copies every byte, unchanged, to its stdout (fd 1),
a pipe that is the server's stdin. Just BEFORE it passes on the first
"tools/call" request, it stat()s a path that doesn't exist. strace logs that
call, so the trace itself shows where the tool calls begin, and compare.py
splits the phases there, by position in the trace, without using any clock.

Markers (stat()s of paths under /sandglass-phase, which doesn't exist):
  ready      once at startup, before the server's own code runs
  tool-call  just before the first tools/call request is passed on
  eof        when the client closed stdin, just before the relay exits
  server-exited  when the server process is gone while the client is still
             connected (#24), e.g. it crashed at startup; the relay then
             exits too, so strace and the container end at once instead of
             waiting for the client's timeout

Imported on the host too (compare.py uses the constants), so the actual work
only happens under `if __name__ == "__main__"`.
"""

import json
import os

PHASE_MARKER_DIR = "/sandglass-phase"
RELAY_READY = f"{PHASE_MARKER_DIR}/ready"
TOOL_CALL_MARKER = f"{PHASE_MARKER_DIR}/tool-call"
EOF_MARKER = f"{PHASE_MARKER_DIR}/eof"
SERVER_EXITED_MARKER = f"{PHASE_MARKER_DIR}/server-exited"
# How often (seconds) the relay checks that the server is still running while
# it waits for the client's next message.
PARENT_CHECK_SECONDS = 0.5
# The launcher hands the relay this fd; the relay writes one byte when ready.
READY_FD = 3


def is_tool_call(line: bytes) -> bool:
    """Is this one MCP stdio message (one line of JSON) a tools/call request?"""
    try:
        message = json.loads(line)
    except ValueError:
        return False  # not JSON (or a partial line): never a marker
    return isinstance(message, dict) and message.get("method") == "tools/call"


def _record(path: str) -> None:
    """Leave an event in the trace: stat() a path that doesn't exist."""
    try:
        os.stat(path)
    except OSError:
        pass


def _write_all(fd: int, data: bytes) -> None:
    while data:
        data = data[os.write(fd, data):]


def relay() -> None:
    """Copy stdin to stdout until EOF, marking the first tools/call."""
    import select  # only here: the host imports this module for its constants

    _record(RELAY_READY)
    os.write(READY_FD, b"1")  # tell the launcher the relay is running
    os.close(READY_FD)

    # The launcher, which becomes the server, is the relay's parent. If it
    # exits (e.g. crashes at startup), the relay is re-parented, so
    # getppid() changes. Without this check the relay would keep waiting for
    # the client, strace would wait for the relay, and the client would only
    # notice at its session timeout (#24).
    parent = os.getppid()
    seen_tool_call = False
    partial = b""  # the start of a line whose newline hasn't arrived yet
    while True:
        ready, _, _ = select.select([0], [], [], PARENT_CHECK_SECONDS)
        if not ready:
            if os.getppid() != parent:
                _record(SERVER_EXITED_MARKER)  # a normal end, too: nothing left to relay to
                return
            continue
        chunk = os.read(0, 65536)
        if not chunk:
            break
        if not seen_tool_call:
            # MCP stdio messages are one JSON object per line. Only complete
            # lines are checked; the server can't act on a line before its
            # newline arrives, and that newline is passed on after the marker.
            *lines, partial = (partial + chunk).split(b"\n")
            if any(is_tool_call(line) for line in lines):
                _record(TOOL_CALL_MARKER)
                seen_tool_call = True
        _write_all(1, chunk)

    _record(EOF_MARKER)  # a normal end: the client closed stdin


if __name__ == "__main__":
    relay()
