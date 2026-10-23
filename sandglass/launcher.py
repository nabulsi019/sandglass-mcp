"""Runs first inside the sandbox, before the server. Not a module you run yourself.

sandbox.py reads this file ON THE HOST and passes its source to the traced
Python as:

    python -S -c <this source> <server.py> <netsink.py source> <stdin_relay.py source>

so the container never has to read an extra file. In this order it:

  1. (#47) points the server's stderr (fd 2, the trace stream) at /dev/null
     (fd 3, opened by sh) and closes fd 3, so the server can't touch the trace;
  2. (#13) starts the local network sink (sandglass/netsink.py) as its own
     process and waits until it listens, then points HTTP(S)_PROXY at it;
  3. (#91) starts the stdin relay (sandglass/stdin_relay.py) as its own
     process and makes its output the server's stdin, so the trace marks
     where the tool calls start;
  4. runs the server: a .py server as __main__ in this same Python, after
     loading site-packages (skipped by -S, because .pth files can run code);
     a .js server by exec'ing Node in this same process (#17), so the fds
     stay closed and compare.py sees one extra exec it treats as the launch.
     If a Python server dies with an exception, its message is put into the
     trace (record_server_error, #24), since its stderr is /dev/null.

Until step 4 only frozen stdlib modules (os, sys, runpy, site) are used, so no
package code runs while the trace stream is still reachable.
"""

import os
import sys

# Must match sandglass/netsink.py (tests/test_network_sink.py checks this).
SINK_URL = "http://127.0.0.1:18080"
SINK_READY_FD = 3
# Must match sandglass/stdin_relay.py (tests/test_phases.py checks this).
RELAY_READY_FD = 3
PYTHON = "/opt/venv/bin/python"
NODE = "/usr/bin/node"  # must match sandglass/sandbox.py CONTAINER_NODE
# (#24) A Python server that dies with an exception: the launcher stat()s
# <this>/<message> (it doesn't exist), so the message lands in the trace.
SERVER_ERROR_DIR = "/sandglass-server-error"
# Characters kept in that message; anything else (including "/") becomes "_".
MESSAGE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:;=_-+'()[]")


def start_sink(source: str) -> None:
    """Start netsink.py as a separate process and wait until it's listening.

    Separate process, not a thread: the server can't patch its memory to stop
    it recording. posix_spawn, not os.fork(): on Python 3.12, os.fork() reads
    /proc/self/stat (thread count), which would show up in every trace.
    """
    ready_r, ready_w = os.pipe()
    os.posix_spawn(PYTHON, [PYTHON, "-I", "-S", "-c", source], {}, file_actions=[
        (os.POSIX_SPAWN_CLOSE, 0),                        # not the MCP stdin...
        (os.POSIX_SPAWN_CLOSE, 1),                        # ...or stdout
        (os.POSIX_SPAWN_DUP2, ready_w, SINK_READY_FD),    # "I'm listening" pipe
    ])
    os.close(ready_w)
    os.read(ready_r, 1)  # b"" if the sink died; compare.py then says it never started
    os.close(ready_r)


def start_relay(source: str) -> None:
    """Start stdin_relay.py as a separate process and make it the server's stdin.

    The relay keeps the client's stdin (fd 0); its stdout (fd 1) becomes a
    pipe, and the read end of that pipe becomes this process's fd 0. os.pipe()
    fds are close-on-exec, so the relay only keeps the ones dup2'd below.
    """
    stdin_r, stdin_w = os.pipe()
    ready_r, ready_w = os.pipe()
    os.posix_spawn(PYTHON, [PYTHON, "-I", "-S", "-c", source], {}, file_actions=[
        (os.POSIX_SPAWN_DUP2, stdin_w, 1),                # relay's output -> server's stdin
        (os.POSIX_SPAWN_DUP2, ready_w, RELAY_READY_FD),   # "I'm running" pipe
    ])
    os.close(stdin_w)
    os.close(ready_w)
    os.read(ready_r, 1)  # b"" if the relay died; compare.py then says it never started
    os.close(ready_r)
    os.dup2(stdin_r, 0)  # the server now reads the client's messages through the relay
    os.close(stdin_r)


def main() -> None:
    # 1. The server must never hold the trace stream.
    os.dup2(3, 2)
    os.close(3)

    # Look like `python <server.py>` would. With -c, sys.path[0] is "" (the
    # cwd); replace it before importing anything non-frozen, or Python lists /project.
    server, sink_source, relay_source = sys.argv[1], sys.argv[2], sys.argv[3]
    sys.argv = [server]
    sys.path[0] = os.path.dirname(server)

    # 2. The network sink.
    start_sink(sink_source)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ[name] = SINK_URL
    for name in ("NO_PROXY", "no_proxy"):
        os.environ.pop(name, None)

    # 3. The stdin relay, which marks the start of the tool calls.
    start_relay(relay_source)

    # 4. The server. Node: replace this process with node (same pid, same fds).
    if server.endswith(".js"):
        os.execv(NODE, [NODE, server])

    # Python: packages, then the server.
    import site
    site.main()
    import runpy
    try:
        runpy.run_path(server, run_name="__main__")
    except SystemExit as exc:
        if exc.code not in (None, 0):
            # e.g. sys.exit("NOTES_API_KEY is not set"): Python would print
            # the message to stderr, which is /dev/null here (#47).
            record_server_error(str(exc.code) if isinstance(exc.code, str) else f"exit code {exc.code}")
        raise
    except BaseException as exc:
        record_server_error(f"{type(exc).__name__}: {exc}")
        raise


def record_server_error(message: str) -> None:
    """Put the server's own error message into the trace (#24).

    The server's stderr is /dev/null (step 1), so its traceback is lost. Like
    the sink and the relay, this stat()s a path that doesn't exist, so the
    message lands in the trace. It runs inside the server's process, so the
    server could fake it: compare.py only uses it as the wording of a reason
    when the run is already INCOMPLETE (the server exited during startup).
    """
    try:
        os.stat(f"{SERVER_ERROR_DIR}/{clean_message(message)}")
    except OSError:
        pass


def clean_message(message: str) -> str:
    """One safe path component: allowed characters only, at most 200 of them."""
    return "".join(c if c in MESSAGE_CHARS else "_" for c in message)[:200] or "_"


if __name__ == "__main__":
    main()
