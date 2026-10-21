"""Runs first inside the sandbox, before the server. Not a module you run yourself.

sandbox.py reads this file ON THE HOST and passes its source to the traced
Python as:

    python -S -c <this source> <server.py> <netsink.py source>

so the container never has to read an extra file. In this order it:

  1. (#47) points the server's stderr (fd 2, the trace stream) at /dev/null
     (fd 3, opened by sh) and closes fd 3, so the server can't touch the trace;
  2. (#13) starts the local network sink (sandglass/netsink.py) as its own
     process and waits until it listens, then points HTTP(S)_PROXY at it;
  3. runs the server: a .py server as __main__ in this same Python, after
     loading site-packages (skipped by -S, because .pth files can run code);
     a .js server by exec'ing Node in this same process (#17), so the fds
     stay closed and compare.py sees one extra exec it treats as the launch.

Until step 3 only frozen stdlib modules (os, sys, runpy, site) are used, so no
package code runs while the trace stream is still reachable.
"""

import os
import sys

# Must match sandglass/netsink.py (tests/test_network_sink.py checks this).
SINK_URL = "http://127.0.0.1:18080"
SINK_READY_FD = 3
PYTHON = "/opt/venv/bin/python"
NODE = "/usr/bin/node"  # must match sandglass/sandbox.py CONTAINER_NODE


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


def main() -> None:
    # 1. The server must never hold the trace stream.
    os.dup2(3, 2)
    os.close(3)

    # Look like `python <server.py>` would. With -c, sys.path[0] is "" (the
    # cwd); replace it before importing anything non-frozen, or Python lists /project.
    server, sink_source = sys.argv[1], sys.argv[2]
    sys.argv = [server]
    sys.path[0] = os.path.dirname(server)

    # 2. The network sink.
    start_sink(sink_source)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ[name] = SINK_URL
    for name in ("NO_PROXY", "no_proxy"):
        os.environ.pop(name, None)

    # 3. The server. Node: replace this process with node (same pid, same fds).
    if server.endswith(".js"):
        os.execv(NODE, [NODE, server])

    # Python: packages, then the server.
    import site
    site.main()
    import runpy
    runpy.run_path(server, run_name="__main__")


if __name__ == "__main__":
    main()
