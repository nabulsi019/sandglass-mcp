"""Servers that exit during startup (#24): INCOMPLETE, with the reason.

Hand-written traces (no Docker), plus one real run of the stdin relay to show
it stops waiting once the server process is gone.
"""

import os
import subprocess
import sys
import time

from sandglass import launcher, sandbox, stdin_relay
from sandglass.compare import compare
from sandglass.trace_parser import parse_trace
from tests.test_sandbox_pipeline import LAUNCH, RELAY_START, SINK_LINES, run, sandbox_policy

# The server (pid 8) dies at startup; the relay (pid 7) notices and ends.
SERVER_ERROR = ('8  10:00:00.300000 newfstatat(AT_FDCWD, "/sandglass-server-error/RuntimeError: NOTES_API_KEY'
                ' is not set", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)')
SERVER_EXIT_1 = "8  10:00:00.300100 +++ exited with 1 +++"
RELAY_SAW_SERVER_GO = [
    '7  10:00:00.800000 newfstatat(AT_FDCWD, "/sandglass-phase/server-exited", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)',
    "7  10:00:00.800100 +++ exited with 0 +++",
]
FAILED_SESSION = {"tools": [], "calls": [], "error": "McpError: Connection closed"}


def startup_crash(lines_after_launch, session=FAILED_SESSION):
    """A trace where the server crashes before any tool call (no eof marker)."""
    lines = [LAUNCH] + SINK_LINES + RELAY_START + lines_after_launch
    return compare(parse_trace("\n".join(lines)), sandbox_policy(), session)


def startup_reasons(result):
    return [r for r in result["incomplete_reasons"] if "exited during startup" in r]


def test_server_exiting_at_startup_is_incomplete_with_its_error_message():
    result = startup_crash([SERVER_ERROR, SERVER_EXIT_1] + RELAY_SAW_SERVER_GO)
    assert result["verdict"] == "INCOMPLETE"
    assert startup_reasons(result) == [
        "the server exited during startup (exited with 1) before any tool call; its error "
        "message (as the server reported it): RuntimeError: NOTES_API_KEY is not set"]
    # The relay's server-exited marker is a normal end, not tampering...
    assert not any("stdin relay" in r for r in result["incomplete_reasons"])
    # ...and neither marker shows up as a probe or a violation.
    assert result["probes"] == [] and result["violations"] == []


def test_without_a_message_the_exit_status_is_still_the_reason():
    # e.g. a Node.js server: the launcher has exec'd node, so no message.
    result = startup_crash([SERVER_EXIT_1] + RELAY_SAW_SERVER_GO)
    assert startup_reasons(result) == [
        "the server exited during startup (exited with 1) before any tool call"]


def test_a_normal_shutdown_is_not_a_startup_exit():
    # The client hung up first (eof marker before the server's exit): a server
    # with no tools, say. Still INCOMPLETE (nothing exercised), but not this reason.
    session = {"tools": [], "calls": []}
    eof = ['7  10:00:00.800000 newfstatat(AT_FDCWD, "/sandglass-phase/eof", 0x7f, 0) = -1 ENOENT (No such file or directory)',
           "7  10:00:00.800100 +++ exited with 0 +++",
           "8  10:00:00.900000 +++ exited with 0 +++"]
    result = startup_crash(eof, session=session)
    assert result["verdict"] == "INCOMPLETE"
    assert startup_reasons(result) == []


def test_runs_that_called_tools_never_get_the_reason():
    # Tools ran (the default session in run()): a later crash isn't a startup failure.
    result = run([LAUNCH, SERVER_ERROR, "8  10:00:01.000000 +++ exited with 1 +++"])
    assert startup_reasons(result) == []


def test_an_error_marker_from_another_process_is_just_a_probe():
    forged = SERVER_ERROR.replace("8  ", "11 ", 1)
    result = startup_crash([forged, SERVER_EXIT_1] + RELAY_SAW_SERVER_GO)
    assert startup_reasons(result) == [
        "the server exited during startup (exited with 1) before any tool call"]
    assert [p["path"] for p in result["probes"]] == [
        "/sandglass-server-error/RuntimeError: NOTES_API_KEY is not set"]


def test_launcher_message_is_one_safe_path_component():
    assert launcher.clean_message("RuntimeError: key /etc/x is \x00 missing") == \
        "RuntimeError: key _etc_x is _ missing"
    assert len(launcher.clean_message("x" * 1000)) == 200
    assert launcher.clean_message("") == "_"


def test_launcher_records_the_error_around_the_server_only():
    # The try/except wraps the server's run, after the fd swap (#47).
    source = sandbox.LAUNCHER  # the exact text the sandbox runs
    main = source[source.index("def main()"):source.index("def record_server_error")]
    assert main.index("os.dup2(3, 2)") < main.index("try:") < main.index("runpy.run_path(")


def test_relay_exits_once_the_server_is_gone():
    # A stand-in "server" starts the real relay (like the launcher does) and
    # exits at once. The client side (our pipe) stays open, so the old relay
    # would wait forever; now it notices its parent is gone and ends.
    starter = (
        "import os, sys\n"
        "ready_r, ready_w = os.pipe()\n"
        "null = os.open(os.devnull, os.O_WRONLY)\n"
        "pid = os.posix_spawn(sys.executable, [sys.executable, '-I', '-S', '-c', sys.argv[1]], {},\n"
        f"    file_actions=[(os.POSIX_SPAWN_DUP2, ready_w, {stdin_relay.READY_FD}),\n"
        "                  (os.POSIX_SPAWN_DUP2, null, 1), (os.POSIX_SPAWN_DUP2, null, 2)])\n"
        "os.read(ready_r, 1)\n"
        "print(pid)\n"
    )
    client_r, client_w = os.pipe()  # never closed until the end: the client is still there
    source = open(stdin_relay.__file__, encoding="utf-8").read()
    out = subprocess.run([sys.executable, "-c", starter, source], stdin=client_r,
                         capture_output=True, text=True, timeout=30, check=True)
    relay_pid = int(out.stdout)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and _running(relay_pid):
            time.sleep(0.1)
        assert not _running(relay_pid), "the relay kept waiting after the server exited"
    finally:
        os.close(client_r)
        os.close(client_w)


def _running(pid: int) -> bool:
    """Is the process still running? Works on Linux and macOS."""
    try:
        os.kill(pid, 0)  # signal 0: only checks that the pid exists
    except ProcessLookupError:
        return False
    # On Linux, an exited process can linger as a zombie until it's reaped.
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return not os.path.exists("/proc/self/stat")  # no /proc (macOS): kill() said it exists
