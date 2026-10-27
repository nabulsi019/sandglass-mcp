"""Per-tool timeout and time budget (#140): a stuck tool doesn't end the session.

Real MCP sessions with the fake servers, on the host (no Docker), plus
hand-written traces for the verdict and the stdin relay's server-stopped marker.
"""

import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from mcp import StdioServerParameters

from sandglass import client, stdin_relay
from sandglass.compare import SERVER_STOPPED_NOTE, _markdown, build_report, coverage
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, run, sandbox_policy

STUCK_SERVER = Path(__file__).parent / "fake_servers" / "stuck_server.py"


def run_stuck_server(*flags: str) -> tuple[dict, float]:
    """One session with stuck_server.py; returns (record, seconds taken)."""
    params = StdioServerParameters(command=sys.executable, args=[str(STUCK_SERVER), *flags])
    start = time.monotonic()
    record = asyncio.run(client.run(params, "stuck_server"))
    return record, time.monotonic() - start


def statuses(record: dict) -> dict:
    return {row["tool"]: (row["status"], row["reason"]) for row in coverage(record)["tools"]}


# --- the client --------------------------------------------------------------

def test_a_stuck_server_stops_the_calls_instead_of_timing_out_each(monkeypatch):
    # stuck_server reads nothing after the "stuck" call: the ping gets no
    # answer, so last_tool is reported, not called and waited for.
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(client, "PING_TIMEOUT_SECONDS", 1)
    record, seconds = run_stuck_server()
    assert statuses(record) == {
        "first_tool": ("ran", None),
        "stuck": ("timed out", "no answer within 1 s"),
        "last_tool": ("not called", "server stopped responding after stuck timed out"),
    }
    assert "error" not in record
    assert seconds < 1 + 1 + 5  # call timeout + ping timeout + start and shutdown


def test_any_answer_to_the_ping_means_alive(monkeypatch):
    # --ping-error: the server answers ping with method-not-found. That still
    # proves it reads its messages, so the next tool is called.
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 1)
    record, _ = run_stuck_server("--ping-error")
    assert statuses(record) == {
        "first_tool": ("ran", None),
        "stuck": ("timed out", "no answer within 1 s"),
        "last_tool": ("ran", None),
    }


def test_tools_left_when_the_budget_runs_out_are_not_called(monkeypatch):
    # The budget cuts the "stuck" call short; last_tool is listed, never dropped.
    monkeypatch.setattr(client, "TIME_BUDGET_SECONDS", 1)
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 30)
    record, seconds = run_stuck_server("--ping-error")
    rows = statuses(record)
    assert rows["first_tool"] == ("ran", None)
    assert rows["stuck"][0] == "timed out"
    assert rows["last_tool"] == ("not called", "time budget")
    assert "error" not in record  # the budget is not a session failure
    assert seconds < 10


def test_coverage_totals_count_the_new_statuses():
    record = {"tools": [{"name": n} for n in ("a", "b", "c")],
              "calls": [{"tool": "a", "status": "OK", "result": "x"},
                        {"tool": "b", "status": "TIMED OUT", "result": "no answer within 30 s"}],
              "not_called": [{"tool": "c", "reason": "time budget"}]}
    assert coverage(record)["totals"] == {"ran": 1, "failed": 0, "timed_out": 1, "not_called": 1,
                                          "skipped": 0, "total": 3}


# --- the verdict ---------------------------------------------------------------

def session_with(*call_statuses: str) -> dict:
    return {"tools": [{"name": f"t{i}"} for i in range(len(call_statuses))],
            "calls": [{"tool": f"t{i}", "arguments": {}, "status": s, "result": ""}
                      for i, s in enumerate(call_statuses)]}


def test_one_timed_out_tool_does_not_make_the_run_incomplete():
    result = run([LAUNCH, NOTE_READ, EXITED], session=session_with("TIMED OUT", "OK"))
    assert result["verdict"] == "CLEAN", result["incomplete_reasons"]


def test_a_tool_that_returned_an_error_counts_as_completed():
    result = run([LAUNCH, EXITED], session=session_with("TIMED OUT", "ERROR"))
    assert result["verdict"] == "CLEAN", result["incomplete_reasons"]


def test_no_completed_call_is_incomplete():
    result = run([LAUNCH, EXITED], session=session_with("TIMED OUT", "NO ANSWER"))
    assert result["verdict"] == "INCOMPLETE"
    assert "no tool call completed (every call timed out or got no answer)" in result["incomplete_reasons"]


# --- the server-stopped marker ---------------------------------------------------

def stat(pid: int, path: str) -> str:
    return f'{pid}  10:00:00.950000 newfstatat(AT_FDCWD, "{path}", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)'


KILLED = "8  10:00:01.000000 +++ killed by SIGKILL +++"


def report_for(result: dict) -> dict:
    return build_report("x", "t", sandbox_policy(), session_with("OK"), result, Path("trace.txt"),
                        {}, {"name": "python312_slim", "file": "f", "multiarch": "m"})


def test_the_relays_server_stopped_marker_gives_the_note():
    # The relay (pid 7) stopped the server (pid 8): its exit is "killed by
    # SIGKILL", which is an exit record, so the trace is complete.
    result = run([LAUNCH, stat(7, stdin_relay.SERVER_STOPPED_MARKER), KILLED])
    assert result["verdict"] == "CLEAN", result["incomplete_reasons"]
    report = report_for(result)
    assert report["server_stopped_note"] == SERVER_STOPPED_NOTE
    assert SERVER_STOPPED_NOTE in _markdown(report)


def test_a_server_writing_the_marker_itself_gets_no_note():
    # Only the relay's own marker counts (#99): from the server it's just a probe.
    result = run([LAUNCH, stat(8, stdin_relay.SERVER_STOPPED_MARKER), EXITED])
    assert result["server_stopped"] is False
    assert report_for(result)["server_stopped_note"] is None
    assert [p["path"] for p in result["probes"]] == [stdin_relay.SERVER_STOPPED_MARKER]


def test_no_marker_no_note():
    result = run([LAUNCH, NOTE_READ, EXITED])
    assert report_for(result)["server_stopped_note"] is None


# --- the stdin relay itself --------------------------------------------------------

# Stands in for the launcher: starts the relay as its child (stdin shared,
# the ready fd as fd 3), waits until it's ready, then ignores the eof and
# sleeps, like a server with a tool stuck in a thread.
STUCK_PARENT = """
import os, subprocess, sys, time
ready_r, ready_w = os.pipe()
os.dup2(ready_r, 10)  # out of the way: fd 3 may be the read end
os.dup2(ready_w, 3)
subprocess.Popen([sys.executable, "-I", "-S", sys.argv[1]], stdout=subprocess.DEVNULL, pass_fds=(3,))
os.close(3)
os.read(10, 1)
print("ready", flush=True)
time.sleep(60)
"""


def test_the_relay_stops_a_server_that_ignores_eof():
    parent = subprocess.Popen([sys.executable, "-c", STUCK_PARENT, stdin_relay.__file__],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert parent.stdout.readline().strip() == "ready"
        start = time.monotonic()
        parent.stdin.close()  # the client hangs up
        assert parent.wait(timeout=10) == -signal.SIGKILL
        assert time.monotonic() - start >= stdin_relay.STOP_GRACE_SECONDS
    finally:
        if parent.poll() is None:
            os.kill(parent.pid, signal.SIGKILL)
