"""The observation window after the last call, deep scans only (#175).

The stdin relay's new marker (order, bytes unchanged, before any tools/call),
the phase split with both boundaries and with the marker missing, the
client's window (one marker notification, idle, ends early when the server
exits), and the report's line.
"""

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters

from sandglass import client, stdin_relay
from sandglass.compare import PHASES, _markdown, observation_line
from tests.test_deep_budget import report_for
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, RELAY_END, RELAY_START, TOOL_CALL, run

EXITING_SERVER = Path(__file__).parent / "fake_servers" / "exiting_server.py"
OBSERVATION = ('7  10:00:00.000700 newfstatat(AT_FDCWD, "/sandglass-phase/observation", 0x7ffe8cb57b40, 0)'
               ' = -1 ENOENT (No such file or directory)')
LATER_READ = '10 10:00:00.000800 openat(AT_FDCWD, "/home/sandglass/.aws/credentials", O_RDONLY|O_CLOEXEC) = 9'
DEEP_SESSION = {"tools": [{"name": "read_note"}], "calls": [{"tool": "read_note"}],
                "observation": {"seconds": 60, "ended_early": False}}


# --- the stdin relay ---------------------------------------------------------------

# Runs the real relay() with its markers written into its output instead of
# stat()ed (so the test sees where they fall), fd 3 as the ready pipe, and
# no server to stop at the end.
RELAY_WRAPPER = """
import os, sys
sys.path.insert(0, sys.argv[1])
import stdin_relay
r, w = os.pipe()
os.dup2(r, 10)  # out of the way: fd 3 may be the read end
os.dup2(w, 3)
stdin_relay._record = lambda path: os.write(1, f"<MARK {path}>".encode())
stdin_relay._stop_server_if_stuck = lambda parent: None
stdin_relay.relay()
"""


def relay_output(messages: list[dict]) -> str:
    """Feed the relay one message per line, a little apart (one read each)."""
    proc = subprocess.Popen([sys.executable, "-c", RELAY_WRAPPER, str(Path(stdin_relay.__file__).parent)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    for message in messages:
        proc.stdin.write((json.dumps(message) + "\n").encode())
        proc.stdin.flush()
        time.sleep(0.2)
    proc.stdin.close()
    out = proc.stdout.read().decode()
    proc.wait(timeout=10)
    return out


INIT = {"jsonrpc": "2.0", "id": 0, "method": "initialize"}
CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}}
ROOTS = {"jsonrpc": "2.0", "method": stdin_relay.OBSERVATION_METHOD}


def test_the_relay_marks_the_window_just_before_its_notification():
    out = relay_output([INIT, CALL, ROOTS])
    mark = lambda path: f"<MARK {path}>"  # noqa: E731
    assert out.index(mark(stdin_relay.TOOL_CALL_MARKER)) < out.index('"tools/call"')
    assert out.index('"tools/call"') < out.index(mark(stdin_relay.OBSERVATION_MARKER)) \
        < out.index(stdin_relay.OBSERVATION_METHOD)
    # The bytes themselves are passed on unchanged.
    without_marks = out
    for path in (stdin_relay.RELAY_READY, stdin_relay.TOOL_CALL_MARKER, stdin_relay.OBSERVATION_MARKER,
                 stdin_relay.EOF_MARKER):
        without_marks = without_marks.replace(mark(path), "")
    assert without_marks == "".join(json.dumps(m) + "\n" for m in (INIT, CALL, ROOTS))


def test_a_window_without_any_tool_call_is_still_marked():
    out = relay_output([INIT, ROOTS])
    assert f"<MARK {stdin_relay.OBSERVATION_MARKER}>" in out
    assert f"<MARK {stdin_relay.TOOL_CALL_MARKER}>" not in out


def test_quick_messages_get_no_window_marker():
    out = relay_output([INIT, CALL, {**CALL, "id": 2}])
    assert stdin_relay.OBSERVATION_MARKER not in out
    assert out.count(f"<MARK {stdin_relay.TOOL_CALL_MARKER}>") == 1


# --- the phases ------------------------------------------------------------------------

def trace(*middle: str) -> list[str]:
    """A run whose relay lines are placed by hand (TOOL_CALL, OBSERVATION)."""
    return [LAUNCH, *RELAY_START, *middle, *RELAY_END[:1], EXITED, RELAY_END[1]]


def phases(lines: list[str], session: dict) -> dict:
    result = run(lines, session=session, relay=False)
    return {(v["target"], v["phase"]) for v in result["violations"]}, result["phase_note"]


def test_events_after_the_marker_are_in_the_observation_phase():
    got, note = phases(trace(TOOL_CALL, NOTE_READ, OBSERVATION, LATER_READ), DEEP_SESSION)
    assert got == {("/home/sandglass/.aws/credentials", "observation")}
    assert note is None
    assert "observation" in PHASES


def test_the_window_is_judged_by_the_same_rules():
    result = run(trace(TOOL_CALL, OBSERVATION, LATER_READ), session=DEEP_SESSION, relay=False)
    assert result["verdict"] == "VIOLATIONS"
    assert result["violations"][0]["reason"].startswith("read outside")
    assert result["observation_events"] == 1


def test_a_missing_marker_in_deep_is_unknown_not_guessed():
    got, note = phases(trace(TOOL_CALL, LATER_READ), DEEP_SESSION)
    assert got == {("/home/sandglass/.aws/credentials", "unknown")}
    assert "observation window" in note


def test_only_the_relays_marker_counts():
    # The server (pid 10) stats the marker path itself: not a boundary.
    forged = OBSERVATION.replace("7  ", "10 ", 1)
    got, _ = phases(trace(TOOL_CALL, forged, LATER_READ), {**DEEP_SESSION, "observation": None})
    assert got == {("/home/sandglass/.aws/credentials", "tool-call")}


def test_quick_traces_split_as_before():
    got, note = phases(trace(TOOL_CALL, LATER_READ), {"tools": [{"name": "read_note"}],
                                                       "calls": [{"tool": "read_note"}]})
    assert got == {("/home/sandglass/.aws/credentials", "tool-call")} and note is None


# --- the client's window ---------------------------------------------------------------

def test_the_window_ends_early_when_the_server_exits(monkeypatch):
    monkeypatch.setattr(client, "OBSERVE_SECONDS", 20)
    sent = []
    original = ClientSession.send_notification

    async def send_notification(self, notification, *args, **kwargs):
        sent.append(notification.method)
        return await original(self, notification, *args, **kwargs)

    monkeypatch.setattr(ClientSession, "send_notification", send_notification)
    params = StdioServerParameters(command=sys.executable, args=[str(EXITING_SERVER)])
    start = time.monotonic()
    record = asyncio.run(client.run(params, "exiting_server", depth="deep"))
    assert record["observation"] == {"seconds": 20, "ended_early": True}
    assert time.monotonic() - start < 15
    # One marker notification, after the calls; nothing else is sent in the window.
    assert sent == ["notifications/initialized", stdin_relay.OBSERVATION_METHOD]


def test_the_safety_net_covers_the_window():
    assert client.session_limit("deep") == client.DEEP_CAP_SECONDS + client.OBSERVE_SECONDS \
        + client.SESSION_GRACE_SECONDS
    assert client.OBSERVE_SECONDS == 60


# --- the report ---------------------------------------------------------------------------

def test_the_report_line():
    report = report_for("deep", {"seconds": 120, "per_tool": 30, "tools": 1})
    report["observation"] = {"seconds": 60, "ended_early": False, "events": 2}
    line = "Observation: 60 s idle after the last call; 2 events in the window, judged like any other"
    assert observation_line(report) == line
    assert f"- {line}" in _markdown(report)
    report["observation"]["ended_early"] = True
    assert "ended early: the server exited" in observation_line(report)
    assert observation_line(report_for("quick")) is None
