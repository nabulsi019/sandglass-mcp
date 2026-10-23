"""Report phases (#18): install / startup / tool-call, from hand-written traces.

The boundary is the stdin relay's tool-call marker (#91), found by its
position in the trace. No clock is used.
"""

from pathlib import Path

import pytest

from sandglass import launcher, stdin_relay
from sandglass.compare import _markdown, build_report
from tests.test_sandbox_pipeline import (EXITED, LAUNCH, RELAY_END, RELAY_START, SESSION_OK,
                                         TOOL_CALL, run, sandbox_policy)

DURING_STARTUP = '8 10:00:00.2 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
DURING_CALL = '8 10:00:00.7 openat(AT_FDCWD, "/project/test_servers/decoy_home/.fake_credentials", O_RDONLY) = 3'
CREDS = "/project/test_servers/decoy_home/.fake_credentials"


def phases(result):
    return {v["target"]: v["phase"] for v in result["violations"]}


# --- the boundary --------------------------------------------------------------

def test_events_split_at_the_relays_tool_call_marker():
    result = run([LAUNCH, DURING_STARTUP, TOOL_CALL, DURING_CALL, EXITED])
    assert phases(result) == {"/etc/passwd": "startup", CREDS: "tool-call"}
    assert result["phase_note"] is None


def test_position_counts_not_timestamps():
    # A VM clock a few ms off the host's used to move events into the wrong
    # phase. Timestamps are now ignored: this read is stamped BEFORE the
    # marker but comes after it in the trace, so it's a tool-call event.
    early_stamp = DURING_CALL.replace("10:00:00.7", "10:00:00.000400")
    result = run([LAUNCH, DURING_STARTUP, TOOL_CALL, early_stamp, EXITED])
    assert phases(result) == {"/etc/passwd": "startup", CREDS: "tool-call"}


def test_a_marker_from_another_process_is_ignored():
    # The server stat()s the marker path itself, trying to move the boundary.
    forged = TOOL_CALL.replace("7  ", "8  ", 1)
    result = run([LAUNCH, forged, DURING_CALL, TOOL_CALL, EXITED])
    assert phases(result) == {CREDS: "startup"}


def test_tool_calls_without_a_marker_are_unknown_never_guessed():
    # Tools were called (SESSION_OK) but the relay's tool-call marker is missing.
    lines = [LAUNCH] + RELAY_START + [DURING_STARTUP, DURING_CALL] + RELAY_END + [EXITED]
    result = run(lines, relay=False)
    assert phases(result) == {"/etc/passwd": "unknown", CREDS: "unknown"}
    assert "tool-call marker is missing" in result["phase_note"]


def test_no_tool_calls_means_everything_is_startup():
    session = {"tools": [], "calls": []}
    lines = [LAUNCH] + RELAY_START + [DURING_CALL] + RELAY_END + [EXITED]
    result = run(lines, session=session, relay=False)
    assert phases(result) == {CREDS: "startup"}
    assert result["phase_note"] is None


def test_probes_and_domains_get_a_phase():
    stat = '8 10:00:00.8 newfstatat(AT_FDCWD, "/home/sandglass/.ssh", 0x7f, 0) = 0'
    result = run([LAUNCH, TOOL_CALL, stat, EXITED])
    assert result["probes"][0]["phase"] == "tool-call"


# --- the relay itself ----------------------------------------------------------

def test_relay_launch_and_markers_are_skipped_the_rest_is_judged():
    # Only its exec and marker stats are skipped (#99). Its Python startup
    # looks for files that don't exist, like any Python: listed as attempted.
    relay_startup = '7  10:00:00.000065 openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY) = -1 ENOENT (No such file or directory)'
    result = run([LAUNCH, relay_startup, TOOL_CALL, EXITED])
    assert result["verdict"] == "CLEAN"
    assert result["probes"] == [] and result["violations"] == []
    assert [(a["pid"], a["target"]) for a in result["attempted"]] == [(7, "/usr/share/locale/locale.alias")]


def test_relay_missing_is_incomplete_and_phases_unknown():
    result = run([LAUNCH, DURING_CALL, EXITED], relay=False)
    assert result["verdict"] == "INCOMPLETE"
    assert any("stdin relay did not start" in r for r in result["incomplete_reasons"])
    assert phases(result) == {CREDS: "unknown"}


@pytest.mark.parametrize("relay_end, how", [
    (["7  10:00:00.6 +++ killed by SIGKILL +++"], "killed by SIGKILL"),       # killed, no eof marker
    (["7  10:00:00.6 +++ exited with 1 +++"], "exited with 1"),               # crashed
    ([RELAY_END[0], "7  10:00:00.9 +++ exited with 1 +++"], "exited with 1"),  # eof, then a bad exit
    ([], "no exit record"),                                                    # still running?
])
def test_relay_ending_early_is_incomplete(relay_end, how):
    # E.g. the server killed the relay, so it could feed itself fake input.
    lines = [LAUNCH] + RELAY_START + [TOOL_CALL, DURING_CALL] + relay_end + [EXITED]
    result = run(lines, relay=False)
    assert result["verdict"] == "INCOMPLETE"
    reasons = [r for r in result["incomplete_reasons"] if "stdin relay exited or was killed" in r]
    assert len(reasons) == 1 and how in reasons[0] and "tampered" in reasons[0]


@pytest.mark.parametrize("line, expected", [
    (b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_note"}}', True),
    (b'{"method": "tools/call", "jsonrpc": "2.0", "id": 3}', True),
    (b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}', False),
    (b'{"jsonrpc":"2.0","id":2,"result":{"method":"tools/call"}}', False),  # nested, not the method
    (b'{"jsonrpc":"2.0","id":2,"meth', False),                               # partial line
    (b'["tools/call"]', False),
    (b"", False),
])
def test_relay_recognises_tool_calls(line, expected):
    assert stdin_relay.is_tool_call(line) is expected


def test_launcher_and_relay_agree():
    assert launcher.RELAY_READY_FD == stdin_relay.READY_FD


# --- the report ------------------------------------------------------------------

SESSION = {"tools": [{"name": "read_note"}],
           "calls": [{"tool": "read_note", "arguments": {"name": "hello"}, "status": "OK", "result": "hi"}]}


def report_markdown(result):
    report = build_report("x", "t", sandbox_policy(), SESSION, result, Path("trace.txt"),
                          {}, {"name": "python312_slim", "file": "f", "multiarch": "m"})
    return _markdown(report)


def test_markdown_has_three_phase_sections():
    md = report_markdown(run([LAUNCH, DURING_STARTUP, TOOL_CALL, DURING_CALL, EXITED]))
    install, startup, calls = md.index("### Install"), md.index("### Startup"), md.index("### Tool calls")
    assert install < startup < calls
    assert "see #16" in md[install:startup]
    assert "/etc/passwd" in md[startup:calls]
    assert ".fake_credentials" in md[calls:]
    assert "### Phase unknown" not in md


def test_markdown_shows_unknown_phase_and_why():
    lines = [LAUNCH] + RELAY_START + [DURING_CALL] + RELAY_END + [EXITED]
    md = report_markdown(run(lines, relay=False))
    assert "Phases are unknown: tools were called, but the tool-call marker is missing" in md
    assert ".fake_credentials" in md[md.index("### Phase unknown"):]
