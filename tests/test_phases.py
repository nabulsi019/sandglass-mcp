"""Report phases (#18): install / startup / tool-call, from hand-written traces."""

from sandglass.compare import _markdown, build_report
from tests.test_sandbox_pipeline import LAUNCH, EXITED, run, sandbox_policy

from pathlib import Path

# The client sets this just before its first call_tool (UTC, strace -tt format).
SESSION = {"tools": [{"name": "read_note"}],
           "calls": [{"tool": "read_note", "arguments": {"name": "hello"}, "status": "OK", "result": "hi"}],
           "tool_calls_started": "10:00:00.500000"}

DURING_STARTUP = '8 10:00:00.2 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
DURING_CALL = '8 10:00:00.7 openat(AT_FDCWD, "/project/test_servers/decoy_home/.fake_credentials", O_RDONLY) = 3'


def phases(result):
    return {v["target"]: v["phase"] for v in result["violations"]}


def test_events_split_at_the_first_tool_call():
    result = run([LAUNCH, DURING_STARTUP, DURING_CALL, EXITED], session=SESSION)
    assert phases(result) == {
        "/etc/passwd": "startup",
        "/project/test_servers/decoy_home/.fake_credentials": "tool-call",
    }


def test_no_tool_calls_means_everything_is_startup():
    session = {"tools": [], "calls": [{"tool": "x"}]}  # no boundary recorded
    result = run([LAUNCH, DURING_CALL, EXITED], session=session)
    assert phases(result) == {"/project/test_servers/decoy_home/.fake_credentials": "startup"}


def test_run_across_midnight():
    launch = LAUNCH.replace("10:00:00.000001", "23:59:59.000000")
    before = '8 23:59:59.500000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
    after = '8 00:00:00.300000 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3'
    exited = "8  00:00:01.000000 +++ exited with 0 +++"
    session = dict(SESSION, tool_calls_started="00:00:00.100000")
    result = run([launch, before, after, exited], session=session)
    assert phases(result) == {"/etc/passwd": "startup", "/etc/shadow": "tool-call"}


def test_probes_and_domains_get_a_phase():
    stat = '8 10:00:00.8 newfstatat(AT_FDCWD, "/home/sandglass/.ssh", 0x7f, 0) = 0'
    result = run([LAUNCH, stat, EXITED], session=SESSION)
    assert result["probes"][0]["phase"] == "tool-call"


def test_markdown_has_three_phase_sections():
    result = run([LAUNCH, DURING_STARTUP, DURING_CALL, EXITED], session=SESSION)
    report = build_report("x", "t", sandbox_policy(), SESSION, result, Path("trace.txt"),
                          {}, {"name": "python312_slim", "file": "f", "multiarch": "m"})
    md = _markdown(report)
    install, startup, calls = md.index("### Install"), md.index("### Startup"), md.index("### Tool calls")
    assert install < startup < calls
    assert "see #16" in md[install:startup]
    assert "/etc/passwd" in md[startup:calls]
    assert ".fake_credentials" in md[calls:]
