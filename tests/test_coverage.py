"""Coverage report (#23): every listed tool as ran / failed / skipped, plus totals."""

import asyncio
import sys
from pathlib import Path

from mcp import StdioServerParameters

from sandglass import client
from sandglass.compare import _markdown, build_report, coverage
from tests.test_phases import report_markdown
from tests.test_sandbox_pipeline import LAUNCH, NOTE_READ, EXITED, run, sandbox_policy

FAKE_SERVER = Path(__file__).parent / "fake_servers" / "coverage_server.py"

TOOLS = [{"name": n, "description": ""} for n in ("ok", "broken", "odd", "never")]


def test_each_tool_gets_a_status_and_totals_add_up():
    session = {
        "tools": TOOLS,
        "calls": [{"tool": "ok", "arguments": {}, "status": "OK", "result": "fine"},
                  {"tool": "broken", "arguments": {}, "status": "ERROR", "result": "not logged in\n(401)"}],
        "skipped": [{"tool": "odd", "reason": "no valid input: can't build a string matching pattern"}],
        "error": "TimeoutError: ",
    }
    cov = coverage(session)
    assert cov["tools"] == [
        {"tool": "ok", "status": "ran", "reason": None},
        {"tool": "broken", "status": "failed", "reason": "ERROR: not logged in (401)"},
        {"tool": "odd", "status": "skipped", "reason": "no valid input: can't build a string matching pattern"},
        {"tool": "never", "status": "skipped",
         "reason": "not called, the session ended first: TimeoutError: "},
    ]
    assert cov["totals"] == {"ran": 1, "failed": 1, "skipped": 2, "total": 4}
    assert cov["note"] is None


def test_no_tool_list_is_said_plainly():
    assert coverage({"tools": [], "calls": [], "error": "McpError: Connection closed"})["note"] == \
        "the server's tool list was never received"
    assert coverage({"tools": [], "calls": []})["note"] == "the server listed no tools"


def test_long_errors_are_shortened():
    session = {"tools": [{"name": "t"}], "calls": [{"tool": "t", "status": "FAILED", "result": "x" * 999}]}
    assert len(coverage(session)["tools"][0]["reason"]) == len("FAILED: ") + 200


def test_markdown_has_a_coverage_section():
    md = report_markdown(run([LAUNCH, NOTE_READ, EXITED]))
    section = md[md.index("## Coverage"):md.index("## Network")]
    assert "Ran 1 · Failed 0 · Skipped 0 · Total 1" in section
    assert "| `read_note` | ran |  |" in section


def test_markdown_without_tools():
    session = {"tools": [], "calls": [], "error": "McpError: Connection closed"}
    report = build_report("x", "t", sandbox_policy(), session, run([LAUNCH, EXITED], session=session),
                          Path("trace.txt"), {}, {"name": "b", "file": "f", "multiarch": "m"})
    assert "No tools: the server's tool list was never received." in _markdown(report)


def test_a_failing_call_does_not_stop_the_other_tools(monkeypatch):
    # A real MCP session with the fake server, on the host (no Docker).
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 1)
    params = StdioServerParameters(command=sys.executable, args=[str(FAKE_SERVER)])
    record = asyncio.run(client.run(params, "coverage_server"))
    statuses = {row["tool"]: (row["status"], row["reason"]) for row in coverage(record)["tools"]}
    assert statuses["ok_tool"] == ("ran", None)
    assert statuses["error_tool"][0] == "failed" and "not logged in" in statuses["error_tool"][1]
    assert statuses["pattern_tool"][0] == "skipped" and "pattern" in statuses["pattern_tool"][1]
    # The timeout raised in the client; it's recorded as FAILED, not a crash.
    assert statuses["slow_tool"][0] == "failed" and statuses["slow_tool"][1].startswith("FAILED: ")


def test_a_session_that_fails_half_way_keeps_what_ran(monkeypatch):
    # run() fills the caller's record as it goes (#23), so a session timeout
    # after the first calls doesn't wipe them.
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 10)
    params = StdioServerParameters(command=sys.executable, args=[str(FAKE_SERVER)])
    record = client.new_session_record()
    try:
        asyncio.run(asyncio.wait_for(client.run(params, "coverage_server", session_record=record), 2))
    except TimeoutError:
        record["error"] = "TimeoutError: "
    cov = coverage(record)
    assert [r["tool"] for r in cov["tools"] if r["status"] == "ran"] == ["ok_tool"]
    # slow_tool was called but never answered before the session ended.
    assert cov["tools"][-1] == {"tool": "slow_tool", "status": "failed",
                                "reason": "NO ANSWER: the session ended before the call returned"}
