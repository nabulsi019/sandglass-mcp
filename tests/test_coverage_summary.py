"""Verdict honesty (#143): tools that didn't run normally are counted next to
the verdict, in the terminal, the Markdown and the JSON. The verdict word and
the exit code never change."""

from pathlib import Path

from mcp.types import CONNECTION_CLOSED, INVALID_PARAMS, REQUEST_TIMEOUT

from sandglass.compare import _markdown, build_report, coverage, coverage_summary, summary_lines
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, run, sandbox_policy


def session(*statuses: str, not_called: int = 0) -> dict:
    """A session with one call per status, then `not_called` tools left."""
    names = [f"t{i}" for i in range(len(statuses) + not_called)]
    return {"tools": [{"name": n} for n in names],
            "calls": [{"tool": n, "arguments": {}, "status": s, "result": "r"}
                      for n, s in zip(names, statuses)],
            "not_called": [{"tool": n, "reason": "time budget"} for n in names[len(statuses):]]}


def summary(s: dict) -> str | None:
    return coverage_summary(coverage(s))


def report(lines: list[str], s: dict) -> dict:
    """A full report of a hand-written trace with this session."""
    return build_report("x", "t", sandbox_policy(), s, run(lines, session=s), Path("trace.txt"),
                        {}, {"name": "python312_slim", "file": "f", "multiarch": "m"})


def test_the_examples_from_the_plan():
    # server-memory: 6 of 9 tools returned errors (isError).
    assert summary(session(*["ERROR"] * 6, *["OK"] * 3)) == "6 of 9 tools returned errors"
    # mcp-server-time: both tools errored on their input.
    assert summary(session("ERROR", "ERROR")) == "2 of 2 tools returned errors"
    # sequential-thinking: every tool ran, so no summary.
    assert summary(session("OK")) is None
    # wikipedia: one timed out, then the rest were not called.
    assert summary(session("OK", "OK", "TIMED OUT", not_called=1)) == "1 of 4 tools timed out, 1 not called"


def test_every_kind_is_counted_in_a_fixed_order():
    s = session("NO ANSWER", "ERROR", "TIMED OUT", "OK", not_called=2)
    s["skipped"] = [{"tool": "odd", "reason": "no valid input"}]
    s["tools"].append({"name": "odd"})
    assert summary(s) == "1 of 7 tools returned errors, 1 failed, 1 timed out, 2 not called, 1 skipped"


def test_a_json_rpc_error_response_returned_an_error_but_a_closed_connection_failed():
    s = session("FAILED", "FAILED", "FAILED", "FAILED")
    s["calls"][0]["error_code"] = INVALID_PARAMS     # the server answered with an error
    s["calls"][1]["error_code"] = CONNECTION_CLOSED  # no answer: the connection closed
    s["calls"][2]["error_code"] = REQUEST_TIMEOUT    # (recorded as TIMED OUT in practice)
    # calls[3]: not an MCP error at all, e.g. a broken pipe
    statuses = [row["status"] for row in coverage(s)["tools"]]
    assert statuses == ["returned an error", "failed", "failed", "failed"]


def test_result_text_is_never_read():
    # A tool that worked can return text about an error: still "ran".
    s = session("OK")
    s["calls"][0]["result"] = '{"status": "error", "message": "rate limited"}'
    assert coverage(s)["tools"][0]["status"] == "ran" and summary(s) is None


def test_no_summary_without_a_tool_list():
    assert summary({"tools": [], "calls": [], "error": "McpError: Connection closed"}) is None


def test_clean_gets_but_in_the_terminal_json_and_markdown():
    r = report([LAUNCH, NOTE_READ, EXITED], session("ERROR", "OK"))
    assert r["verdict"] == "CLEAN"
    assert r["coverage_summary"] == "1 of 2 tools returned errors"
    assert summary_lines(r)[0].startswith("Verdict: CLEAN (but 1 of 2 tools returned errors)  (violations: 0")
    assert "**Verdict: CLEAN** (but 1 of 2 tools returned errors)\n" in _markdown(r)


def test_other_verdicts_get_and():
    # Every call got an error response: still INCOMPLETE, as before #143.
    s = session("FAILED", "FAILED")
    for call in s["calls"]:
        call["error_code"] = INVALID_PARAMS
    r = report([LAUNCH, EXITED], s)
    assert r["verdict"] == "INCOMPLETE"
    assert summary_lines(r)[0].startswith("Verdict: INCOMPLETE (and 2 of 2 tools returned errors)  (")
    assert "**Verdict: INCOMPLETE** (and 2 of 2 tools returned errors)\n" in _markdown(r)


def test_a_clean_run_keeps_its_old_line():
    r = report([LAUNCH, NOTE_READ, EXITED], session("OK"))
    assert r["coverage_summary"] is None
    assert summary_lines(r)[0].startswith("Verdict: CLEAN  (violations: 0")
    assert "**Verdict: CLEAN**\n" in _markdown(r)
