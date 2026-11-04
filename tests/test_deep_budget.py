"""The deep scan's time budget (#170): 30 s per tool, at least 120 s, at most 600 s.

The budget rule, the "under 5 s left" rule with a fake budget clock against
tests/fake_servers/coverage_server.py (on the host, no Docker), the --deep
flag's usage errors, and the depth in the report and the reproduce command.
"""

import asyncio
import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from sandglass import client
from sandglass.compare import _markdown, build_report, coverage
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, run, sandbox_policy

FAKE_SERVER = Path(__file__).parent / "fake_servers" / "coverage_server.py"


# --- the budget rule -----------------------------------------------------------

@pytest.mark.parametrize("tools, seconds", [
    (0, 120), (1, 120), (4, 120),   # the floor
    (5, 150), (13, 390), (20, 600),  # 30 s per tool
    (21, 600), (22, 600), (100, 600),  # the cap
])
def test_deep_budget(tools, seconds):
    assert client.deep_budget(tools) == seconds


def test_the_safety_net_covers_the_cap():
    assert client.session_limit("deep") == 600 + client.SESSION_GRACE_SECONDS
    assert client.session_limit("quick") == 120 + client.SESSION_GRACE_SECONDS


# --- under 5 s left: a fake budget clock -----------------------------------------

def run_with_clock(monkeypatch, readings: list[float], depth: str) -> dict:
    """One session with coverage_server.py where the budget clock returns
    `readings` in order (then the last one forever)."""
    values = iter(readings)
    last = [readings[-1]]

    def fake_clock():
        last[0] = next(values, last[0])
        return last[0]

    monkeypatch.setattr(client, "budget_clock", fake_clock)
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 1)  # slow_tool takes 3 s
    params = StdioServerParameters(command=sys.executable, args=[str(FAKE_SERVER)])
    return asyncio.run(client.run(params, "coverage_server", depth=depth))


def statuses(record: dict) -> dict:
    return {row["tool"]: (row["status"], row["reason"]) for row in coverage(record)["tools"]}


def test_deep_starts_no_call_with_under_5_s_left(monkeypatch):
    # Deep reads the clock once at the start and once after tools/list (5
    # tools: 150 s), then once per tool. slow_tool would start with 2 s left.
    record = run_with_clock(monkeypatch, [0, 0, 10, 20, 30, 40, 148], "deep")
    assert record["budget"] == {"seconds": 150, "per_tool": 30, "tools": 5}
    assert statuses(record)["slow_tool"] == ("not called", "time budget")
    assert [c["tool"] for c in record["calls"]] == ["ok_tool", "error_tool", "rejected_tool", "pattern_tool"]


def test_quick_still_starts_a_call_with_2_s_left(monkeypatch):
    # The same moment in quick (120 s from the start): the call starts, as before #170.
    record = run_with_clock(monkeypatch, [0, 10, 20, 30, 40, 118], "quick")
    assert "budget" not in record
    assert statuses(record)["slow_tool"][0] == "timed out"


def test_deep_with_exactly_5_s_left_does_not_start(monkeypatch):
    record = run_with_clock(monkeypatch, [0, 0, 10, 20, 30, 40, 145], "deep")
    assert statuses(record)["slow_tool"] == ("not called", "time budget")


def test_deep_reaches_every_tool_with_time_left(monkeypatch):
    record = run_with_clock(monkeypatch, [0, 0, 10, 20, 30, 40, 50], "deep")
    # The first pass of the round robin (#172) reaches every tool.
    assert [c["tool"] for c in record["calls"][:5]] == ["ok_tool", "error_tool", "rejected_tool",
                                                         "pattern_tool", "slow_tool"]
    assert record["not_called"] == [] and record["calls_not_made"] == 0


# --- the flag ----------------------------------------------------------------------

def test_deep_without_sandbox_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sandglass", "test_servers/good_notes_server.py", "--deep"])
    with pytest.raises(SystemExit) as exc:
        client.main()
    assert exc.value.code == 2
    assert "--deep needs --sandbox" in capsys.readouterr().err


@pytest.mark.parametrize("argv, depth", [([], "quick"), (["--deep"], "deep")])
def test_the_flag_reaches_the_scan(monkeypatch, argv, depth):
    seen = {}

    def fake_run_scan(*args, **kwargs):
        # A quick scan calls run_scan exactly as before #170: no depth argument.
        seen["depth"] = kwargs.get("depth", "quick")
        seen["positional"] = len(args)
        return {"verdict": "CLEAN"}

    monkeypatch.setattr(client, "run_scan", fake_run_scan)
    with pytest.raises(SystemExit) as exc:
        client.scan_main(["pypi:sandglass-test-notes@1.0.0", "--policy",
                          "policies/templates/no_network.v1.yaml", *argv])
    assert exc.value.code == 0
    assert seen["depth"] == depth
    assert seen["positional"] == 7  # spec ... inputs, as before #170


@pytest.mark.parametrize("argv, depth", [([], "quick"), (["--deep"], "deep")])
def test_the_flag_reaches_the_sandboxed_run(monkeypatch, argv, depth):
    seen = {}

    def fake_run_sandboxed(*args, **kwargs):
        seen["depth"] = kwargs.get("depth", "quick")
        return {"verdict": "CLEAN"}

    monkeypatch.setattr(client, "run_sandboxed", fake_run_sandboxed)
    monkeypatch.setattr(sys, "argv", ["sandglass", "test_servers/good_notes_server.py", "--policy",
                                      "policies/notes_readonly.yaml", "--sandbox", *argv])
    with pytest.raises(SystemExit):
        client.main()
    assert seen["depth"] == depth


# --- the report ---------------------------------------------------------------------

def test_reproduce_command_has_deep_only_in_deep():
    quick = client.server_setup(["sandglass", "scan", "pypi:x@1"], [], {}, "described")
    deep = client.server_setup(["sandglass", "scan", "pypi:x@1"], [], {}, "described", "deep")
    assert quick["command"] == "sandglass scan pypi:x@1 --inputs described"
    assert deep["command"] == "sandglass scan pypi:x@1 --deep --inputs described"


def report_for(depth: str, budget: dict | None = None) -> dict:
    session = {"tools": [{"name": "read_note", "description": ""}],
               "calls": [{"tool": "read_note", "arguments": {"name": "hello"}, "status": "OK", "result": "hi"}]}
    if budget:
        session["budget"] = budget
    return build_report("x", "t", sandbox_policy(), session, run([LAUNCH, NOTE_READ, EXITED], session=session),
                        None, {}, {"name": "b", "file": "f", "multiarch": "m"}, depth=depth)


def test_quick_report_has_depth_and_no_budget():
    report = report_for("quick")
    assert report["depth"] == "quick"
    assert "budget" not in report
    assert "Time budget" not in _markdown(report)


def test_deep_report_has_depth_and_budget():
    report = report_for("deep", {"seconds": 120, "per_tool": 30, "tools": 1})
    assert report["depth"] == "deep"
    assert report["budget"] == {"seconds": 120, "per_tool": 30, "tools": 1}
    assert "- Time budget: 120 s (30 s per tool, 1 tool)" in _markdown(report)


def test_the_verdict_does_not_depend_on_the_depth():
    assert report_for("quick")["verdict"] == report_for("deep", {"seconds": 120, "per_tool": 30,
                                                                  "tools": 1})["verdict"]
