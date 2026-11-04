"""Repeated calls and the repeatability check, deep scans only (#172).

Input variants (order, dedupe, the cap, harmless edge cases), the round
robin under a fake budget clock, coverage with several calls per tool, the
comparison of the two runs, and one download per deep scan.
"""

import asyncio
import sys
from pathlib import Path

from mcp import StdioServerParameters
from mcp.types import Tool

from sandglass import PROJECT_ROOT, client, sandbox, scan
from sandglass.compare import (UNSTABLE_LABEL, coverage, coverage_summary, stability_line, summary_lines,
                               verdict_line, with_second_run)
from sandglass.inputs import MAX_VARIANTS, SAMPLES_DIR, arguments_of, input_variants
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, run

FAKE_SERVER = Path(__file__).parent / "fake_servers" / "coverage_server.py"
POLICY = PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml"
CREDS_READ = '10 10:00:00.000200 openat(AT_FDCWD, "/home/sandglass/.aws/credentials", O_RDONLY|O_CLOEXEC) = 9'


# --- input variants -------------------------------------------------------------

def variants(schema: dict, description: str = "", name: str = "tool") -> list[tuple[str, dict]]:
    return [(variant, arguments_of(inputs)) for variant, inputs in input_variants(schema, description, name)]


def test_variant_order_and_dedupe():
    # schema and minimal give the same "hello" as described: dropped.
    schema = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
    assert variants(schema) == [
        ("described", {"path": "hello"}),
        ("sample-file", {"path": f"{SAMPLES_DIR}/notes.txt"}),
        ("edge-empty", {"path": ""}),
        ("edge-long", {"path": "x" * 1000}),
        ("edge-unicode", {"path": "héllo 🙂"}),
    ]


def test_at_most_five_variants():
    # Every mode differs here, so the cap cuts the edge cases short.
    schema = {"type": "object", "required": ["path"], "properties": {
        "path": {"type": "string", "description": "A path, e.g. 'abc'"},
        "opt": {"type": "integer", "minimum": 5}}}
    got = variants(schema)
    assert len(got) == MAX_VARIANTS == 5
    assert [name for name, _ in got] == ["described", "sample-file", "schema", "minimal", "edge-empty"]


def test_no_arguments_is_one_variant():
    assert variants({"type": "object", "properties": {}}) == [("described", {})]


def test_edge_cases_are_harmless():
    schema = {"type": "object", "required": ["a", "n", "l", "b", "e"], "properties": {
        "a": {"type": "string"}, "n": {"type": "integer"}, "l": {"type": "array", "items": {"type": "string"}},
        "b": {"type": "boolean"}, "e": {"type": "string", "enum": ["only"]}}}
    edges = {name: args for name, args in variants(schema) if name.startswith("edge")}
    assert edges["edge-empty"] == {"a": "", "n": 0, "l": [], "b": False, "e": "only"}
    assert edges["edge-long"]["a"] == "x" * 1000 and edges["edge-long"]["n"] == -1
    assert edges["edge-unicode"]["a"] == "héllo 🙂"
    # No traversal or injection: no path separators, no shell characters.
    for args in edges.values():
        for value in args.values():
            assert not any(bad in str(value) for bad in ("/", "..", ";", "$", "`", "|", "&", "<", ">"))


# --- the round robin --------------------------------------------------------------

def tool(name: str, schema: dict) -> Tool:
    return Tool(name=name, description="", input_schema=schema)


def test_deep_plan_is_round_robin():
    with_path = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
    no_args = {"type": "object", "properties": {}}
    plan = client.deep_plan([tool("a", with_path), tool("b", no_args)], client.new_session_record(), "described")
    assert [(name, variant) for name, variant, _ in plan] == [
        ("a", "described"), ("b", "described"),
        ("a", "sample-file"), ("a", "edge-empty"), ("a", "edge-long"), ("a", "edge-unicode")]


def run_deep(monkeypatch, readings: list[float], replay: dict | None = None) -> dict:
    """One deep session with coverage_server.py, the budget clock giving `readings`."""
    values = iter(readings)
    last = [readings[-1]]

    def fake_clock():
        last[0] = next(values, last[0])
        return last[0]

    monkeypatch.setattr(client, "budget_clock", fake_clock)
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 1)  # slow_tool takes 3 s
    params = StdioServerParameters(command=sys.executable, args=[str(FAKE_SERVER)])
    return asyncio.run(client.run(params, "coverage_server", depth="deep", replay=replay))


def test_no_tool_is_starved_of_its_first_call(monkeypatch):
    # The budget (150 s) runs out right after the first pass.
    record = run_deep(monkeypatch, [0, 0, 1, 2, 3, 4, 5, 149])
    assert [c["tool"] for c in record["calls"]] == ["ok_tool", "error_tool", "rejected_tool",
                                                     "pattern_tool", "slow_tool"]
    assert all(c["variant"] == "described" for c in record["calls"])
    assert record["not_called"] == [] and record["calls_not_made"] > 0


def test_a_timed_out_tool_gets_no_more_variants(monkeypatch):
    record = run_deep(monkeypatch, [0, 0, 1])
    assert [c["variant"] for c in record["calls"] if c["tool"] == "slow_tool"] == ["described"]
    assert sum(1 for c in record["calls"] if c["tool"] == "ok_tool") > 1


def test_run_2_replays_run_1s_calls(monkeypatch):
    first = run_deep(monkeypatch, [0, 0, 1, 2, 3, 4, 5, 149])
    second = run_deep(monkeypatch, [0, 0, 1], replay=first)
    assert ([(c["tool"], c["variant"], c["arguments"]) for c in second["calls"]]
            == [(c["tool"], c["variant"], c["arguments"]) for c in first["calls"]])
    assert second["budget"] == first["budget"]


# --- coverage with several calls --------------------------------------------------

def test_coverage_shows_the_best_call_per_tool():
    session = {"tools": [{"name": "t"}, {"name": "u"}], "calls": [
        {"tool": "t", "variant": "described", "status": "ERROR", "result": "no such file"},
        {"tool": "u", "variant": "described", "status": "ERROR", "result": "bad"},
        {"tool": "t", "variant": "sample-file", "status": "OK", "result": "found"},
        {"tool": "u", "variant": "edge-empty", "status": "FAILED", "result": "boom"}]}
    cov = coverage(session)
    assert [(row["tool"], row["status"]) for row in cov["tools"]] == [("t", "ran"), ("u", "returned an error")]
    assert [c["variant"] for c in cov["tools"][0]["calls"]] == ["described", "sample-file"]
    assert cov["totals"]["calls"] == 4
    # The summary counts tools with no successful call, not calls.
    assert coverage_summary(cov) == "1 of 2 tools returned errors"


def test_quick_coverage_has_no_calls_column():
    session = {"tools": [{"name": "t"}], "calls": [{"tool": "t", "status": "OK", "result": "x"}]}
    cov = coverage(session)
    assert "calls" not in cov["totals"] and "calls" not in cov["tools"][0]


# --- comparing the two runs --------------------------------------------------------

SESSION = {"tools": [{"name": "read_note"}], "calls": [{"tool": "read_note"}]}


def merged(lines_1: list[str], lines_2: list[str]) -> dict:
    return with_second_run(run([LAUNCH, *lines_1, EXITED], session=SESSION),
                           run([LAUNCH, *lines_2, EXITED], session=SESSION), SESSION, "trace-2.txt")


def test_same_entries_with_different_counts_is_stable():
    result = merged([CREDS_READ], [CREDS_READ, CREDS_READ.replace("000200", "000300")])
    assert result["stability"]["status"] == "stable"
    assert result["verdict"] == "VIOLATIONS"
    # Each finding once: run 1's events, none of run 2's repeats.
    assert [v["run"] for v in result["violations"]] == [1]


def test_a_missing_entry_is_unstable_and_the_worse_verdict_wins():
    result = merged([NOTE_READ], [NOTE_READ, CREDS_READ])
    s = result["stability"]
    assert s["status"] == "unstable" and s["verdicts"] == ["CLEAN", "VIOLATIONS"]
    assert s["only_in_run_1"] == [] and s["only_in_run_2"] == ["read /home/sandglass/.aws/credentials (startup)"]
    assert result["verdict"] == "VIOLATIONS"
    assert [(v["target"], v["run"]) for v in result["violations"]] == [("/home/sandglass/.aws/credentials", 2)]


def test_a_finding_only_in_run_1_still_counts():
    result = merged([CREDS_READ], [NOTE_READ])
    assert result["verdict"] == "VIOLATIONS" and result["stability"]["only_in_run_1"]


def test_an_incomplete_run_2_makes_the_scan_incomplete():
    run_1 = run([LAUNCH, NOTE_READ, EXITED], session=SESSION)
    run_2 = run([LAUNCH, NOTE_READ, EXITED], session=SESSION, sink=False)  # the sink never started
    result = with_second_run(run_1, run_2, SESSION, "trace-2.txt")
    assert result["verdict"] == "INCOMPLETE"
    assert any(reason.startswith("run 2: the network sink did not start") for reason in result["incomplete_reasons"])
    assert result["stability"]["status"] == "unstable"


def test_the_unstable_label_and_the_verdict_word():
    r = {"verdict": "VIOLATIONS", "coverage_summary": None, "stability": {
        "status": "unstable", "verdicts": ["CLEAN", "VIOLATIONS"], "only_in_run_1": [],
        "only_in_run_2": ["read /x (tool-call)"]}}
    assert verdict_line(r) == f"VIOLATIONS ({UNSTABLE_LABEL})"
    assert stability_line(r) == ("Stability: unstable between runs (verdicts CLEAN / VIOLATIONS; "
                                 "only in run 2: read /x (tool-call))")
    r["coverage_summary"] = "1 of 2 tools returned errors"
    assert verdict_line(r) == f"VIOLATIONS (and 1 of 2 tools returned errors, {UNSTABLE_LABEL})"
    assert verdict_line({"verdict": "CLEAN", "coverage_summary": None}) == "CLEAN"  # quick: unchanged


# --- one download per deep scan -------------------------------------------------------

def test_one_download_per_deep_scan(monkeypatch, tmp_path):
    calls = {"download": 0, "install": 0, "runs": []}
    hash_ok = {"file": "x.whl", "source": "PyPI", "algorithm": "sha256", "ours": "a",
               "published": "a", "match": True}

    def download(*args):
        calls["download"] += 1
        return object()

    def install(*args):
        calls["install"] += 1
        return 0

    async def fake_run(params, server, errlog, session, inputs_mode, depth="quick", replay=None):
        calls["runs"].append((depth, replay is not None, params.args[params.args.index("-v") + 1]))
        return session

    monkeypatch.setattr(client, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(sandbox, "detect_multiarch", lambda: "aarch64-linux-gnu")
    monkeypatch.setattr(scan, "download", download)
    monkeypatch.setattr(scan, "describe_files", lambda prepared: [])
    monkeypatch.setattr(scan, "verify_hash", lambda *a: hash_ok)
    monkeypatch.setattr(scan, "choose_entry", lambda prepared, entry: ("x", "/package/site/bin/x"))
    monkeypatch.setattr(sandbox, "create_volume", lambda name: None)
    monkeypatch.setattr(sandbox, "remove_volume", lambda name: None)
    monkeypatch.setattr(scan, "install", install)
    monkeypatch.setattr(scan, "log_tail", lambda path: "")
    monkeypatch.setattr(client, "parse_trace_file", lambda *a, **k: ([], False))
    monkeypatch.setattr(client, "run", fake_run)
    report = client.run_scan(scan.parse_spec("pypi:x@1.0"), POLICY, depth="deep")
    assert calls["download"] == 1 and calls["install"] == 1
    # Two runs, the second a replay, both from the same installed volume.
    assert [(depth, replay) for depth, replay, _ in calls["runs"]] == [("deep", False), ("deep", True)]
    assert calls["runs"][0][2] == calls["runs"][1][2]
    assert report["second_run"]["trace_file"].endswith(client.TRACE_2_FILENAME)


def test_quick_runs_once(monkeypatch, tmp_path):
    runs = []

    async def fake_run(params, server, errlog, session, inputs_mode):
        runs.append(server)
        return session

    monkeypatch.setattr(client, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(sandbox, "detect_multiarch", lambda: "aarch64-linux-gnu")
    monkeypatch.setattr(client, "parse_trace_file", lambda *a, **k: ([], False))
    monkeypatch.setattr(client, "run", fake_run)
    report = client.run_sandboxed(PROJECT_ROOT / "test_servers" / "good_notes_server.py",
                                  PROJECT_ROOT / "policies" / "notes_readonly.yaml")
    assert len(runs) == 1 and "stability" not in report and "second_run" not in report
    assert not any(line.startswith("Stability") for line in summary_lines(report))
