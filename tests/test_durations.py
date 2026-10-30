"""Durations (#156): total and per-phase wall-clock seconds in every report.

A fake clock that only moves when a (faked) step runs, so each phase gets an
exact, known duration. Durations are reported, never judged.
"""

import asyncio
import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from sandglass import PROJECT_ROOT, client, sandbox, scan
from sandglass.compare import _markdown, duration_line, summary_lines

POLICY = PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml"
FIXTURE = PROJECT_ROOT / "test_servers" / "good_notes_server.py"
FAKE_SERVER = Path(__file__).parent / "fake_servers" / "coverage_server.py"


class FakeClock:
    """time.monotonic stand-in: moves only when told to."""

    def __init__(self):
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def takes(self, seconds: float, result=None):
        """A fake step that takes `seconds` and returns `result`."""
        def step(*args, **kwargs):
            self.now += seconds
            return result
        return step


@pytest.fixture
def fake_clock(monkeypatch, tmp_path):
    clock = FakeClock()
    monkeypatch.setattr(client, "clock", clock)
    monkeypatch.setattr(client, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(sandbox, "detect_multiarch", clock.takes(0.25, "aarch64-linux-gnu"))
    return clock


# --- the Durations record ------------------------------------------------------------

def test_phases_that_did_not_happen_are_none_not_zero(fake_clock):
    d = client.Durations()
    with d.phase("run"):
        fake_clock.now += 10.804
    with d.phase("analysis"):
        fake_clock.now += 1.0
    with d.phase("analysis"):  # added up, e.g. the install's trace and the server's
        fake_clock.now += 0.5
    assert d.record() == {"total": 12.3, "download": None, "install": None, "run": 10.8, "analysis": 1.5}


def test_a_phase_that_raises_still_counts(fake_clock):
    d = client.Durations()
    with pytest.raises(scan.ScanError):
        with d.phase("download"):
            fake_clock.now += 3.1
            raise scan.ScanError("package hash mismatch")
    assert d.record()["download"] == 3.1


# --- fixture mode: run and analysis only ----------------------------------------------

def test_fixture_mode_has_no_download_or_install(fake_clock, monkeypatch):
    async def fake_run(params, server, errlog, session, inputs_mode):
        fake_clock.now += 10.8
        return session
    monkeypatch.setattr(client, "run", fake_run)
    monkeypatch.setattr(client, "parse_trace_file", fake_clock.takes(1.5, ([], False)))
    report = client.run_sandboxed(FIXTURE, POLICY)
    assert report["durations"] == {"total": 12.55, "download": None, "install": None,
                                   "run": 10.8, "analysis": 1.5}
    # Never judged: an empty trace is INCOMPLETE whatever the durations.
    assert report["verdict"] == "INCOMPLETE"


# --- scan mode: every phase, and the null cases ---------------------------------------

@pytest.fixture
def fake_scan(fake_clock, monkeypatch):
    """A scan whose download takes 3.1 s and install 6.0 s (exit code 0)."""
    hash_ok = {"file": "x.whl", "source": "PyPI", "algorithm": "sha256", "ours": "a",
               "published": "a", "match": True}
    monkeypatch.setattr(scan, "download", fake_clock.takes(3.0, object()))
    monkeypatch.setattr(scan, "describe_files", lambda prepared: [])
    monkeypatch.setattr(scan, "verify_hash", fake_clock.takes(0.1, hash_ok))
    monkeypatch.setattr(scan, "choose_entry", lambda prepared, entry: ("x", "/package/site/bin/x"))
    monkeypatch.setattr(sandbox, "create_volume", lambda name: None)
    monkeypatch.setattr(sandbox, "remove_volume", lambda name: None)
    monkeypatch.setattr(scan, "install", fake_clock.takes(6.0, 0))
    monkeypatch.setattr(scan, "log_tail", lambda path: "")
    monkeypatch.setattr(client, "parse_trace_file", fake_clock.takes(0.5, ([], False)))

    async def fake_run(params, server, errlog, session, inputs_mode):
        fake_clock.now += 10.8
        return session
    monkeypatch.setattr(client, "run", fake_run)
    return monkeypatch, hash_ok


def test_a_full_scan_has_every_phase(fake_scan):
    report = client.run_scan(scan.parse_spec("pypi:x@1.0"), POLICY)
    # analysis = the install trace (0.5) + the server's trace (0.5)
    assert report["durations"] == {"total": 21.15, "download": 3.1, "install": 6.0,
                                   "run": 10.8, "analysis": 1.0}
    assert summary_lines(report)[-1] == "Duration: 21.1 s (download 3.1, install 6.0, run 10.8, analysis 1.0)"
    assert "- Duration: 21.1 s (download 3.1, install 6.0, run 10.8, analysis 1.0)\n" in _markdown(report)


def test_a_scan_stopped_at_the_hash_check_has_only_download(fake_scan, fake_clock):
    monkeypatch, hash_ok = fake_scan
    monkeypatch.setattr(scan, "verify_hash", fake_clock.takes(0.1, {**hash_ok, "match": False}))
    report = client.run_scan(scan.parse_spec("pypi:x@1.0"), POLICY)
    assert report["verdict"] == "INCOMPLETE"
    assert report["durations"] == {"total": 3.35, "download": 3.1, "install": None,
                                   "run": None, "analysis": None}
    assert summary_lines(report)[-1] == "Duration: 3.4 s (download 3.1)"


def test_a_failed_install_has_no_run(fake_scan, fake_clock):
    monkeypatch, _ = fake_scan
    monkeypatch.setattr(scan, "install", fake_clock.takes(6.0, 1))
    report = client.run_scan(scan.parse_spec("pypi:x@1.0"), POLICY)
    assert report["durations"] == {"total": 9.85, "download": 3.1, "install": 6.0,
                                   "run": None, "analysis": 0.5}


# --- per tool call -----------------------------------------------------------------

def test_each_call_records_its_duration(monkeypatch):
    # A real MCP session with the fake server, on the host, with the real clock.
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 1)
    params = StdioServerParameters(command=sys.executable, args=[str(FAKE_SERVER)])
    record = asyncio.run(client.run(params, "coverage_server"))
    seconds = {c["tool"]: c["seconds"] for c in record["calls"]}
    assert all(s >= 0 for s in seconds.values())
    assert set(seconds) == {"ok_tool", "error_tool", "rejected_tool", "pattern_tool", "slow_tool"}
    assert 1 <= seconds["slow_tool"] < 3  # timed out after the 1 s call timeout


def test_the_coverage_table_shows_each_calls_time():
    report = {"coverage": {"totals": {"ran": 1, "failed": 0, "skipped": 1, "total": 2}, "note": None,
                           "tools": [{"tool": "a", "status": "ran", "reason": None},
                                     {"tool": "b", "status": "skipped", "reason": "no input"}]},
              "exercised": [{"tool": "a", "seconds": 0.123}]}
    from sandglass.compare import _coverage_section
    lines = _coverage_section(report)
    assert "| Tool | Status | Time | Reason |" in lines
    assert "| `a` | ran | 0.12 s |  |" in lines and "| `b` | skipped |  | no input |" in lines


def test_duration_line_leaves_out_phases_that_did_not_happen():
    assert duration_line({"total": 12.34, "download": None, "install": None,
                          "run": 10.8, "analysis": 1.5}) == "Duration: 12.3 s (run 10.8, analysis 1.5)"
