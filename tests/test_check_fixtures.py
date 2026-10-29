"""scripts/check_fixtures.py itself: a mismatch must be reported, never crash (#101).

No Docker: run_sandboxed is replaced by a function that returns reports.
"""

import contextlib
import importlib.util

from sandglass import PROJECT_ROOT

spec = importlib.util.spec_from_file_location("check_fixtures", PROJECT_ROOT / "scripts" / "check_fixtures.py")
check_fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_fixtures)


def fake_report(violations):
    return {"verdict": "VIOLATIONS", "violations": violations, "domains": [],
            "network_isolation": {"isolated": True, "outcome": "ENETUNREACH"}}


def test_mixed_exec_and_file_violations_are_a_fail_not_a_crash(monkeypatch, capsys):
    # A regression: an exec (mode None) AND a file read in the same run.
    mixed = [{"mode": None, "target": "/bin/sh", "phase": "tool-call"},
             {"mode": "read", "target": "/lib/libx.so", "phase": "tool-call"}]
    monkeypatch.setattr(check_fixtures, "run_sandboxed", lambda server, policy, *setup: fake_report(mixed))
    # The scans (#19) too: no building, no Docker.
    monkeypatch.setattr(check_fixtures, "build_test_packages", lambda: None)
    monkeypatch.setattr(check_fixtures, "run_scan", lambda spec, policy, registry: fake_report(mixed))
    # The local npm registry (#138) too: no Docker.
    monkeypatch.setattr(check_fixtures, "local_npm_registry", lambda: contextlib.nullcontext([]))
    assert check_fixtures.main() == 1
    out = capsys.readouterr().out
    # Every fixture was still checked, and the summary was printed.
    assert out.count("=====") >= 2 * (len(check_fixtures.EXPECTED) + 1)
    assert "FAIL shell_command_server.py: expected VIOLATIONS [(None, '/bin/sh')]" in out


def test_in_order_sorts_none_modes_first():
    assert check_fixtures.in_order({("read", "/b"), (None, "/a"), ("list", "/c")}) == [
        (None, "/a"), ("list", "/c"), ("read", "/b")]
