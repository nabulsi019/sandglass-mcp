"""The quick scan (the default) must keep its behaviour (#170).

Deep scans (#170 onwards) add budgets, sample files, repeated calls, a
second run and an observation window, all behind --deep. This file freezes
what the quick scan does, so a later deep item can't change it by accident:

  1. the exact `docker run` arguments, for a fixture and for a scan
  2. the exact MCP messages and tool calls against tests/fake_servers/coverage_server.py
  3. the budget: 120 s for all calls, 30 s per call, counted from the start

Report text may change (the depth field and label, #174); behaviour may not.
"""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters

from sandglass import PROJECT_ROOT, client, sandbox

FAKE_SERVER = Path(__file__).parent / "fake_servers" / "coverage_server.py"
# The SDK's own methods, kept before any test wraps them.
original_request, original_notification = ClientSession.send_request, ClientSession.send_notification

# The sh script every quick run starts with (before strace, untraced).
QUICK_SCRIPT = ('mkdir -m 0700 /tmp/work && cd /tmp/work && unset OLDPWD GPG_KEY PYTHON_VERSION PYTHON_SHA256'
                ' && exec strace -f -tt -y -e trace=file,process,network,memfd_create,io_uring_setup,'
                'io_uring_enter,io_uring_register,ptrace,process_vm_readv,process_vm_writev,pidfd_getfd,'
                'unshare,setns,userfaultfd --kill-on-exit -o /proc/self/fd/2 /opt/venv/bin/python -S'
                ' /usr/local/lib/mcp-runtime/run.py "$@" 3>/dev/null')
HARDENING = ["run", "-i", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
             "--user", "10001:10001", "-e", "HOME=/home/sandglass", "--dns", "127.0.0.1", "--dns-search", "."]


def test_fixture_docker_arguments_are_frozen():
    _, args = sandbox.docker_command(PROJECT_ROOT / "test_servers" / "good_notes_server.py", ["--x"], ["FOO"])
    assert args == HARDENING + [
        "-e", "FOO",
        "-v", f"{PROJECT_ROOT}:/project:ro",
        "--mount", "type=tmpfs,destination=/project/reports,tmpfs-mode=0555",
        "-w", "/project", "sandglass-sandbox", "sh", "-c", QUICK_SCRIPT, "launch",
        "/project/test_servers/good_notes_server.py", "python", "", "--x"]


def test_scan_docker_arguments_are_frozen():
    _, args = sandbox.scan_run_command("vol1", "/package/bin/srv", "python", ["--y"], ["BAR"])
    assert args == HARDENING + [
        "-e", "BAR", "-v", "vol1:/package:ro", "-w", "/package", "sandglass-sandbox",
        "sh", "-c", QUICK_SCRIPT, "launch", "/package/bin/srv", "python", "/package/site", "--y"]


def test_the_budget_is_frozen():
    assert client.TIME_BUDGET_SECONDS == 120
    assert client.CALL_TIMEOUT_SECONDS == 30
    assert client.PING_TIMEOUT_SECONDS == 5
    assert client.session_limit("quick") == 120 + 30
    assert client.DEFAULT_DEPTH == "quick"


def run_recorded(monkeypatch, **run_kwargs) -> tuple[dict, list]:
    """One quick session with coverage_server.py; returns (record, every MCP
    request and notification the client sent, by method name)."""
    sent = []

    async def send_request(self, request, *args, **kwargs):
        sent.append(("request", request.method))
        return await original_request(self, request, *args, **kwargs)

    async def send_notification(self, notification, *args, **kwargs):
        sent.append(("notification", notification.method))
        return await original_notification(self, notification, *args, **kwargs)

    monkeypatch.setattr(ClientSession, "send_request", send_request)
    monkeypatch.setattr(ClientSession, "send_notification", send_notification)
    monkeypatch.setattr(client, "CALL_TIMEOUT_SECONDS", 1)  # slow_tool takes 3 s
    params = StdioServerParameters(command=sys.executable, args=[str(FAKE_SERVER)])
    record = asyncio.run(client.run(params, "coverage_server", **run_kwargs))
    return record, sent


def test_quick_calls_and_messages_are_frozen(monkeypatch):
    record, sent = run_recorded(monkeypatch)
    # One call per tool, in the listed order, with the described mode's inputs.
    assert [(c["tool"], c["arguments"], c["status"]) for c in record["calls"]] == [
        ("ok_tool", {"name": "hello"}, "OK"),
        ("error_tool", {"name": "hello"}, "ERROR"),
        ("rejected_tool", {"name": "hello"}, "FAILED"),
        ("pattern_tool", {"code": "ABC"}, "OK"),
        ("slow_tool", {"name": "hello"}, "TIMED OUT"),
    ]
    # The ping after the timeout (#140), and nothing else after the calls.
    assert sent == [("request", "initialize"), ("notification", "notifications/initialized"),
                    ("request", "tools/list")] + [("request", "tools/call")] * 5 + [("request", "ping")]
    # The quick record's shape: no deep-only keys (budget, variants, runs).
    assert set(record) == {"tools", "calls", "skipped", "not_called", "inputs"}
    assert all(set(c) <= {"tool", "arguments", "status", "result", "seconds", "error_code"}
               for c in record["calls"])


def test_explicit_quick_is_the_default(monkeypatch):
    default, sent_default = run_recorded(monkeypatch)
    quick, sent_quick = run_recorded(monkeypatch, depth="quick")
    assert sent_default == sent_quick
    assert ([(c["tool"], c["arguments"]) for c in default["calls"]]
            == [(c["tool"], c["arguments"]) for c in quick["calls"]])


def test_quick_sends_no_observation_marker(monkeypatch):
    # (#175) The observation window is deep only: quick never sends its
    # notification (notifications/roots/list_changed) and never waits.
    record, sent = run_recorded(monkeypatch)
    assert ("notification", "notifications/roots/list_changed") not in sent
    assert "observation" not in record
