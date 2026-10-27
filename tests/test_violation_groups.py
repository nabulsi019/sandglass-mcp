"""Report noise (#141): network violations grouped per domain, lookup and address.

tests/data/wikipedia_network_trace.txt holds lines copied verbatim from a real
`sandglass scan pypi:wikipedia-mcp@2.0.1 --policy policies/templates/no_network.v1.yaml`
trace (ARM Mac, OrbStack; reports/ is not in git): the launch, the filter
self-test, the sink's and the relay's launch and markers (with the
nameservers the sink read from /etc/resolv.conf), every connect(), the ::1
bind, and the exits. Syscall lines only: strace prints no environment
(just "/* 0 vars */"), and no file contents.
"""

from pathlib import Path

import pytest

from sandglass import PROJECT_ROOT, netsink
from sandglass.client import _scan_policy
from sandglass.compare import (NAME_LOOKUPS, _markdown, build_report, compare, group_violations,
                               summary_lines)
from sandglass.trace_parser import parse_trace
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, SINK_LINES, run, sandbox_policy

WIKIPEDIA = (Path(__file__).parent / "data" / "wikipedia_network_trace.txt").read_text(encoding="utf-8")
NO_NETWORK = PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml"
SESSION = {"tools": [{"name": "get_article"}],
           "calls": [{"tool": "get_article", "arguments": {}, "status": "OK", "result": "x"}]}


def wikipedia(extra_after_last_connect: list[str] = (), drop_resolvers: bool = False) -> dict:
    """The wikipedia lines as a report, optionally with lines added after the
    last connect(), or without the sink's nameserver report."""
    lines = WIKIPEDIA.splitlines()
    if drop_resolvers:
        lines = [line for line in lines if netsink.RESOLVER_MARKER_DIR not in line]
    last = max(i for i, line in enumerate(lines) if "connect(" in line)
    lines = lines[:last + 1] + list(extra_after_last_connect) + lines[last + 1:]
    policy = _scan_policy(NO_NETWORK, "/package/site/bin/wikipedia-mcp", "aarch64-linux-gnu", "python")
    result = compare(parse_trace("\n".join(lines)), policy, SESSION)
    return build_report("wikipedia", "t", policy, SESSION, result, Path("trace.txt"), {},
                        {"name": "b", "file": "f", "multiarch": "m"})


def entries(report: dict) -> list[tuple[str, int]]:
    return [(g["label"], g["count"]) for g in report["violation_groups"]]


# --- the real wikipedia-mcp trace -------------------------------------------------

def test_wikipedia_becomes_one_domain_and_one_name_lookups_entry():
    report = wikipedia()
    assert report["verdict"] == "VIOLATIONS", report["incomplete_reasons"]
    assert report["resolvers"] == ["0.250.250.200"]
    # 13 proxy requests + 128 connects to port 53 + 2 nscd connects. (The
    # ::1 bind is in the trace too, but not a violation since #142.)
    assert len(report["violations"]) == 143  # every raw event stays in the JSON
    assert entries(report) == [("domain en.wikipedia.org", 13), (NAME_LOOKUPS, 130)]
    lookups = report["violation_groups"][1]["breakdown"]
    assert lookups == {"nscd socket (ENOENT)": 2, "port 53 at 0.250.250.200 (ENETUNREACH)": 128}
    # The groups cover every event exactly once.
    assert sorted(i for g in report["violation_groups"] for i in g["events"]) == list(range(143))


def test_the_wikipedia_summary_lines():
    lines = summary_lines(wikipedia())
    assert lines[0] == "Verdict: VIOLATIONS  (violations: 143 in 2 entries, attempted: 0, probes: 0)"
    assert lines[1].startswith("  VIOLATION domain en.wikipedia.org ×13 (CONNECT :443 ×13), ")
    assert lines[2].startswith(f"  VIOLATION {NAME_LOOKUPS} ×130 (nscd socket (ENOENT) ×2, "
                               "port 53 at 0.250.250.200 (ENETUNREACH) ×128), ")
    assert lines[1].endswith(", tool-call") and len(lines) == 3


DIRECT_DNS = ('13    02:34:20.400000 connect(8<socket:[1]>, {sa_family=AF_INET, sin_port=htons(53), '
              'sin_addr=inet_addr("6.6.6.6")}, 16) = -1 ENETUNREACH (Network is unreachable)')


def test_dns_to_another_address_is_its_own_entry():
    report = wikipedia([DIRECT_DNS])
    assert entries(report) == [("domain en.wikipedia.org", 13), (NAME_LOOKUPS, 130),
                               ("direct DNS to 6.6.6.6:53 (bypasses the system resolver)", 1)]


def test_unknown_resolvers_never_merge_port_53():
    # Without the sink's report, no port-53 address is called a name lookup:
    # each is its own entry (only the nscd socket is still a lookup).
    report = wikipedia([DIRECT_DNS], drop_resolvers=True)
    assert report["resolvers"] is None
    labels = entries(report)
    assert (NAME_LOOKUPS, 2) in labels
    assert [label for label, _ in labels if label.startswith("port 53 to ")] == [
        "port 53 to 0.250.250.200 (the container's resolver could not be read, so not grouped as name lookups)",
        "port 53 to 6.6.6.6 (the container's resolver could not be read, so not grouped as name lookups)"]
    assert "**unknown**" in _markdown(report)


def test_the_markdown_uses_the_same_entries():
    md = _markdown(wikipedia())
    tool_calls = md[md.index("### Tool calls"):md.index("## Programs run")]
    assert "1. **domain en.wikipedia.org** ×13" in tool_calls
    assert f"2. **{NAME_LOOKUPS}** ×130" in tool_calls
    assert "3. " not in tool_calls
    assert "- Nameservers in the container's resolv.conf: `0.250.250.200`" in md
    assert "| `en.wikipedia.org` | 443 | CONNECT | **no** | tool-call | 13 |" in md


# --- grouping rules, from hand-written records ----------------------------------------

def record(syscall: str, target: str, phase: str = "tool-call", error: str | None = None) -> dict:
    return {"syscall": syscall, "target": target, "phase": phase, "error": error, "timestamp": "t",
            "mode": "domain" if syscall == "proxy request" else None}


def connect(address: str, port: int) -> dict:
    return record("connect", f'{{sa_family=AF_INET, sin_port=htons({port}), sin_addr=inet_addr("{address}")}}',
                  error="ENETUNREACH")


def test_two_domains_stay_two_entries_and_phases_are_separate():
    groups = group_violations([record("proxy request", "a.example"), record("proxy request", "b.example"),
                               record("proxy request", "a.example"),
                               record("proxy request", "a.example", phase="startup")], [], [])
    assert [(g["label"], g["phase"], g["count"]) for g in groups] == [
        ("domain a.example", "tool-call", 2), ("domain b.example", "tool-call", 1),
        ("domain a.example", "startup", 1)]


def test_a_non_dns_connect_is_its_own_entry():
    groups = group_violations([connect("10.0.0.53", 53), connect("8.8.8.8", 443), connect("10.0.0.53", 53),
                               connect("8.8.8.8", 443), connect("8.8.4.4", 443)], [], ["10.0.0.53"])
    assert [(g["label"], g["count"]) for g in groups] == [
        (NAME_LOOKUPS, 2), ("connect AF_INET 8.8.8.8:443", 2), ("connect AF_INET 8.8.4.4:443", 1)]


def test_files_and_programs_are_never_grouped():
    read = {**record("openat", "/etc/passwd"), "mode": "read"}
    groups = group_violations([read, read, record("execve", "/bin/sh")], [], [])
    assert [g["count"] for g in groups] == [1, 1, 1]


def test_a_one_event_entry_prints_as_before():
    result = run([LAUNCH, '8 10:00:00.5 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3', EXITED])
    report = build_report("x", "t", sandbox_policy(), SESSION, result, Path("trace.txt"), {},
                          {"name": "b", "file": "f", "multiarch": "m"})
    lines = summary_lines(report)
    assert lines[0].startswith("Verdict: VIOLATIONS  (violations: 1 in 1 entry, ")
    assert lines[1] == "  VIOLATION openat /etc/passwd at 10:00:00.5"
    assert "1. **read outside allowed paths**: `/etc/passwd`" in _markdown(report)


# --- the sink's nameserver report ---------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("nameserver 0.250.250.200\n", ["0.250.250.200"]),
    ("# comment\nnameserver 10.0.0.2\nnameserver fe80::1%eth0\nsearch x\n", ["10.0.0.2", "fe80::1"]),
    ("nameserver ../../etc\nnameserver 1.2.3.4/x\noptions ndots:0\n", []),  # never into a marker path
    ("", []),
])
def test_nameservers_are_read_from_resolv_conf(text, expected):
    assert netsink.nameservers(text) == expected


SINK_RESOLV_READ = '9 10:00:00.000075 openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY|O_CLOEXEC) = 3</etc/resolv.conf>'


def resolver_marker(pid: int, name: str) -> str:
    return (f'{pid} 10:00:00.000076 newfstatat(AT_FDCWD, "{netsink.RESOLVER_MARKER_DIR}/{name}", '
            "0x7ffe, 0) = -1 ENOENT (No such file or directory)")


def with_sink_report(report: list[str], after_ready: list[str] = ()) -> dict:
    """A run whose sink (pid 9) does `report` just before its ready marker."""
    lines = [LAUNCH] + SINK_LINES[:-1] + report + SINK_LINES[-1:] + list(after_ready) + [NOTE_READ, EXITED]
    return run(lines, sink=False)


def test_the_sinks_resolv_conf_read_before_ready_is_not_a_violation():
    # notes_readonly doesn't allow reading /etc/resolv.conf; the sink's own
    # read, before "ready", is skipped like its other startup events.
    result = with_sink_report([SINK_RESOLV_READ, resolver_marker(9, "nameserver/10.0.0.2"),
                               resolver_marker(9, "done")])
    assert result["verdict"] == "CLEAN", (result["violations"], result["incomplete_reasons"])
    assert result["resolvers"] == ["10.0.0.2"]


def test_the_sinks_report_after_ready_does_not_count():
    # After "ready" the server's code runs: a read there is judged, and
    # nameserver markers there are ignored (resolvers unknown).
    result = with_sink_report([], after_ready=[SINK_RESOLV_READ, resolver_marker(9, "nameserver/6.6.6.6"),
                                               resolver_marker(9, "done")])
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [("read", "/etc/resolv.conf")]
    assert result["resolvers"] is None


def test_an_unreadable_resolv_conf_means_unknown():
    assert with_sink_report([resolver_marker(9, "unreadable")])["resolvers"] is None


def test_a_server_reading_resolv_conf_is_judged_and_its_markers_ignored():
    result = run([LAUNCH, SINK_RESOLV_READ.replace("9 ", "8 ", 1), resolver_marker(8, "nameserver/6.6.6.6"),
                  resolver_marker(8, "done"), EXITED])
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [("read", "/etc/resolv.conf")]
    assert result["resolvers"] is None  # only the sink's report counts
