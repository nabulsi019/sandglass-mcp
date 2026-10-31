"""(#147) compare.py's rules for the DNS recorder: trust, names, allow rules,
grouping, the fail-closed INCOMPLETE reasons and the report's lines.

Hand-written traces, no Docker. The recorder itself is in tests/test_dns_sink.py;
the real run is dns_fetch_server.js in scripts/check_fixtures.py.
"""

from pathlib import Path

from sandglass import dnssink, launcher
from sandglass.compare import NAME_LOOKUPS, _markdown, build_report, compare
from sandglass.trace_parser import parse_trace
from tests.test_policy_templates import template
from tests.test_sandbox_pipeline import (DNS_LINES, EXITED, LAUNCH, RELAY_END, RELAY_START, SELF_TEST,
                                         SINK_LINES, TOOL_CALL)

# The sink's nameserver report (#141): resolv.conf names the recorder.
RESOLVER = [
    '9  10:00:00.000046 newfstatat(AT_FDCWD, "/sandglass-resolver/nameserver/127.0.0.1", 0x7f, 0) = -1 ENOENT (No such file or directory)',
    '9  10:00:00.000047 newfstatat(AT_FDCWD, "/sandglass-resolver/done", 0x7f, 0) = -1 ENOENT (No such file or directory)',
]
NSCD = ('8  10:00:00.300000 connect(5<socket:[3]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)'
        ' = -1 ENOENT (No such file or directory)')
TO_RECORDER = ('8  10:00:00.300100 connect(5<socket:[4]>, {sa_family=AF_INET, sin_port=htons(53), '
               'sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
REPLY = ('6  10:00:00.300300 sendto(3<UDP:[1]>, "\\x12\\x34", 37, 0, {sa_family=AF_INET, sin_port=htons(40000), '
         'sin_addr=inet_addr("127.0.0.1")}, 16) = 37')
DIRECT_DNS = ('8  10:00:00.300400 connect(6<socket:[5]>, {sa_family=AF_INET, sin_port=htons(53), '
              'sin_addr=inet_addr("6.6.6.6")}, 16) = -1 ENETUNREACH (Network is unreachable)')
DNS_EXIT = "6  10:00:01.300000 +++ exited with 0 +++"


def query(name: str, qtype: str = "A", pid: int = 6, time: str = "10:00:00.300200") -> str:
    """The recorder's marker for one query."""
    return (f'{pid}  {time} newfstatat(AT_FDCWD, "/sandglass-dns/{qtype}/{name}", 0x7f, 0)'
            " = -1 ENOENT (No such file or directory)")


def trace(server_lines: list[str], dns: bool = True, after_exit: list[str] = (), before_exit: list[str] = ()):
    """A full run: launch, self-test, the recorder (unless dns=False), the
    sink with its nameserver report, the relay, then `server_lines` during
    the tool calls, the relay's end and the server's exit."""
    sink = SINK_LINES[len(DNS_LINES):]
    return ([LAUNCH] + SELF_TEST + (DNS_LINES if dns else []) + sink[:-1] + RESOLVER + sink[-1:]
            + RELAY_START + [TOOL_CALL] + server_lines + RELAY_END + list(before_exit) + [EXITED]
            + list(after_exit))


SESSION = {"tools": [{"name": "fetch"}],
           "calls": [{"tool": "fetch", "arguments": {}, "status": "OK", "result": "x"}]}


def judge(lines: list[str], policy_name: str = "no_network") -> dict:
    policy = template(policy_name)
    result = compare(parse_trace("\n".join(lines)), policy, SESSION)
    return build_report("x", "t", policy, SESSION, result, Path("trace.txt"), {},
                        {"name": "b", "file": "f", "multiarch": "m"})


def entries(report: dict) -> list[tuple[str, int, dict]]:
    return [(g["label"], g["count"], g["breakdown"]) for g in report["violation_groups"]]


def test_the_ready_fd_matches_the_launcher():
    assert dnssink.READY_FD == launcher.DNS_READY_FD
    assert launcher.DNS_SCRIPT == "/usr/local/lib/mcp-runtime/dns.py"


def test_a_clean_run_with_the_recorder_is_clean():
    report = judge(trace([]))
    assert report["verdict"] == "CLEAN" and report["dns_names"] == []
    assert any("/usr/local/lib/mcp-runtime/dns.py" in str(p["argv"]) and p["note"] == "Sandglass's DNS recorder"
               for p in report["programs"])


def test_one_name_takes_its_lookup_steps_into_its_domain_entry():
    report = judge(trace([NSCD, TO_RECORDER, query("hidden.example"),
                          query("hidden.example", "AAAA", time="10:00:00.300250"), REPLY]))
    assert report["verdict"] == "VIOLATIONS", report["incomplete_reasons"]
    assert [(d["name"], d["qtype"], d["phase"]) for d in report["dns_names"]] == [
        ("hidden.example", "A", "tool-call"), ("hidden.example", "AAAA", "tool-call")]
    assert entries(report) == [("domain hidden.example", 4, {
        "nscd socket (ENOENT)": 1, "port 53 at 127.0.0.1": 1, "DNS lookup A": 1, "DNS lookup AAAA": 1})]
    # The recorder's reply is its own event, never a violation.
    assert all(v["pid"] == 8 or v["syscall"] == "dns query" for v in report["violations"])
    assert ("- `hidden.example` (tool-call, **not allowed**): looked up (DNS: A, AAAA), "
            "not contacted (answered NXDOMAIN)") in _markdown(report)


def test_several_names_share_one_lookups_entry():
    report = judge(trace([NSCD, TO_RECORDER, query("a.example"), query("b.example")]))
    labels = [label for label, _, _ in entries(report)]
    assert labels == ["name lookups for a.example, b.example", "domain a.example", "domain b.example"]


def test_without_a_name_the_lookups_say_so():
    report = judge(trace([NSCD]))
    assert entries(report) == [(NAME_LOOKUPS, 1, {"nscd socket (ENOENT)": 1})]
    assert NAME_LOOKUPS == "name lookups: no name recorded"


def test_direct_dns_elsewhere_is_unchanged():
    report = judge(trace([DIRECT_DNS, query("x.example")]))
    labels = [label for label, _, _ in entries(report)]
    assert "direct DNS to 6.6.6.6:53 (bypasses the system resolver)" in labels


def test_a_listed_domain_is_allowed_with_its_lookup_steps():
    policy = template("listed_domains_only")
    allowed = policy.allow_domains[0].removeprefix("*.")
    report = judge(trace([TO_RECORDER, query(allowed)]), "listed_domains_only")
    assert report["verdict"] == "CLEAN", (report["incomplete_reasons"], report["violations"])
    assert [d["allowed"] for d in report["dns_names"]] == [True]
    # Another name is still a violation, its step to the recorder is not.
    report = judge(trace([TO_RECORDER, query(allowed), query("other.example")]), "listed_domains_only")
    assert [(v["syscall"], v["target"]) for v in report["violations"]] == [("dns query", "other.example")]
    assert "also requested" not in _markdown(report)


def test_markers_from_another_process_are_not_names():
    # The server stats a marker path itself: just a probe, never a recorded name.
    report = judge(trace([query("fake.example", pid=8)]))
    assert report["dns_names"] == [] and report["verdict"] == "CLEAN"


def test_an_unreadable_query_is_a_violation_under_no_network():
    report = judge(trace([TO_RECORDER, query("_invalid_", qtype="_invalid_")]))
    assert [(v["syscall"], v["target"]) for v in report["violations"]][-1] == (
        "dns query", "(unreadable DNS query)")


def test_the_recorder_never_started_is_incomplete():
    report = judge(trace([], dns=False))
    assert report["verdict"] == "INCOMPLETE"
    assert report["incomplete_reasons"] == [
        "the DNS recorder never started, so names the server looked up can't be recorded"]


def test_the_recorder_stopping_before_the_server_is_incomplete():
    report = judge(trace([], before_exit=['6  10:00:00.950000 +++ killed by SIGKILL +++']))
    assert report["incomplete_reasons"] == [
        "the DNS recorder stopped before the server did (killed by SIGKILL); "
        "names looked up after that weren't recorded"]
    # Stopping after the server exited is the normal end.
    assert judge(trace([], after_exit=[DNS_EXIT]))["verdict"] == "CLEAN"


def test_lookups_that_reached_the_recorder_without_a_name_are_incomplete():
    report = judge(trace([TO_RECORDER]))
    assert report["verdict"] == "INCOMPLETE"
    assert report["incomplete_reasons"] == [
        "name lookups reached the DNS recorder (1 connect(s) or send(s) to 127.0.0.1:53) "
        "but it recorded no name"]


def test_a_request_through_the_proxy_too_shows_both():
    sink_request = ('9  10:00:00.300500 newfstatat(AT_FDCWD, "/sandglass-netsink/CONNECT/both.example/443",'
                    ' 0x7f, 0) = -1 ENOENT (No such file or directory)')
    connect = ('8  10:00:00.300450 connect(7<socket:[6]>, {sa_family=AF_INET, sin_port=htons(18080), '
               'sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
    report = judge(trace([TO_RECORDER, query("both.example"), connect, sink_request]))
    entry = [e for e in entries(report) if e[0] == "domain both.example"][0]
    assert entry[2] == {"CONNECT :443": 1, "port 53 at 127.0.0.1": 1, "DNS lookup A": 1}
    assert "looked up (DNS: A), also requested through the proxy" in _markdown(report)
