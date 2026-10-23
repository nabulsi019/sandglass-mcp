"""The local network sink (sandglass/netsink.py) and how compare.py uses it (#13).

Hand-written strace lines, so no Docker needed. The sink's startup lines
come from tests/test_sandbox_pipeline.py's run() helper.
"""

import errno

import pytest

from sandglass import launcher, netsink
from sandglass.policy import PolicyError, load_policy
from tests.test_sandbox_pipeline import EXITED, LAUNCH, POLICY_FILE, SERVER, run, sandbox_policy

import yaml


def sink_request(method, host, port, pid=9):
    """The stat() the sink makes for one request."""
    return (f'{pid}  10:00:00.5 newfstatat(AT_FDCWD, "/sandglass-netsink/{method}/{host}/{port}", '
            '0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)')


SERVER_TO_SINK = ('10 10:00:00.4 connect(5, {sa_family=AF_INET, sin_port=htons(18080), '
                  'sin_addr=inet_addr("127.0.0.1")}, 16) = 0')


def policy_with_domains(tmp_path, domains):
    data = yaml.safe_load(POLICY_FILE.read_text())
    data["network"]["allow_domains"] = domains
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data))
    return load_policy(path, server_script=SERVER, in_sandbox=True, multiarch="x86_64-linux-gnu")


# --- the sink's request parsing ------------------------------------------------

@pytest.mark.parametrize("data, expected", [
    (b"GET http://undeclared.example/x HTTP/1.1\r\nHost: undeclared.example\r\n\r\n",
     ("GET", "undeclared.example", 80)),
    (b"CONNECT api.Example.com:443 HTTP/1.1\r\n\r\n", ("CONNECT", "api.example.com", 443)),
    (b"POST http://localhost:8000/ HTTP/1.1\r\n\r\n", ("POST", "localhost", 8000)),
    (b"GET http://../etc/x HTTP/1.1\r\n\r\n", ("GET", "_invalid_", 80)),      # no ".." in the marker
    (b"GET http://a/b/c HTTP/1.1\r\n\r\n", ("GET", "a", 80)),
    (b"GET http://evil.com%2F..%2F HTTP/1.1\r\n\r\n", ("GET", "_invalid_", 80)),
    (b"GET http://_dmarc.Example.com/ HTTP/1.1\r\n\r\n", ("GET", "_dmarc.example.com", 80)),
    (b"CONNECT my_host.internal:8443 HTTP/1.1\r\n\r\n", ("CONNECT", "my_host.internal", 8443)),
    (b"GET http://a..b/ HTTP/1.1\r\n\r\n", ("GET", "_invalid_", 80)),       # empty label
    (b"GET http://_..%2F/ HTTP/1.1\r\n\r\n", ("GET", "_invalid_", 80)),
    (b"garbage", ("_invalid_", "_invalid_", 0)),
    (b"", ("_invalid_", "_invalid_", 0)),
])
def test_parse_request(data, expected):
    assert netsink.parse_request(data) == expected


def test_launcher_and_sink_agree():
    assert launcher.SINK_URL == netsink.SINK_URL
    assert launcher.SINK_READY_FD == netsink.READY_FD


# --- compare: domains --------------------------------------------------------

def test_undeclared_domain_is_one_violation_naming_it():
    result = run([LAUNCH, SERVER_TO_SINK, sink_request("GET", "undeclared.example", 80), EXITED])
    assert result["verdict"] == "VIOLATIONS"
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [("domain", "undeclared.example")]
    assert result["domains"] == [{"method": "GET", "host": "undeclared.example", "port": 80,
                                  "allowed": False, "timestamp": "10:00:00.5", "phase": "startup"}]


def test_allowed_domains_exact_and_wildcard(tmp_path):
    policy = policy_with_domains(tmp_path, ["api.example.com", "*.trusted.org"])
    lines = [LAUNCH, SERVER_TO_SINK,
             sink_request("CONNECT", "api.example.com", 443),
             sink_request("GET", "cdn.trusted.org", 80),
             sink_request("GET", "trusted.org", 80),          # bare domain is NOT *.trusted.org
             sink_request("GET", "eviltrusted.org", 80),      # suffix must start at a dot
             EXITED]
    result = run(lines, policy=policy)
    assert [d["allowed"] for d in result["domains"]] == [True, True, False, False]
    assert sorted(v["target"] for v in result["violations"]) == ["eviltrusted.org", "trusted.org"]


def test_underscore_host_is_recorded_by_name():
    result = run([LAUNCH, SERVER_TO_SINK, sink_request("GET", "_dmarc.example.com", 80), EXITED])
    assert [d["host"] for d in result["domains"]] == ["_dmarc.example.com"]
    assert [v["target"] for v in result["violations"]] == ["_dmarc.example.com"]


def test_bad_allow_domains_entry(tmp_path):
    with pytest.raises(PolicyError, match="not a host name"):
        policy_with_domains(tmp_path, ["https://example.com"])


def test_sink_startup_is_not_a_violation_and_isolation_is_reported():
    result = run([LAUNCH, EXITED])
    assert result["verdict"] == "CLEAN"
    assert result["network_isolation"]["isolated"] is True
    assert result["network_isolation"]["outcome"] == "ENETUNREACH"


@pytest.mark.parametrize("raised, expected", [
    (OSError(errno.ENETUNREACH, "Network is unreachable"), ("isolated", "ENETUNREACH")),
    (OSError(errno.EHOSTUNREACH, "No route to host"), ("not-isolated", "EHOSTUNREACH")),
    (OSError(errno.ECONNREFUSED, "Connection refused"), ("not-isolated", "ECONNREFUSED")),
    (TimeoutError("timed out"), ("not-isolated", "timeout")),
    (OSError("no errno"), ("not-isolated", "unknown-error")),
    (None, ("not-isolated", "connected")),  # the connect worked
])
def test_isolation_result_is_decided_after_the_connect_finished(raised, expected):
    def connect():
        if raised is not None:
            raise raised
    assert netsink.isolation_result(connect) == expected


def test_server_cannot_forge_sink_records():
    # The same stat, but from the server's pid: just a probe, no domain event.
    result = run([LAUNCH, sink_request("GET", "allowed-by-forgery.com", 80, pid=10), EXITED])
    assert result["domains"] == []
    assert result["verdict"] == "CLEAN"


def test_server_cannot_become_the_sink_with_a_late_ready_marker():
    # The real sink (pid 9) stats "ready" first; a later one from pid 10 changes nothing.
    fake_ready = '10 10:00:00.6 newfstatat(AT_FDCWD, "/sandglass-netsink/ready", 0x7f, 0) = -1 ENOENT (No such file or directory)'
    public = ('10 10:00:00.7 connect(4, {sa_family=AF_INET, sin_port=htons(80), '
              'sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network is unreachable)')
    result = run([LAUNCH, fake_ready, public, EXITED])
    assert [v["syscall"] for v in result["violations"]] == ["connect"]


def test_failed_connect_to_the_sink_is_a_violation():
    # e.g. the server killed the sink first, so nothing would record the domain.
    refused = ('10 10:00:00.4 connect(5, {sa_family=AF_INET, sin_port=htons(18080), '
               'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)')
    result = run([LAUNCH, refused, EXITED])
    assert result["verdict"] == "VIOLATIONS"


def test_direct_connect_to_a_public_ip_is_still_a_violation():
    public = ('10 10:00:00.4 connect(5, {sa_family=AF_INET, sin_port=htons(443), '
              'sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ENETUNREACH (Network is unreachable)')
    result = run([LAUNCH, public, EXITED])
    assert [v["pid"] for v in result["violations"]] == [10]


# --- compare: the run can't be trusted without the sink -----------------------

def test_missing_sink_is_incomplete():
    result = run([LAUNCH, EXITED], sink=False)
    assert result["verdict"] == "INCOMPLETE"
    assert any("network sink did not start" in r for r in result["incomplete_reasons"])


# --- the isolation check (#100): only the sink's own report counts ------------

ISOLATION_CONNECT_IN_PROGRESS = ('9  10:00:00.1 connect(1, {sa_family=AF_INET, sin_port=htons(443), '
                                 'sin_addr=inet_addr("1.1.1.1")}, 16) = -1 EINPROGRESS (Operation now in progress)')
SINK_READY_LINE = '9  10:00:00.3 newfstatat(AT_FDCWD, "/sandglass-netsink/ready", 0x7f, 0) = -1 ENOENT (No such file or directory)'


def isolation_marker(result, outcome, pid=9, time="10:00:00.2"):
    return (f'{pid}  {time} newfstatat(AT_FDCWD, "/sandglass-isolation/{result}/{outcome}", 0x7f, 0)'
            ' = -1 ENOENT (No such file or directory)')


def sink_run(*sink_lines):
    """A run whose sink startup is exactly these lines (instead of SINK_LINES)."""
    return run([LAUNCH, *sink_lines, EXITED], sink=False)


@pytest.mark.parametrize("outcome", ["connected", "timeout", "ECONNREFUSED", "EHOSTUNREACH"])
def test_not_isolated_is_incomplete(outcome):
    # A host with a route out: the connect's first errno is EINPROGRESS, which
    # used to read as "failed, so isolated". Only the sink's report counts now.
    result = sink_run(ISOLATION_CONNECT_IN_PROGRESS, isolation_marker("not-isolated", outcome), SINK_READY_LINE)
    assert result["verdict"] == "INCOMPLETE"
    assert any(r.startswith("the sandbox may reach the internet") and outcome in r
               for r in result["incomplete_reasons"])
    assert result["network_isolation"]["isolated"] is False


def test_missing_isolation_result_is_incomplete():
    result = sink_run(ISOLATION_CONNECT_IN_PROGRESS, SINK_READY_LINE)
    assert result["verdict"] == "INCOMPLETE"
    assert "the network isolation result is missing from the trace" in result["incomplete_reasons"]


def test_isolation_result_from_another_process_or_after_ready_is_ignored():
    forged = isolation_marker("isolated", "ENETUNREACH", pid=10)                 # the server's pid
    late = isolation_marker("isolated", "ENETUNREACH", time="10:00:00.4")       # the sink, after ready
    result = sink_run(ISOLATION_CONNECT_IN_PROGRESS, forged, SINK_READY_LINE, late)
    assert result["verdict"] == "INCOMPLETE"
    assert result["network_isolation"] is None
