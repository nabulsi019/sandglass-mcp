"""Normal runtime behaviour is not a violation; its dangerous neighbours are (#142).

The harmless lines are copied from real traces (the #25 scans and
test_servers/runtime_noise_server.py); each neighbour is one step further and
must still be caught. Hand-written traces, so no Docker.
"""

import pytest

from sandglass.policy import PolicyError, _exec_exact
from tests.test_policy_templates import template
from tests.test_sandbox_pipeline import EXITED, LAUNCH, run, sandbox_policy

UNAME_NOTE = "Python's platform module (platform.processor()) (baseline: python312_slim)"


def judged(*lines: str, policy=None) -> dict:
    """Compare a run with these server lines (pid 8) under notes_readonly."""
    return run([LAUNCH, *(f"8  10:00:00.5 {line}" for line in lines), EXITED], policy=policy)


def violations(result: dict) -> list[tuple]:
    return [(v["syscall"], v["mode"], v["target"]) for v in result["violations"]]


# --- harmless: not violations ------------------------------------------------------

DEV_NULL_RDWR = 'openat(AT_FDCWD</package>, "/dev/null", O_RDWR|O_CLOEXEC) = 5</dev/null>'
OVERCOMMIT_READ = ('openat(AT_FDCWD</project>, "/proc/sys/vm/overcommit_memory", O_RDONLY|O_CLOEXEC)'
                   ' = 3</proc/sys/vm/overcommit_memory>')
IPV6_PROBE = ('bind(3<socket:[22946]>, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), '
              'inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0')
IPV4_PROBE = ('bind(3<socket:[22947]>, {sa_family=AF_INET, sin_port=htons(0), '
              'sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
UNAME_P = 'execve("/usr/bin/uname", ["uname", "-p"], 0xaaaaf4f1a420 /* 18 vars */) = 0'


@pytest.mark.parametrize("line", [
    DEV_NULL_RDWR,
    'openat(AT_FDCWD, "/dev/null", O_WRONLY|O_CLOEXEC) = 5</dev/null>',
    'openat(AT_FDCWD, "/dev/null", O_RDONLY|O_CLOEXEC) = 5</dev/null>',  # already allowed before #142
    OVERCOMMIT_READ,
    IPV6_PROBE,
    IPV4_PROBE,
])
def test_normal_runtime_behaviour_is_clean(line):
    result = judged(line)
    assert result["verdict"] == "CLEAN", (result["violations"], result["incomplete_reasons"])


def test_uname_p_is_a_program_run_with_the_baseline_note_not_a_violation():
    result = judged(UNAME_P)
    assert result["verdict"] == "CLEAN"
    assert [(p["argv"], p["note"]) for p in result["programs"] if p["path"] == "/usr/bin/uname"] == [
        (["uname", "-p"], UNAME_NOTE)]


# --- the dangerous neighbours: still caught -----------------------------------------

@pytest.mark.parametrize("line, expected", [
    # Other /dev files, read or written.
    ('openat(AT_FDCWD, "/dev/mem", O_RDONLY|O_CLOEXEC) = 3</dev/mem>', ("openat", "read", "/dev/mem")),
    ('openat(AT_FDCWD, "/dev/mem", O_RDWR|O_CLOEXEC) = 3</dev/mem>', ("openat", "write", "/dev/mem")),
    ('openat(AT_FDCWD, "/dev/zero", O_WRONLY|O_CLOEXEC) = 3</dev/zero>', ("openat", "write", "/dev/zero")),
    # write_exact is exact: not a prefix of other names.
    ('openat(AT_FDCWD, "/dev/null2", O_WRONLY|O_CREAT|O_CLOEXEC, 0666) = 3</dev/null2>',
     ("openat", "write", "/dev/null2")),
    # Writing /proc/sys: the baseline only allows the overcommit READ.
    ('openat(AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_WRONLY|O_CLOEXEC) = 3</proc/sys/vm/overcommit_memory>',
     ("openat", "write", "/proc/sys/vm/overcommit_memory")),
    # Other /proc/sys reads are judged by the policy (notes_readonly: no).
    ('openat(AT_FDCWD, "/proc/sys/kernel/hostname", O_RDONLY|O_CLOEXEC) = 3</proc/sys/kernel/hostname>',
     ("openat", "read", "/proc/sys/kernel/hostname")),
    # A real port, any address, or another loopback address.
    ('bind(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
     ("bind", None, '{sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}')),
    ('bind(3<socket:[1]>, {sa_family=AF_INET6, sin6_port=htons(8080), sin6_flowinfo=htonl(0), '
     'inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0',
     ("bind", None, '{sa_family=AF_INET6, sin6_port=htons(8080), sin6_flowinfo=htonl(0), '
                    'inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}')),
    ('bind(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("0.0.0.0")}, 16) = 0',
     ("bind", None, '{sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("0.0.0.0")}')),
    ('bind(3<socket:[1]>, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), '
     'inet_pton(AF_INET6, "::", &sin6_addr), sin6_scope_id=0}, 28) = 0',
     ("bind", None, '{sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), '
                    'inet_pton(AF_INET6, "::", &sin6_addr), sin6_scope_id=0}')),
    ('bind(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.2")}, 16) = 0',
     ("bind", None, '{sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.2")}')),
    # listen() and connect() on their own.
    ("listen(3<socket:[1]>, 128) = 0", ("listen", None, "3, 128")),
    ('connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16)'
     " = -1 ENETUNREACH (Network is unreachable)",
     ("connect", None, '{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}')),
    # uname with other arguments, uname from another path, uname through a shell.
    ('execve("/usr/bin/uname", ["uname", "-a"], 0x0 /* 8 vars */) = 0', ("execve", None, "/usr/bin/uname")),
    ('execve("/usr/bin/uname", ["uname", "-p", "-a"], 0x0 /* 8 vars */) = 0', ("execve", None, "/usr/bin/uname")),
    ('execve("/tmp/uname", ["uname", "-p"], 0x0 /* 8 vars */) = 0', ("execve", None, "/tmp/uname")),
    ('execve("/bin/sh", ["sh", "-c", "uname -p"], 0x0 /* 8 vars */) = 0', ("execve", None, "/bin/sh")),
])
def test_dangerous_neighbours_are_still_violations(line, expected):
    result = judged(line)
    assert result["verdict"] == "VIOLATIONS"
    assert violations(result) == [expected]


def test_dev_tcp_is_never_allowed():
    # /dev/tcp is a bash feature, not a file: the open fails, and is listed
    # as an attempt (like any failed open), never allowed silently.
    result = judged('openat(AT_FDCWD, "/dev/tcp/1.2.3.4/80", O_RDWR|O_CLOEXEC) = -1 ENOENT (No such file or directory)')
    assert [(a["mode"], a["target"]) for a in result["attempted"]][-1:] == [("write", "/dev/tcp/1.2.3.4/80")]


def test_a_loopback_port_0_bind_that_then_listens_is_a_violation():
    # Same socket (inode 22946): the bind AND the listen are violations.
    result = judged(IPV6_PROBE, "listen(3<socket:[22946]>, 128) = 0")
    assert [(s, t[:24]) for s, _, t in violations(result)] == [
        ("bind", "{sa_family=AF_INET6, sin"), ("listen", "3, 128")]


def test_a_listen_on_another_socket_does_not_taint_the_probe():
    result = judged(IPV6_PROBE, "listen(4<socket:[99]>, 128) = 0")
    assert [s for s, _, _ in violations(result)] == ["listen"]


def test_the_probe_socket_connecting_out_is_still_caught():
    connect = ('connect(3<socket:[22946]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), '
               'inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (x)')
    result = judged(IPV6_PROBE, connect)
    assert [s for s, _, _ in violations(result)] == ["connect"]


def test_other_proc_sys_reads_follow_the_policy():
    # no_network.v1 reads anywhere but /home and /root: the policy decides.
    line = 'openat(AT_FDCWD, "/proc/sys/kernel/hostname", O_RDONLY|O_CLOEXEC) = 3</proc/sys/kernel/hostname>'
    assert judged(line, policy=template("no_network"))["verdict"] == "CLEAN"
    assert judged(line)["verdict"] == "VIOLATIONS"


# --- loading the baseline -------------------------------------------------------------

def test_the_baseline_exact_entries_load():
    policy = sandbox_policy()
    assert policy.baseline_write_exact == ["/dev/null"]
    assert policy.baseline_exec_exact == [
        {"path": "/usr/bin/uname", "argv": ["uname", "-p"], "note": UNAME_NOTE}]
    assert "/proc/sys/vm/overcommit_memory" in map(str, policy.baseline_read_allow)


@pytest.mark.parametrize("entry", [
    "/usr/bin/uname",                                     # not a mapping
    {"path": "/usr/bin/uname", "why": "x"},               # no argv
    {"path": "/usr/bin/uname", "argv": "uname -p", "why": "x"},  # argv not a list
    {"path": "/usr/bin/uname", "argv": ["uname", 1], "why": "x"},
    {"path": "/usr/bin/uname", "argv": ["uname", "-p"]},  # no reason
])
def test_bad_exec_exact_entries_are_refused(entry):
    with pytest.raises(PolicyError):
        _exec_exact({"exec_exact": [entry]}, "b")
