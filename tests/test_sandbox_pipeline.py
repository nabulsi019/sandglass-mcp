"""Unit tests for the sandbox pipeline: strace parsing, policy comparison, verdicts.

These use small hand-written strace lines, so they run without Docker.
"""

from pathlib import PurePosixPath as P

import pytest

from sandglass import PROJECT_ROOT, sandbox
from sandglass.compare import compare
from sandglass.policy import load_policy
from sandglass.trace_parser import parse_trace

POLICY_FILE = PROJECT_ROOT / "policies" / "notes_readonly.yaml"
SERVER = PROJECT_ROOT / "test_servers" / "good_notes_server.py"

# A minimal "complete" run: server launched, one allowed read, clean exit.
LAUNCH = '8  10:00:00.000001 execve("/opt/venv/bin/python", ["python", "/project/test_servers/good_notes_server.py"], 0x0 /* 8 vars */) = 0'
NOTE_READ = '10 10:00:00.000100 openat(AT_FDCWD, "/project/test_servers/allowed_notes/hello.txt", O_RDONLY|O_CLOEXEC) = 8'
EXITED = "8  10:00:01.000000 +++ exited with 0 +++"

SESSION_OK = {"tools": [{"name": "read_note"}], "calls": [{"tool": "read_note"}]}


def sandbox_policy():
    return load_policy(POLICY_FILE, server_script=SERVER, in_sandbox=True,
                       multiarch="x86_64-linux-gnu")


# The local network sink (sandglass/netsink.py) as it shows up in every real
# trace: its own exec, its listening socket, the isolation check, the ready marker.
SINK_LINES = [
    '9  10:00:00.000010 execve("/opt/venv/bin/python", ["/opt/venv/bin/python", "-I", "-S", "-c", "..."], 0x0 /* 0 vars */) = 0',
    '9  10:00:00.000020 bind(0, {sa_family=AF_INET, sin_port=htons(18080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
    '9  10:00:00.000030 listen(0, 16)     = 0',
    '9  10:00:00.000040 connect(1, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ENETUNREACH (Network is unreachable)',
    '9  10:00:00.000045 newfstatat(AT_FDCWD, "/sandglass-isolation/isolated/ENETUNREACH", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)',
    '9  10:00:00.000050 newfstatat(AT_FDCWD, "/sandglass-netsink/ready", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)',
]


# The launcher's self-test of Sandglass's syscall filter (#84), as in every
# real trace: right after the launch (pid 8), before the sink, both refused.
SELF_TEST = [
    '8  10:00:00.000002 io_uring_setup(1, {flags=0, sq_thread_cpu=0, sq_thread_idle=0}) = -1 EPERM (Operation not permitted)',
    '8  10:00:00.000003 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = -1 EPERM (Operation not permitted)',
]


# The stdin relay (sandglass/stdin_relay.py, #91): its exec and ready marker at
# startup, its tool-call marker, and at the end its eof marker and clean exit.
RELAY_START = [
    '7  10:00:00.000060 execve("/opt/venv/bin/python", ["/opt/venv/bin/python", "-I", "-S", "-c", "..."], 0x0 /* 0 vars */) = 0',
    '7  10:00:00.000070 newfstatat(AT_FDCWD, "/sandglass-phase/ready", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)',
]
TOOL_CALL = '7  10:00:00.000500 newfstatat(AT_FDCWD, "/sandglass-phase/tool-call", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)'
RELAY_END = [
    '7  10:00:00.900000 newfstatat(AT_FDCWD, "/sandglass-phase/eof", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)',
    "7  10:00:00.900100 +++ exited with 0 +++",
]


def run(lines, session=SESSION_OK, sink=True, relay=True, policy=None, self_test=True):
    """Compare a hand-written trace, with Sandglass's helpers added like in a
    real run (unless sink=False / relay=False / self_test=False): the filter
    self-test, the sink's and the relay's startup lines right after the first
    line (the launch), then at the end the relay's tool-call marker (unless
    the test placed its own TOOL_CALL), its eof marker and its exit. So by
    default every event is in "startup"."""
    if lines and relay:
        end = ([] if TOOL_CALL in lines else [TOOL_CALL]) + RELAY_END
        lines = lines[:1] + RELAY_START + lines[1:] + end
    if sink and lines:
        lines = lines[:1] + SINK_LINES + lines[1:]
    if self_test and lines:  # True: the usual self-test; or a list of lines to use instead
        lines = lines[:1] + (SELF_TEST if self_test is True else self_test) + lines[1:]
    return compare(parse_trace("\n".join(lines)), policy or sandbox_policy(), session)


# --- trace_parser ----------------------------------------------------------

def test_parser_modes_and_failures():
    events = parse_trace("\n".join([
        '8 10:00:00.1 openat(AT_FDCWD, "/a", O_RDONLY) = 3',
        '8 10:00:00.2 openat(AT_FDCWD, "/b", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3',
        '8 10:00:00.3 openat(AT_FDCWD, "/c", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3',
        '8 10:00:00.4 openat(AT_FDCWD, "/d", O_RDONLY) = -1 ENOENT (No such file or directory)',
        '8 10:00:00.5 openat(AT_FDCWD, "rel.txt", O_RDONLY) = 3',
    ]))
    assert [(e.target, e.mode, e.succeeded, e.error) for e in events] == [
        ("/a", "read", True, None),
        ("/b", "write", True, None),
        ("/c", "list", True, None),
        ("/d", "read", False, "ENOENT"),
        ("/project/rel.txt", "read", True, None),  # relative -> joined with cwd
    ]


def test_parser_stitches_unfinished_and_resumed_lines():
    events = parse_trace("\n".join([
        '9  10:00:00.1 openat(AT_FDCWD, "/secret", O_RDONLY <unfinished ...>',
        '10 10:00:00.2 openat(AT_FDCWD, "/other", O_RDONLY) = 4',
        '9  10:00:00.3 <... openat resumed>) = 3',
    ]))
    by_pid = {e.pid: e for e in events}
    assert by_pid[9].target == "/secret" and by_pid[9].succeeded
    assert by_pid[10].target == "/other"
    # The evidence is the whole call, not just the "<... resumed>" half.
    assert by_pid[9].raw == '9  10:00:00.1 openat(AT_FDCWD, "/secret", O_RDONLY) = 3'


def test_parser_network_ignores_sendto_without_address():
    events = parse_trace("\n".join([
        '8 10:00:00.1 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ENETUNREACH (Network is unreachable)',
        '8 10:00:00.2 sendto(5, "\\0", 1, 0, NULL, 0) = 1',  # asyncio socketpair wake-up
    ]))
    assert [(e.kind, e.syscall) for e in events] == [("network", "connect")]



def test_parser_sendmmsg_counts_only_with_an_address():
    events = parse_trace("\n".join([
        # A datagram to 8.8.8.8 sent with sendmmsg: recorded, like sendmsg.
        '8 10:00:00.1 sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="x", iov_len=1}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=1}], 1, 0) = -1 ENETUNREACH (Network is unreachable)',
        # glibc's resolver on an already connected UDP socket: no address, skipped.
        '8 10:00:00.2 sendmmsg(4, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="y", iov_len=1}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=1}], 1, MSG_NOSIGNAL) = 1',
    ]))
    assert [(e.kind, e.syscall, e.succeeded) for e in events] == [("network", "sendmmsg", False)]
    assert 'inet_addr("8.8.8.8")' in events[0].target


@pytest.mark.parametrize("escaped, expected", [
    (r"/tmp/caf\303\251", "/tmp/café"),        # strace's default: octal, one per byte
    (r"/tmp/caf\xc3\xa9", "/tmp/café"),        # the same bytes with strace -x
    (r"/tmp/\342\202\254", "/tmp/€"),          # 3-byte UTF-8 character
    (r'/tmp/a\"b', '/tmp/a"b'),
    (r"/tmp/a\\b", "/tmp/a\\b"),
    (r"/tmp/a\nb", "/tmp/a\nb"),
    (r"/tmp/bad\377", "/tmp/bad\\xff"),        # not valid UTF-8: stays visible
])
def test_parser_unescape_rebuilds_utf8_bytes(escaped, expected):
    events = parse_trace(f'8 10:00:00.1 openat(AT_FDCWD, "{escaped}", O_RDONLY) = 3')
    assert events[0].target == expected


@pytest.mark.parametrize("path, expected", [
    ("//etc/passwd", "/etc/passwd"),
    ("///etc/passwd", "/etc/passwd"),
    ("/etc//./passwd", "/etc/passwd"),
    ("notes//hello.txt", "/project/notes/hello.txt"),  # relative: joined with the cwd
])
def test_parser_collapses_leading_slashes(path, expected):
    events = parse_trace(f'8 10:00:00.1 openat(AT_FDCWD, "{path}", O_RDONLY) = 3')
    assert events[0].target == expected


def test_parser_keeps_paths_strace_could_not_read():
    # strace shows memory it can't read as a bare address. Never drop these (#98).
    events = parse_trace("\n".join([
        '8 10:00:00.1 openat(AT_FDCWD, 0xffff83995370, O_RDONLY|O_CLOEXEC) = 3',
        '8 10:00:00.2 newfstatat(AT_FDCWD, 0xffff83995370, 0xffffc0de0000, 0) = 0',
        '8 10:00:00.3 unlink(0xffff83995370) = 0',
        # Two paths, one unreadable: not silently judged by the readable one.
        '8 10:00:00.4 rename("/tmp/a", 0xffff83995370) = 0',
    ]))
    assert [(e.kind, e.target, e.mode) for e in events] == [
        ("file", "<unreadable>", "read"),
        ("probe", "<unreadable>", None),
        ("file", "<unreadable>", "write"),
        ("file", "<unreadable>", "write"),
    ]


def test_parser_null_and_fd_only_paths_are_not_unreadable():
    events = parse_trace("\n".join([
        '8 10:00:00.1 openat(AT_FDCWD, NULL, O_RDONLY) = -1 EFAULT (Bad address)',
        '8 10:00:00.2 newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=10, ...}, AT_EMPTY_PATH) = 0',
        '8 10:00:00.3 newfstatat(AT_FDCWD, "/etc/x", 0xffffc0de0000, 0) = -1 ENOENT (No such file or directory)',
    ]))
    assert [(e.kind, e.target) for e in events] == [("probe", "/etc/x")]


def test_parser_memfd_create_is_a_write_to_memfd_name():
    events = parse_trace("\n".join([
        '8 10:00:00.1 memfd_create("payload", MFD_CLOEXEC) = 5',
        '8 10:00:00.2 memfd_create("", 0) = -1 EMFILE (Too many open files)',
    ]))
    assert [(e.kind, e.target, e.mode, e.succeeded) for e in events] == [
        ("file", "memfd:payload", "write", True),
        ("file", "memfd:", "write", False),
    ]


# --- compare: verdicts -------------------------------------------------------

def test_clean_run():
    result = run([LAUNCH, NOTE_READ, EXITED])
    assert result["verdict"] == "CLEAN"


def test_truncated_trace_is_incomplete_never_clean():
    # Same run, but strace was killed before writing "+++ exited".
    result = run([LAUNCH, NOTE_READ])
    assert result["verdict"] == "INCOMPLETE"
    assert any("truncated" in r for r in result["incomplete_reasons"])


def test_empty_trace_and_failed_session_are_incomplete():
    result = run([], session={"tools": [], "calls": [], "error": "server exited"})
    assert result["verdict"] == "INCOMPLETE"


def test_incomplete_wins_over_violations():
    secret = '10 10:00:00.2 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
    result = run([LAUNCH, secret])  # violation, but no exit record
    assert result["verdict"] == "INCOMPLETE"
    assert len(result["violations"]) == 1  # still reported as evidence


# --- compare: rules ---------------------------------------------------------

def test_failed_open_is_attempted_but_eacces_is_violation():
    result = run([
        LAUNCH,
        '10 10:00:00.2 openat(AT_FDCWD, "/home/x/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
        '10 10:00:00.3 openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = -1 EACCES (Permission denied)',
        EXITED,
    ])
    assert [a["target"] for a in result["attempted"]] == ["/home/x/.ssh/id_rsa"]
    assert [v["target"] for v in result["violations"]] == ["/root/.aws/credentials"]


def test_double_slash_paths_match_the_policy_like_the_kernel_sees_them():
    # The kernel opens "//x" as "/x": an allowed note stays allowed, and
    # /etc/passwd is reported under its real name.
    result = run([
        LAUNCH,
        '10 10:00:00.2 openat(AT_FDCWD, "//project/test_servers/allowed_notes/hello.txt", O_RDONLY) = 8',
        '10 10:00:00.3 openat(AT_FDCWD, "//etc/passwd", O_RDONLY) = 3',
        EXITED,
    ])
    assert [v["target"] for v in result["violations"]] == ["/etc/passwd"]


def test_failed_network_attempt_is_violation():
    result = run([
        LAUNCH,
        '8 10:00:00.2 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH (Network is unreachable)',
        EXITED,
    ])
    assert result["verdict"] == "VIOLATIONS"


def test_baseline_and_runtime_allow_reads_but_never_writes():
    reads = [
        '8 10:00:00.2 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3',
        '8 10:00:00.3 openat(AT_FDCWD, "/opt/venv/lib/python3.12/site-packages/mcp/__init__.py", O_RDONLY) = 3',
    ]
    writes = [
        '8 10:00:00.4 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_WRONLY|O_TRUNC) = 3',
        '8 10:00:00.5 openat(AT_FDCWD, "/opt/venv/lib/python3.12/site-packages/mcp/__init__.py", O_RDWR) = 3',
        '8 10:00:00.6 unlink("/usr/local/lib/python3.12/os.py") = 0',
    ]
    result = run([LAUNCH, *reads, *writes, EXITED])
    assert sorted(v["target"] for v in result["violations"]) == sorted([
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/opt/venv/lib/python3.12/site-packages/mcp/__init__.py",
        "/usr/local/lib/python3.12/os.py",
    ])
    assert all(v["mode"] == "write" for v in result["violations"])


def test_exact_server_dir_entry_allows_only_that_listing():
    result = run([
        LAUNCH,
        '8 10:00:00.2 openat(AT_FDCWD, "/project/test_servers", O_RDONLY|O_DIRECTORY) = 3',
        '8 10:00:00.3 openat(AT_FDCWD, "/project/test_servers/decoy_home", O_RDONLY|O_DIRECTORY) = 3',
        '8 10:00:00.4 openat(AT_FDCWD, "/project/test_servers/decoy_home/.fake_credentials", O_RDONLY) = 3',
        EXITED,
    ])
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [
        ("list", "/project/test_servers/decoy_home"),
        ("read", "/project/test_servers/decoy_home/.fake_credentials"),
    ]


def test_second_exec_is_violation():
    result = run([LAUNCH, '11 10:00:00.2 execve("/bin/sh", ["sh", "-c", "id"], 0x0 /* 8 vars */) = 0', EXITED])
    assert [v["target"] for v in result["violations"]] == ["/bin/sh"]


@pytest.mark.parametrize("line", [
    '8 10:00:00.2 openat(AT_FDCWD, 0xffff83995370, O_RDONLY|O_CLOEXEC) = 3',
    '8 10:00:00.2 newfstatat(AT_FDCWD, 0xffff83995370, 0xffffc0de0000, 0) = 0',
    '7  10:00:00.2 openat(AT_FDCWD, 0xffff83995370, O_RDONLY) = 3',  # from the relay's pid too
])
def test_unreadable_path_makes_the_run_incomplete(line):
    result = run([LAUNCH, NOTE_READ, line, EXITED])
    assert result["verdict"] == "INCOMPLETE"
    [reason] = [r for r in result["incomplete_reasons"] if "couldn't read" in r]
    assert reason.startswith("1 file event(s) with a path strace couldn't read") and "0xffff83995370" in reason
    assert result["violations"] == [] and result["probes"] == []  # never judged as a real path


def test_memfd_create_is_a_violation_and_a_failed_one_is_attempted():
    # A file in memory only: code written there can be exec'd without touching disk.
    result = run([
        LAUNCH,
        '8 10:00:00.2 memfd_create("payload", MFD_CLOEXEC) = 5',
        '8 10:00:00.3 memfd_create("other", 0) = -1 EMFILE (Too many open files)',
        EXITED,
    ])
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [("write", "memfd:payload")]
    assert [a["target"] for a in result["attempted"]] == ["memfd:other"]


# --- Sandglass's helpers are judged except for their known events (#99) ------

# The sink is pid 9 and the relay pid 7 (see SINK_LINES and RELAY_START).
CREDENTIALS_READ = 'openat(AT_FDCWD, "/home/sandglass/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3'
PUBLIC_CONNECT = 'connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network is unreachable)'
SHELL_EXEC = 'execve("/bin/sh", ["sh", "-c", "id"], 0x0 /* 8 vars */) = 0'


@pytest.mark.parametrize("helper_pid", ["7 ", "9 "])
@pytest.mark.parametrize("call, expected", [
    (CREDENTIALS_READ, ("read", "/home/sandglass/.aws/credentials")),
    (PUBLIC_CONNECT, (None, '{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}')),
    (SHELL_EXEC, (None, "/bin/sh")),
])
def test_anything_else_a_helper_does_is_judged_like_the_server(helper_pid, call, expected):
    result = run([LAUNCH, f"{helper_pid} 10:00:00.2 {call}", EXITED])
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [expected]
    assert result["violations"][0]["pid"] == int(helper_pid)


def test_the_sinks_proxy_traffic_is_still_skipped():
    # A proxy client being accepted, and a non-blocking accept with no client yet.
    accepted = '9  10:00:00.3 accept4(0, {sa_family=AF_INET, sin_port=htons(54321), sin_addr=inet_addr("127.0.0.1")}, [16], SOCK_CLOEXEC) = 4'
    no_client = '9  10:00:00.4 accept4(0, 0x7ffd0000, [16], SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable)'
    result = run([LAUNCH, accepted, no_client, EXITED])
    assert result["verdict"] == "CLEAN" and result["violations"] == []


def test_a_helpers_launch_is_only_its_first_event():
    # A second exec of the venv Python by the sink is not its launch.
    again = '9  10:00:00.5 execve("/opt/venv/bin/python", ["python"], 0x0 /* 0 vars */) = 0'
    result = run([LAUNCH, again, EXITED])
    assert [v["target"] for v in result["violations"]] == ["/opt/venv/bin/python"]


# --- io_uring (#75) ------------------------------------------------------------

# As Node's libuv does at every startup (seen in the sandbox image); blocked by
# Docker's default seccomp profile.
IO_URING_BLOCKED = ('8 10:00:00.2 io_uring_setup(256, {flags=IORING_SETUP_NO_SQARRAY, sq_thread_cpu=0, '
                    'sq_thread_idle=0}) = -1 EPERM (Operation not permitted)')
IO_URING_WORKS = ('8 10:00:00.3 io_uring_setup(4, {flags=0, sq_thread_cpu=0, sq_thread_idle=0, '
                  'sq_entries=4, cq_entries=8, features=IORING_FEAT_SINGLE_MMAP}) = 5')


def test_parser_io_uring_events():
    events = parse_trace("\n".join([
        IO_URING_BLOCKED,
        IO_URING_WORKS,
        '8 10:00:00.4 io_uring_enter(5, 1, 1, IORING_ENTER_GETEVENTS, NULL, 8) = 1',
        '8 10:00:00.5 io_uring_register(5, IORING_REGISTER_BUFFERS, 0x7f, 1) = 0',
    ]))
    assert [(e.kind, e.target, e.succeeded, e.error) for e in events] == [
        ("io_uring", "io_uring_setup", False, "EPERM"),
        ("io_uring", "io_uring_setup", True, None),
        ("io_uring", "io_uring_enter", True, None),
        ("io_uring", "io_uring_register", True, None),
    ]


def test_blocked_io_uring_is_attempted_and_the_run_stays_clean():
    # Not a violation even though EPERM: the file rule's EPERM -> VIOLATION would
    # turn every Node server into a violator.
    other_thread = IO_URING_BLOCKED.replace("8 ", "11 ", 1)
    result = run([LAUNCH, IO_URING_BLOCKED, other_thread, EXITED])
    assert result["verdict"] == "CLEAN"
    assert [a["syscall"] for a in result["attempted"]] == ["io_uring_setup", "io_uring_setup"]
    assert "invisible to strace" in result["attempted"][0]["reason"]


def test_working_io_uring_makes_the_run_incomplete():
    result = run([LAUNCH, IO_URING_WORKS,
                  '8 10:00:00.4 io_uring_enter(5, 1, 1, IORING_ENTER_GETEVENTS, NULL, 8) = 1', EXITED])
    assert result["verdict"] == "INCOMPLETE"
    [reason] = [r for r in result["incomplete_reasons"] if "io_uring" in r]
    assert reason.startswith("io_uring was available, file access may be missing from the trace (")
    assert "2 successful io_uring call(s)" in reason and "io_uring_setup(4," in reason
    assert result["violations"] == [] and result["attempted"] == []


# --- policy in sandbox mode ------------------------------------------------

def test_sandbox_placeholders_and_multiarch():
    policy = sandbox_policy()
    assert P("/usr/local") in policy.runtime_allow
    assert P("/opt/venv") in policy.runtime_allow
    assert P("/project/test_servers/good_notes_server.py") in policy.runtime_allow
    assert policy.list_exact == [P("/project/test_servers")]
    assert policy.read_allow == [P("/project/test_servers/allowed_notes")]
    assert policy.baseline_name == "python312_slim"
    assert P("/lib/x86_64-linux-gnu") in policy.baseline_read_allow


def test_base_image_is_pinned_to_a_debian_release():
    # "python:3.12-slim" alone follows whatever Debian release is newest, which
    # can change strace's output format and the files the baselines list (#81).
    from_lines = [line for line in (PROJECT_ROOT / "Dockerfile").read_text().splitlines()
                  if line.startswith("FROM ")]
    assert from_lines == ["FROM python:3.12-slim-trixie"]


def test_strace_records_memfd_create_and_io_uring():
    _, args = sandbox.docker_command(SERVER)
    assert ("-e trace=file,process,network,memfd_create,"
            "io_uring_setup,io_uring_enter,io_uring_register,"
            "ptrace,process_vm_readv,process_vm_writev,"
            "pidfd_getfd,unshare,setns,userfaultfd ") in " ".join(args)  # (#155)


def test_docker_command_is_least_privilege():
    _, args = sandbox.docker_command(SERVER)
    joined = " ".join(args)
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--user 10001:10001" in joined
    assert f"{PROJECT_ROOT}:/project:ro" in joined
    assert "--cap-add" not in joined and "--privileged" not in joined
    assert ".venv" not in joined  # the Mac's venv is never mounted


# --- trace integrity (#47) ---------------------------------------------------

def test_trace_is_never_a_file_in_the_container():
    _, args = sandbox.docker_command(SERVER)
    joined = " ".join(args)
    # No read-write mount at all: the only -v is the read-only project.
    volumes = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
    assert volumes == [f"{PROJECT_ROOT}:/project:ro"]
    # strace writes to its stderr, and the server's stderr is swapped out.
    assert "-o /proc/self/fd/2" in joined and "3>/dev/null" in joined
    assert "--kill-on-exit" in joined
    # reports/ (where the host keeps traces) is covered by an empty read-only tmpfs.
    assert "type=tmpfs,destination=/project/reports,tmpfs-mode=0555" in joined


def test_launcher_closes_the_trace_stream_before_loading_packages():
    # In main(): fd 2 swapped and fd 3 closed before the sink and the stdin
    # relay start, before site.main() (which runs .pth files) and before the
    # server itself runs.
    main = sandbox.LAUNCHER[sandbox.LAUNCHER.index("def main()"):]
    order = ["os.dup2(3, 2)", "os.close(3)", "sys.path[0] =", "start_sink(",
             "start_relay(", "site.main()", "runpy.run_path("]
    positions = [main.index(step) for step in order]
    assert positions == sorted(positions)


UNREADABLE_EXEC = '8  10:00:00.000001 execve(0x7ffdc67270d0, 0x7ffdc6728518, 0x7ffdc6728548) = 0'


def test_unreadable_first_exec_is_the_server_launch():
    # The non-dumpable strace can't read the first execve's arguments.
    result = run([UNREADABLE_EXEC, NOTE_READ, EXITED])
    assert result["verdict"] == "CLEAN"


def test_unreadable_later_exec_is_still_a_violation():
    later = '11 10:00:00.2 execve(0x7ffdc67270d0, 0x7ffdc6728518, 0x7ffdc6728548) = 0'
    result = run([LAUNCH, later, EXITED])
    assert [v["target"] for v in result["violations"]] == ["<unreadable>"]


def test_probes_grouped_by_path_with_counts_per_syscall():
    stat = '8 10:00:00.2 newfstatat(AT_FDCWD, "/project/test_servers", {st_mode=S_IFDIR|0755, ...}, 0) = 0'
    link = '8 10:00:00.3 readlinkat(AT_FDCWD, "/project/test_servers", 0xffff, 4096) = -1 EINVAL (Invalid argument)'
    result = run([LAUNCH, stat, stat, stat, link, EXITED])
    assert result["probes"] == [{
        "path": "/project/test_servers", "count": 4,
        "syscalls": {"newfstatat": 3, "readlinkat": 1},
        "first_timestamp": "10:00:00.2", "phase": "startup",
    }]
    assert result["verdict"] == "CLEAN"  # probes never change the verdict


def test_baseline_covers_cgroup_v1_cpu_quota_reads_only():
    # On cgroup v1 hosts the runtime finds its CPU quota through these three
    # files instead of cgroup v2's cpu.max. Reads are fine; writes are not,
    # and neighbouring files are not covered.
    v1_files = [
        "/proc/self/mountinfo",
        "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
        "/sys/fs/cgroup/cpu/cpu.cfs_period_us",
    ]
    reads = [f'8 10:00:00.2 openat(AT_FDCWD, "{path}", O_RDONLY|O_CLOEXEC) = 3' for path in v1_files]
    assert run([LAUNCH, *reads, EXITED])["verdict"] == "CLEAN"

    write = '8 10:00:00.3 openat(AT_FDCWD, "/sys/fs/cgroup/cpu/cpu.cfs_quota_us", O_WRONLY) = 3'
    neighbour = '8 10:00:00.4 openat(AT_FDCWD, "/proc/self/environ", O_RDONLY) = 3'
    result = run([LAUNCH, write, neighbour, EXITED])
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [
        ("write", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"),
        ("read", "/proc/self/environ"),
    ]
