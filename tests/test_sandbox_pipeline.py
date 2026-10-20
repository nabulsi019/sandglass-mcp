"""Unit tests for the sandbox pipeline: strace parsing, policy comparison, verdicts.

These use small hand-written strace lines, so they run without Docker.
"""

from pathlib import PurePosixPath as P

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
    '9  10:00:00.000050 newfstatat(AT_FDCWD, "/sandglass-netsink/ready", 0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)',
]


def run(lines, session=SESSION_OK, sink=True, policy=None):
    """Compare a hand-written trace. Unless sink=False, the sink's startup lines
    are slipped in right after the first line (the launch), like in a real run."""
    if sink and lines:
        lines = lines[:1] + SINK_LINES + lines[1:]
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
    # In main(): fd 2 swapped and fd 3 closed before the sink starts, before
    # site.main() (which runs .pth files) and before the server itself runs.
    main = sandbox.LAUNCHER[sandbox.LAUNCHER.index("def main()"):]
    order = ["os.dup2(3, 2)", "os.close(3)", "sys.path[0] =", "start_sink(",
             "site.main()", "runpy.run_path("]
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
        "first_timestamp": "10:00:00.2",
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
