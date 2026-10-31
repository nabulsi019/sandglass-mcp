"""(#155) Sandglass's syscall filter in the install phase and the npm download
container, and the four new refused calls (pidfd_getfd, unshare, setns,
userfaultfd).

  - the launcher's --filter-then-exec mode, for real in a child process (Linux)
  - the parser: the new calls are "evasion" events
  - hand-written install traces: the self-test, io_uring, evasions
The old-Docker npm scans run through the real sandbox in scripts/check_fixtures.py.
"""

import platform
import subprocess
import sys

import pytest

from sandglass import PROJECT_ROOT, launcher, sandbox
from sandglass.compare import compare_install
from sandglass.policy import load_install_baseline, load_policy
from sandglass.trace_parser import parse_trace
from tests.test_install import DONE, START, filter_start
from tests.test_sandbox_pipeline import EXITED, LAUNCH, run

POLICY = load_policy(PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml", in_sandbox=True,
                     multiarch="x86_64-linux-gnu", container_script="/package/x/server.js",
                     package_dir="/package")
BASELINE = load_install_baseline("x86_64-linux-gnu")
NEW_CALLS = [
    ('9 10:00:00.4 pidfd_getfd(5, 2, 0) = -1 EPERM (Operation not permitted)', "pidfd_getfd"),
    ('9 10:00:00.4 unshare(CLONE_NEWUSER) = -1 EPERM (Operation not permitted)', "unshare"),
    ('9 10:00:00.4 setns(5, CLONE_NEWNS) = -1 EPERM (Operation not permitted)', "setns"),
    ('9 10:00:00.4 userfaultfd(O_CLOEXEC) = -1 EPERM (Operation not permitted)', "userfaultfd"),
]


def judge_install(lines, start=START):
    events = parse_trace("\n".join([start] + lines + [DONE]), cwd="/package")
    return compare_install(events, POLICY, BASELINE, 0)


def found(result):
    return [(v["mode"], v["target"], v["reason"]) for v in result["violations"]]


# --- the filter itself ----------------------------------------------------------

def test_the_new_calls_are_blocked_on_both_architectures():
    for machine, numbers in launcher.SYSCALLS.items():
        for name in ("pidfd_getfd", "unshare", "setns", "userfaultfd"):
            assert name in launcher.BLOCKED and name in numbers, (machine, name)
    assert launcher.SYSCALLS["x86_64"]["unshare"] == 272 and launcher.SYSCALLS["aarch64"]["unshare"] == 97


def test_filtered_is_an_argv_list_through_the_launcher():
    argv = sandbox.filtered(["npm", "install", "--ignore-scripts"])
    assert argv[:4] == ["/usr/local/bin/python", "-S", "-c", sandbox.LAUNCHER]
    assert argv[4:] == ["--filter-then-exec", "npm", "install", "--ignore-scripts"]


@pytest.mark.skipif(platform.system() != "Linux" or platform.machine() not in launcher.SYSCALLS,
                    reason="the filter is installed only on Linux x86_64 / aarch64 (inside the sandbox)")
def test_filter_then_exec_filters_the_program_it_runs():
    # The launcher in its second mode execs this probe, which must already be filtered.
    probe = """
import ctypes, os
nr = {"x86_64": {"unshare": 272, "setns": 308, "userfaultfd": 323, "pidfd_getfd": 438},
      "aarch64": {"unshare": 97, "setns": 268, "userfaultfd": 282, "pidfd_getfd": 438}}[os.uname().machine]
libc = ctypes.CDLL(None, use_errno=True)
for name, args in (("unshare", (0x10000000,)), ("setns", (0, 0)), ("userfaultfd", (0,)),
                   ("pidfd_getfd", (0, 0, 0))):
    result = libc.syscall(nr[name], *args)
    print(name, result if result >= 0 else -ctypes.get_errno())
"""
    source = (PROJECT_ROOT / "sandglass" / "launcher.py").read_text(encoding="utf-8")
    out = subprocess.run([sys.executable, "-S", "-c", source, "--filter-then-exec",
                          sys.executable, "-c", probe],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split("\n")[:-1] == ["unshare -1", "setns -1", "userfaultfd -1", "pidfd_getfd -1"]


def test_the_new_calls_are_evasion_events():
    events = parse_trace("\n".join(line for line, _ in NEW_CALLS))
    assert [(e.kind, e.target, e.mode, e.succeeded) for e in events] == [
        ("evasion", name, "evade", False) for _, name in NEW_CALLS]


@pytest.mark.parametrize("line, target", NEW_CALLS)
def test_the_new_calls_are_violations_in_the_servers_run(line, target):
    result = run([LAUNCH, line, EXITED])
    assert [(v["mode"], v["target"], v["reason"]) for v in result["violations"]] == [
        ("evade", target, "tried to evade tracing")]


# --- the install phase ----------------------------------------------------------

def test_the_install_self_test_is_not_reported():
    result = judge_install([])
    assert result["incomplete_reasons"] == [] and result["violations"] == [] and result["attempted"] == []


def test_a_missing_install_self_test_is_incomplete():
    start = "\n".join(filter_start(8)[:1] + filter_start(8)[3:])  # the filter's exec and the shell only
    result = judge_install([], start=start)
    assert result["incomplete_reasons"] == [
        "syscall filter not active during install (#155): its self-test before the installer started: "
        "io_uring_setup missing; clone(CLONE_UNTRACED) missing"]


def test_a_self_test_that_worked_is_incomplete():
    lines = filter_start(8)
    lines[1] = lines[1].replace("= -1 EPERM (Operation not permitted)", "= 3<anon_inode:[io_uring]>")
    result = judge_install([], start="\n".join(lines))
    assert any(r.startswith("syscall filter not active during install") and
               "io_uring_setup succeeded instead of being refused (EPERM)" in r
               for r in result["incomplete_reasons"])


def test_a_self_test_after_the_shell_started_does_not_count():
    # Only the filter's own calls before it execs the shell: anything later is the installer's.
    lines = filter_start(8)
    start = "\n".join(lines[:1] + lines[3:] + lines[1:3])
    result = judge_install([], start=start)
    assert any("syscall filter not active during install" in r for r in result["incomplete_reasons"])
    assert ("evade", "clone CLONE_UNTRACED", "install tried to evade tracing") in found(result)


def test_a_refused_io_uring_during_install_is_only_attempted():
    line = '9 10:00:00.4 io_uring_setup(256, {flags=0}) = -1 EPERM (Operation not permitted)'
    result = judge_install([line])
    assert result["incomplete_reasons"] == [] and result["violations"] == []
    assert [(a["syscall"], a["error"]) for a in result["attempted"]] == [("io_uring_setup", "EPERM")]


def test_a_working_io_uring_during_install_is_incomplete():
    line = '9 10:00:00.4 io_uring_setup(256, {flags=0}) = 4<anon_inode:[io_uring]>'
    result = judge_install([line])
    assert any(r.startswith("io_uring was available") for r in result["incomplete_reasons"])


@pytest.mark.parametrize("line, target", NEW_CALLS + [
    ('9 10:00:00.4 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = -1 EPERM (Operation not permitted)',
     "clone CLONE_UNTRACED"),
    ('9 10:00:00.4 ptrace(PTRACE_ATTACH, 1) = -1 EPERM (Operation not permitted)', "ptrace PTRACE_ATTACH"),
    ('9 10:00:00.4 process_vm_readv(1, NULL, 0, NULL, 0, 0) = -1 EPERM (Operation not permitted)',
     "process_vm_readv"),
])
def test_a_refused_evasion_during_install_is_a_violation(line, target):
    result = judge_install([line])
    assert found(result) == [("evade", target, "install tried to evade tracing")]
    assert result["incomplete_reasons"] == []  # refused: nothing got away
