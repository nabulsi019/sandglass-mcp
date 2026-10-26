"""Sandglass's own syscall filter (#84): the BPF program, the kernel, the verdicts.

  - the BPF program is run through a tiny interpreter (no kernel needed)
  - on Linux, the filter is installed for real in a child Python process
  - hand-written traces: the self-test, attempts to evade tracing
The hostile fixtures (untraced_clone_server, iouring_node_server.js,
ptrace_server) run through the real sandbox in scripts/check_fixtures.py.
"""

import platform
import struct
import subprocess
import sys

import pytest

from sandglass import PROJECT_ROOT, launcher
from sandglass.compare import compare_install
from sandglass.policy import load_install_baseline, load_policy
from sandglass.trace_parser import parse_trace
from tests.test_install import DONE, START
from tests.test_sandbox_pipeline import EXITED, LAUNCH, SELF_TEST, TOOL_CALL, run

ALLOW, ERRNO = 0x7FFF0000, 0x00050000
EPERM, ENOSYS = ERRNO | 1, ERRNO | 38


def evaluate(program, nr: int, arch: int, arg0: int = 0) -> int:
    """Run classic BPF over a struct seccomp_data, like the kernel would."""
    data = struct.pack("<iIQ6Q", nr, arch, 0, arg0, 0, 0, 0, 0, 0)
    a, pc = 0, 0
    while True:
        code, jt, jf, k = program[pc]
        if code == 0x20:                       # A = data[k] (32 bits)
            a = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code in (0x15, 0x35, 0x45):       # jeq / jge / jset
            taken = {0x15: a == k, 0x35: a >= k, 0x45: bool(a & k)}[code]
            pc += 1 + (jt if taken else jf)
        elif code == 0x06:                     # return k
            return k
        else:
            raise AssertionError(f"unknown instruction {code:#x}")


@pytest.mark.parametrize("machine", sorted(launcher.SYSCALLS))
def test_the_bpf_program_blocks_exactly_what_it_should(machine):
    program = launcher._bpf_program(machine)
    nr, arch = launcher.SYSCALLS[machine], launcher.AUDIT_ARCH[machine]
    assert all(0 <= jt < 256 and 0 <= jf < 256 for _, jt, jf, _ in program)
    for name in launcher.BLOCKED:                                 # io_uring, ptrace, process_vm
        assert evaluate(program, nr[name], arch) == EPERM, name
    assert evaluate(program, nr["clone3"], arch) == ENOSYS        # flags unreadable: fall back to clone
    untraced = launcher.CLONE_UNTRACED | launcher.SIGCHLD
    assert evaluate(program, nr["clone"], arch, untraced) == EPERM
    assert evaluate(program, nr["clone"], arch, launcher.SIGCHLD) == ALLOW   # fork()
    assert evaluate(program, nr["clone"], arch, 0x3D0F00) == ALLOW            # a thread
    for other in (0, 1, 2, 3, 59, 257, 221, 435 - 1):             # read, write, open, execve, openat...
        assert evaluate(program, other, arch) == ALLOW, other
    # Another ABI (32-bit, or the other architecture's numbers): everything refused.
    assert evaluate(program, 3, 0x40000003) == EPERM              # AUDIT_ARCH_I386
    assert evaluate(program, 0x40000000 + 2, arch) == EPERM       # x32 syscall numbers


@pytest.mark.skipif(platform.system() != "Linux" or platform.machine() not in launcher.SYSCALLS,
                    reason="the filter is installed only on Linux x86_64 / aarch64 (inside the sandbox)")
def test_the_filter_works_in_the_real_kernel():
    # In a child process: the filter can't be removed once installed.
    probe = """
import ctypes, os, threading, subprocess, sys
from sandglass import launcher
launcher.install_syscall_filter()
libc = ctypes.CDLL(None, use_errno=True)
nr = launcher.SYSCALLS[os.uname().machine]
def call(*args):
    result = libc.syscall(*args)
    return result if result >= 0 else -ctypes.get_errno()
print("io_uring_setup", call(nr["io_uring_setup"], 1, ctypes.create_string_buffer(120)))
print("untraced", call(nr["clone"], launcher.CLONE_UNTRACED | launcher.SIGCHLD, 0, 0, 0, 0))
print("clone3", call(nr["clone3"], 0, 0))
print("ptrace", call(nr["ptrace"], 16, os.getppid(), 0, 0))
t = threading.Thread(target=lambda: None); t.start(); t.join()            # threads still work
print("subprocess", subprocess.run(["true"]).returncode)                  # so do children
pid = os.fork()
if pid == 0:
    os._exit(7)
print("fork", os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
"""
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                         cwd=PROJECT_ROOT, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split("\n")[:-1] == [
        "io_uring_setup -1", "untraced -1", "clone3 -38", "ptrace -1", "subprocess 0", "fork 7"]


def test_seccomp_unconfined_never_appears_in_the_product():
    # The old-Docker simulation (scripts/check_fixtures.py) is test code only.
    for path in (PROJECT_ROOT / "sandglass").rglob("*"):
        if path.is_file() and path.suffix in (".py", ".yaml"):
            assert "unconfined" not in path.read_text(encoding="utf-8"), path


# --- the parser --------------------------------------------------------------

def test_evasion_events():
    trace = "\n".join([
        '8 10:00:00.1 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = -1 EPERM (Operation not permitted)',
        '8 10:00:00.2 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f) = 12',
        '8 10:00:00.3 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x7f, stack_size=0x9000}, 88) = -1 ENOSYS (Function not implemented)',
        '8 10:00:00.4 clone3({flags=CLONE_UNTRACED, exit_signal=SIGCHLD}, 88) = 13',
        '8 10:00:00.5 ptrace(PTRACE_ATTACH, 1) = -1 EPERM (Operation not permitted)',
        '8 10:00:00.6 process_vm_writev(1, NULL, 0, NULL, 0, 0) = -1 EPERM (Operation not permitted)',
    ])
    assert [(e.kind, e.target, e.mode, e.succeeded) for e in parse_trace(trace)] == [
        ("evasion", "clone CLONE_UNTRACED", "evade", False),
        ("evasion", "clone3 CLONE_UNTRACED", "evade", True),   # plain clone/clone3: not events
        ("evasion", "ptrace PTRACE_ATTACH", "evade", False),
        ("evasion", "process_vm_writev", "evade", False),
    ]


# --- the self-test ------------------------------------------------------------

def reasons(result) -> str:
    return " | ".join(result["incomplete_reasons"])


def test_a_working_self_test_is_not_reported():
    result = run([LAUNCH, EXITED])
    assert result["verdict"] == "CLEAN"
    assert result["attempted"] == [] and result["violations"] == []


def test_a_missing_self_test_is_incomplete():
    result = run([LAUNCH, EXITED], self_test=False)
    assert result["verdict"] == "INCOMPLETE"
    assert ("Sandglass's syscall filter is not active (#84): its self-test before the server started: "
            "io_uring_setup missing; clone(CLONE_UNTRACED) missing") in reasons(result)


@pytest.mark.parametrize("line, problem", [
    ('8  10:00:00.000002 io_uring_setup(1, {flags=0}) = 3', "io_uring_setup succeeded"),
    ('8  10:00:00.000003 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = 9', "clone(CLONE_UNTRACED) succeeded"),
    ('8  10:00:00.000003 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = -1 ENOSYS (Function not implemented)',
     "clone(CLONE_UNTRACED) failed with ENOSYS"),
])
def test_a_self_test_that_got_through_is_incomplete(line, problem):
    # Docker < 25 without Sandglass's filter: the self-test's calls work.
    kept = [l for l in SELF_TEST if l.split()[2].split("(")[0] != line.split()[2].split("(")[0]]
    result = run([LAUNCH, EXITED], self_test=kept + [line])
    assert result["verdict"] == "INCOMPLETE" and problem in reasons(result)


def test_the_server_cant_fake_the_self_test():
    # The same two refused calls, but from the server after the sink is ready: they
    # don't count as the self-test (missing), and the clone is an attempt to evade.
    late = [l.replace("10:00:00.00000", "10:00:00.20000") for l in SELF_TEST]
    result = run([LAUNCH] + late + [EXITED], self_test=False)
    assert "io_uring_setup missing; clone(CLONE_UNTRACED) missing" in reasons(result)
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [("evade", "clone CLONE_UNTRACED")]


# --- attempts to evade tracing ----------------------------------------------------

BLOCKED_CLONE = '14 10:00:00.3 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = -1 EPERM (Operation not permitted)'
WORKED_CLONE = '14 10:00:00.3 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = 15'


def test_a_refused_untraced_clone_is_a_violation():
    result = run([LAUNCH, TOOL_CALL, BLOCKED_CLONE, EXITED])
    assert result["verdict"] == "VIOLATIONS"
    [v] = result["violations"]
    assert (v["mode"], v["target"], v["reason"], v["phase"]) == (
        "evade", "clone CLONE_UNTRACED", "tried to evade tracing", "tool-call")


def test_an_untraced_child_that_got_away_makes_the_run_incomplete():
    result = run([LAUNCH, WORKED_CLONE, EXITED])
    assert result["verdict"] == "INCOMPLETE"
    assert "a process got out of strace's sight" in reasons(result)
    assert [v["target"] for v in result["violations"]] == ["clone CLONE_UNTRACED"]


@pytest.mark.parametrize("line, target", [
    ('14 10:00:00.3 ptrace(PTRACE_ATTACH, 1) = -1 EPERM (Operation not permitted)', "ptrace PTRACE_ATTACH"),
    ('14 10:00:00.3 ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)', "ptrace PTRACE_TRACEME"),
    ('14 10:00:00.3 process_vm_readv(1, NULL, 0, NULL, 0, 0) = -1 EPERM (Operation not permitted)', "process_vm_readv"),
])
def test_ptrace_and_process_vm_are_violations_under_any_policy(line, target):
    # Even when the policy allows everything else, e.g. "read anywhere".
    from tests.test_policy_templates import template
    result = run([LAUNCH, line, EXITED], policy=template("no_network"))
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [("evade", target)]


def test_an_install_script_that_evades_is_caught_too():
    policy = load_policy(PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml", in_sandbox=True,
                         multiarch="x86_64-linux-gnu", container_script="/package/x/server.js",
                         package_dir="/package")
    line = '9 10:00:00.4 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = 15'
    events = parse_trace("\n".join([START, line, DONE]), cwd="/package")
    result = compare_install(events, policy, load_install_baseline("x86_64-linux-gnu"), 0)
    assert [(v["mode"], v["target"], v["reason"]) for v in result["violations"]] == [
        ("evade", "clone CLONE_UNTRACED", "install tried to evade tracing")]
    assert any("out of strace's sight" in r for r in result["incomplete_reasons"])
