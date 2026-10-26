"""Runs first inside the sandbox, before the server. Not a module you run yourself.

sandbox.py reads this file ON THE HOST and passes its source to the traced
Python as:

    python -S -c <this source> <server.py> <netsink.py source> <stdin_relay.py source>

so the container never has to read an extra file. In this order it:

  1. (#47) points the server's stderr (fd 2, the trace stream) at /dev/null
     (fd 3, opened by sh) and closes fd 3, so the server can't touch the trace;
  1b. (#84) installs Sandglass's syscall filter (seccomp) on itself, so it
     covers everything started from here on (not strace, our parent), and
     runs its self-test: io_uring, CLONE_UNTRACED clones, ptrace and
     process_vm_* are refused, whatever Docker's own profile allows;
  2. (#13) starts the local network sink (sandglass/netsink.py) as its own
     process and waits until it listens, then points HTTP(S)_PROXY at it;
  3. (#91) starts the stdin relay (sandglass/stdin_relay.py) as its own
     process and makes its output the server's stdin, so the trace marks
     where the tool calls start;
  4. runs the server: a .py server as __main__ in this same Python, after
     loading site-packages (skipped by -S, because .pth files can run code);
     a .js server by exec'ing Node in this same process (#17), so the fds
     stay closed and compare.py sees one extra exec it treats as the launch.
     If a Python server dies with an exception, its message is put into the
     trace (record_server_error, #24), since its stderr is /dev/null.

Until step 4 only frozen stdlib modules (os, sys, runpy, site) are used, so no
package code runs while the trace stream is still reachable. (Step 1b imports
ctypes, after the fd swap, with only the standard library on sys.path.)
"""

import os
import sys

# Must match sandglass/netsink.py (tests/test_network_sink.py checks this).
SINK_URL = "http://127.0.0.1:18080"
SINK_READY_FD = 3
# Must match sandglass/stdin_relay.py (tests/test_phases.py checks this).
RELAY_READY_FD = 3
PYTHON = "/opt/venv/bin/python"
NODE = "/usr/bin/node"  # must match sandglass/sandbox.py CONTAINER_NODE
# (#24) A Python server that dies with an exception: the launcher stat()s
# <this>/<message> (it doesn't exist), so the message lands in the trace.
SERVER_ERROR_DIR = "/sandglass-server-error"
# Characters kept in that message; anything else (including "/") becomes "_".
MESSAGE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:;=_-+'()[]")


def start_sink(source: str) -> None:
    """Start netsink.py as a separate process and wait until it's listening.

    Separate process, not a thread: the server can't patch its memory to stop
    it recording. posix_spawn, not os.fork(): on Python 3.12, os.fork() reads
    /proc/self/stat (thread count), which would show up in every trace.
    """
    ready_r, ready_w = os.pipe()
    os.posix_spawn(PYTHON, [PYTHON, "-I", "-S", "-c", source], {}, file_actions=[
        (os.POSIX_SPAWN_CLOSE, 0),                        # not the MCP stdin...
        (os.POSIX_SPAWN_CLOSE, 1),                        # ...or stdout
        (os.POSIX_SPAWN_DUP2, ready_w, SINK_READY_FD),    # "I'm listening" pipe
    ])
    os.close(ready_w)
    os.read(ready_r, 1)  # b"" if the sink died; compare.py then says it never started
    os.close(ready_r)


def start_relay(source: str) -> None:
    """Start stdin_relay.py as a separate process and make it the server's stdin.

    The relay keeps the client's stdin (fd 0); its stdout (fd 1) becomes a
    pipe, and the read end of that pipe becomes this process's fd 0. os.pipe()
    fds are close-on-exec, so the relay only keeps the ones dup2'd below.
    """
    stdin_r, stdin_w = os.pipe()
    ready_r, ready_w = os.pipe()
    os.posix_spawn(PYTHON, [PYTHON, "-I", "-S", "-c", source], {}, file_actions=[
        (os.POSIX_SPAWN_DUP2, stdin_w, 1),                # relay's output -> server's stdin
        (os.POSIX_SPAWN_DUP2, ready_w, RELAY_READY_FD),   # "I'm running" pipe
    ])
    os.close(stdin_w)
    os.close(ready_w)
    os.read(ready_r, 1)  # b"" if the relay died; compare.py then says it never started
    os.close(ready_r)
    os.dup2(stdin_r, 0)  # the server now reads the client's messages through the relay
    os.close(stdin_r)


# ---------------------------------------------------------------------------
# (#84) Sandglass's own syscall filter: seccomp, installed by this process
# on itself, so it covers the sink, the relay, the server and every process
# they start (filters are inherited and survive exec), but NOT strace, our
# parent, which must keep ptrace. It doesn't depend on Docker's own profile,
# so it works the same on any Docker version.
# ---------------------------------------------------------------------------

# Syscall numbers per architecture (the kernel's tables differ). Only these
# two are known; on any other the filter isn't installed and the self-test
# below makes the run INCOMPLETE.
SYSCALLS = {
    "x86_64": {"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
               "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
               "clone": 56, "clone3": 435},
    "aarch64": {"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
                "ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271,
                "clone": 220, "clone3": 435},
}
# seccomp_data.arch for each (AUDIT_ARCH_*). A syscall made through another
# ABI (e.g. 32-bit int 0x80 on x86_64) has another arch and other numbers.
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
# Refused with EPERM: io_uring (its file access is invisible to strace),
# tracing or reading/writing another process's memory.
BLOCKED = ("io_uring_setup", "io_uring_enter", "io_uring_register",
           "ptrace", "process_vm_readv", "process_vm_writev")
CLONE_UNTRACED = 0x00800000  # a child strace can't follow: EPERM
SIGCHLD = 17
EPERM, ENOSYS = 1, 38


def _bpf_program(machine: str) -> list[tuple[int, int, int, int]]:
    """The filter as (code, jump-if-true, jump-if-false, k) instructions.

    Classic BPF reads struct seccomp_data: nr at offset 0, arch at 4, the
    arguments from 16 (8 bytes each; the low half of args[0] is at 16 on
    little-endian x86_64 and aarch64). Jumps count instructions to skip.
    """
    nr = SYSCALLS[machine]
    load = 0x20                                   # BPF_LD | BPF_W | BPF_ABS: A = data[k]
    jeq, jge, jset, ret = 0x15, 0x35, 0x45, 0x06  # BPF_JMP | JEQ/JGE/JSET | BPF_K, BPF_RET | BPF_K
    allow, errno = 0x7FFF0000, 0x00050000         # SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO | errno
    blocked = [nr[name] for name in BLOCKED]
    n = len(blocked)
    # Layout: 0-3 checks, 4..4+n-1 blocked list, then clone3, clone, allow,
    # the clone flags check, and the three returns at the end.
    eperm = 4 + n + 7       # index of "return EPERM"
    enosys, wrong_abi = eperm + 1, eperm + 2
    program = [
        (load, 0, 0, 4),                                        # 0: A = arch
        (jeq, 0, wrong_abi - 2, AUDIT_ARCH[machine]),           # 1: not ours -> wrong ABI
        (load, 0, 0, 0),                                        # 2: A = syscall number
        (jge, wrong_abi - 4, 0, 0x40000000),                    # 3: x32 numbers -> wrong ABI
    ]
    for i, number in enumerate(blocked):                        # 4..: io_uring, ptrace, process_vm
        here = 4 + i
        program.append((jeq, eperm - here - 1, 0, number))
    here = 4 + n
    program += [
        (jeq, enosys - here - 1, 0, nr["clone3"]),              # clone3: flags unreadable -> ENOSYS
        (jeq, 1, 0, nr["clone"]),                               # clone: check its flags
        (ret, 0, 0, allow),                                     # everything else
        (load, 0, 0, 16),                                       # A = low half of args[0] (flags)
        (jset, 0, 1, CLONE_UNTRACED),                           # CLONE_UNTRACED -> EPERM
        (ret, 0, 0, errno | EPERM),
        (ret, 0, 0, allow),                                     # a normal clone
    ]
    assert len(program) == eperm
    program += [
        (ret, 0, 0, errno | EPERM),                             # eperm
        (ret, 0, 0, errno | ENOSYS),                            # enosys
        (ret, 0, 0, errno | EPERM),                             # wrong_abi: refuse everything
    ]
    return program


def install_syscall_filter() -> None:
    """Install the filter on this process (#84). Fails quietly: if it isn't
    installed (unknown architecture, prctl refused), the self-test shows it in
    the trace and compare.py makes the run INCOMPLETE."""
    machine = os.uname().machine
    if machine not in SYSCALLS:
        return
    import ctypes  # stdlib; imported only now, after the fd swap

    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

    program = _bpf_program(machine)
    filters = (SockFilter * len(program))(*[SockFilter(*ins) for ins in program])
    prog = SockFprog(len(program), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS, SECCOMP_MODE_FILTER = 22, 38, 2
    # NO_NEW_PRIVS: required for an unprivileged process to install a filter
    # (and no setuid program can then gain privileges).
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0:
        libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)


def filter_self_test() -> None:
    """Try what the filter must block, so the trace shows whether it works (#84).

    Before any server code: an io_uring_setup and a clone with CLONE_UNTRACED,
    both from this process. With the filter both fail with EPERM. compare.py
    reads only these two events (the first of each, from the launcher, before
    the sink is ready); if either is missing or succeeded, the run is INCOMPLETE.
    """
    import ctypes
    nr = SYSCALLS.get(os.uname().machine)
    if nr is None:
        nr = SYSCALLS["x86_64"]  # unknown arch: the calls below just fail; the trace decides
    libc = ctypes.CDLL(None, use_errno=True)
    params = ctypes.create_string_buffer(120)  # struct io_uring_params, zeroed
    fd = libc.syscall(nr["io_uring_setup"], 1, params)
    if fd >= 0:
        os.close(fd)  # no filter: the trace shows the success
    pid = libc.syscall(nr["clone"], CLONE_UNTRACED | SIGCHLD, 0, 0, 0, 0)
    if pid == 0:
        os._exit(0)  # no filter: an untraced child; it does nothing and leaves
    if pid > 0:
        os.waitpid(pid, 0)


def main() -> None:
    # 1. The server must never hold the trace stream.
    os.dup2(3, 2)
    os.close(3)

    # 1b. (#84) Sandglass's syscall filter, then its self-test. After the fd
    # swap (protected, unchanged), before the sink, the relay or the server.
    # They import ctypes (stdlib): sys.path[0], the cwd here, is taken off
    # first, so only the standard library can be found (no listing of the
    # cwd, and nothing in the project or package folder can stand in for ctypes).
    cwd_entry = sys.path.pop(0)
    install_syscall_filter()
    filter_self_test()
    sys.path.insert(0, cwd_entry)

    # Look like `python <server.py>` would. With -c, sys.path[0] is "" (the
    # cwd); replace it before importing anything non-frozen, or Python lists /project.
    server, sink_source, relay_source = sys.argv[1], sys.argv[2], sys.argv[3]
    sys.argv = [server]
    sys.path[0] = os.path.dirname(server)

    # 2. The network sink.
    start_sink(sink_source)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ[name] = SINK_URL
    for name in ("NO_PROXY", "no_proxy"):
        os.environ.pop(name, None)

    # 3. The stdin relay, which marks the start of the tool calls.
    start_relay(relay_source)

    # 4. The server. Node: replace this process with node (same pid, same fds).
    # (`sandglass scan npm:...` says so with SANDGLASS_RUNTIME: an npm "bin"
    # file doesn't always end in .js.)
    if server.endswith(".js") or os.environ.get("SANDGLASS_RUNTIME") == "node":
        os.execv(NODE, [NODE, server])

    # Python: packages, then the server.
    import site
    site.main()
    # `sandglass scan pypi:...` (#19): the package was installed into this
    # folder with pip --target. addsitedir also runs its .pth files, like a
    # real install would. Put it right after the server's own folder, so the
    # package's dependencies win over Sandglass's own (in /opt/venv). This is
    # done here, after step 1, and not with PYTHONPATH: PYTHONPATH is read at
    # interpreter startup, so a package could shadow e.g. `encodings` and run
    # before the trace stream is hidden.
    site_dir = os.environ.get("SANDGLASS_SITE_DIR")
    if site_dir:
        before = list(sys.path)
        site.addsitedir(site_dir)
        added = [p for p in sys.path if p not in before]
        sys.path[:] = before[:1] + added + before[1:]
    import runpy
    try:
        runpy.run_path(server, run_name="__main__")
    except SystemExit as exc:
        if exc.code not in (None, 0):
            # e.g. sys.exit("NOTES_API_KEY is not set"): Python would print
            # the message to stderr, which is /dev/null here (#47).
            record_server_error(str(exc.code) if isinstance(exc.code, str) else f"exit code {exc.code}")
        raise
    except BaseException as exc:
        record_server_error(f"{type(exc).__name__}: {exc}")
        raise


def record_server_error(message: str) -> None:
    """Put the server's own error message into the trace (#24).

    The server's stderr is /dev/null (step 1), so its traceback is lost. Like
    the sink and the relay, this stat()s a path that doesn't exist, so the
    message lands in the trace. It runs inside the server's process, so the
    server could fake it: compare.py only uses it as the wording of a reason
    when the run is already INCOMPLETE (the server exited during startup).
    """
    try:
        os.stat(f"{SERVER_ERROR_DIR}/{clean_message(message)}")
    except OSError:
        pass


def clean_message(message: str) -> str:
    """One safe path component: allowed characters only, at most 200 of them."""
    return "".join(c if c in MESSAGE_CHARS else "_" for c in message)[:200] or "_"


if __name__ == "__main__":
    main()
