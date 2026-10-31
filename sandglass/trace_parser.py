"""Turn strace output into a list of simple Event objects.

Expected input: a file produced by `strace -f -tt -o trace.txt`, read one
line at a time and at most MAX_TRACE_BYTES of it (#83). Each line looks like:

    17  18:04:49.654027 openat(AT_FDCWD, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 3
    ^pid ^timestamp     ^syscall(arguments)                                    ^result

A failed call ends with an error name, e.g. `= -1 ENOENT (No such file or directory)`.

Failed syscalls are KEPT, with succeeded=False and the error name. They matter:
under --network none every connect() fails, and a failed attempt to open a
credentials file still shows intent. compare.py decides what each one means.

Paths strace couldn't read (printed as a bare address) are KEPT too, with
target "<unreadable>" (#98): compare.py makes the run INCOMPLETE.

Event kinds:
  file     open/openat/... with mode "read", "write", or "list" (a directory
           opened with O_DIRECTORY, i.e. listing its contents), plus
           path-changing syscalls like rename/unlink (always "write"), and
           memfd_create as a "write" to "memfd:<name>"
  probe    stat/access/readlink: checks a path without reading its contents
  process  execve/execveat: a program was launched
  network  connect/bind/listen/accept, and sendto/sendmsg/sendmmsg WITH a destination
  io_uring io_uring_setup/enter/register: file access strace can't see (#75)
  evasion  clone/clone3 with CLONE_UNTRACED, ptrace, process_vm_readv/writev,
           pidfd_getfd, unshare, setns, userfaultfd (#155):
           ways out of strace's sight (#84), mode "evade"
  exit     a traced process exited ("+++ exited with 0 +++")
"""

import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, asdict

# The most of a trace file that is read (#83). A server making a huge number
# of syscalls could otherwise use up the host's memory. Past this, the run is
# INCOMPLETE: the part we didn't read could hold anything.
MAX_TRACE_BYTES = 256 * 1024 * 1024

# ---------------------------------------------------------------------------
# Which syscalls we care about, grouped by what they mean.
# ---------------------------------------------------------------------------

OPEN_SYSCALLS = {"open", "openat", "openat2", "creat"}

# Syscalls that change the filesystem without open(): always "write".
WRITE_SYSCALLS = {
    "rename", "renameat", "renameat2", "unlink", "unlinkat", "mkdir", "mkdirat",
    "rmdir", "link", "linkat", "symlink", "symlinkat", "truncate",
    "chmod", "fchmodat", "fchmodat2", "chown", "lchown", "fchownat",
}

# Syscalls that look at a path without reading its contents.
PROBE_SYSCALLS = {
    "stat", "lstat", "newfstatat", "fstatat64", "statx", "statfs",
    "access", "faccessat", "faccessat2", "readlink", "readlinkat",
}

EXEC_SYSCALLS = {"execve", "execveat"}

# Path syscalls that take two paths (old, new). Both must be readable.
TWO_PATH_SYSCALLS = {"rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat"}

# memfd_create(name, flags) makes an anonymous file that lives only in memory
# (#77). It's recorded as a WRITE to "memfd:<name>", which no write_allow entry
# covers, so creating one is a violation, like writing any file outside policy.
MEMFD_PREFIX = "memfd:"

# io_uring (#75): a process hands file opens/reads to the kernel through a
# shared ring, so they never show up as openat/read syscalls. All we can see
# is the ring being set up and used. compare.py decides what that means.
IO_URING_SYSCALLS = {"io_uring_setup", "io_uring_enter", "io_uring_register"}

# (#84) Ways to get out of strace's sight, which Sandglass's syscall filter
# (sandglass/launcher.py) refuses: a child strace can't follow (clone or
# clone3 with CLONE_UNTRACED), tracing another process (ptrace), and reading
# or writing another process's memory (process_vm_readv/writev).
# (#155) Also refused by the filter, and reported the same way: taking an fd
# from another process (pidfd_getfd), new or other namespaces (unshare,
# setns), and userfaultfd (stalling the kernel mid-syscall).
# A plain clone (threads, fork) is not one of them and is skipped.
EVASION_SYSCALLS = {"ptrace", "process_vm_readv", "process_vm_writev",
                    "pidfd_getfd", "unshare", "setns", "userfaultfd"}
CLONE_SYSCALLS = {"clone", "clone3"}
UNTRACED_FLAG = "CLONE_UNTRACED"

# connect/bind/listen/accept always count. sendto/sendmsg/sendmmsg only count
# when they carry a destination address: without one they're sending on an already
# connected socket (whose connect() we already recorded) or on a local
# socketpair, which can't reach the network. asyncio uses a socketpair
# internally, so counting every sendto would flag every Python server.
# (glibc's DNS resolver uses sendmmsg on a connected UDP socket: no address.)
SEND_SYSCALLS = {"sendto", "sendmsg", "sendmmsg"}
NETWORK_SYSCALLS = {"connect", "bind", "listen", "accept", "accept4"} | SEND_SYSCALLS

# Flags that mean an open() can modify the file.
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

# ---------------------------------------------------------------------------
# Regular expressions for the strace line format.
# ---------------------------------------------------------------------------

# "<pid> <HH:MM:SS.micro> <rest>"
LINE_RE = re.compile(r"^(\d+)\s+(\d\d:\d\d:\d\d\.\d+)\s+(.*)$")
# "openat(...) = 3" or "openat(...) = -1 ENOENT (No such file...)" or "exit_group(0) = ?"
# Greedy (.*) so a ")" inside a quoted path doesn't end the arguments early.
CALL_RE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(\S+)(?:\s+(E[A-Z0-9]+))?")
# Second half of a call that was interrupted by another thread's output.
RESUMED_RE = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
UNFINISHED = "<unfinished ...>"
EXIT_RE = re.compile(r"^\+\+\+ (exited with \d+|killed by \w+.*) \+\+\+$")
# A double-quoted strace string, allowing escaped characters inside.
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
# One escape inside a strace string: \xNN (hex), \NNN (octal), or one character (\n, \", ...).
ESCAPE_RE = re.compile(r"\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)", re.DOTALL)
SIMPLE_ESCAPES = {"n": b"\n", "t": b"\t", "r": b"\r", "v": b"\v", "f": b"\f"}
# Target for an exec, open, write or stat whose path strace couldn't read.
UNREADABLE = "<unreadable>"
# A bare address as one argument (how strace shows memory it couldn't read).
ADDRESS_RE = re.compile(r"(?:^|, )0x[0-9a-f]+(?=,|$)")


@dataclass
class Event:
    kind: str           # file | probe | process | network | io_uring | evasion | exit
    syscall: str        # e.g. "openat"
    pid: int
    timestamp: str      # HH:MM:SS.micro, from strace -tt
    target: str         # path, program, network address, or exit status
    mode: str | None    # "read"/"write"/"list" for file events, else None
    succeeded: bool
    error: str | None   # e.g. "ENOENT" when succeeded is False
    raw: str            # the original strace line, kept as evidence
    # symlink/link only (#16): the path the new link points to, absolute. A
    # link inside a writable folder to a secret would otherwise make reading
    # the secret look like reading the allowed folder.
    link_target: str | None = None
    # A successful open only (#122): the file actually opened, as strace -y
    # prints it after the returned fd. Differs from `target` when the path
    # went through a symlink. None without -y.
    opened: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _unescape(s: str) -> str:
    """Undo strace's C-style escaping of strings (\\", \\\\, \\n, \\303, \\x41, ...).

    strace escapes each non-ASCII BYTE, so "/tmp/café" arrives as
    "/tmp/caf\\303\\251" (or "\\xc3\\xa9" with -x). Rebuild the bytes first, then
    decode them as UTF-8. Bytes that aren't valid UTF-8 stay visible as "\\xff".
    """
    out = bytearray()
    pos = 0
    for match in ESCAPE_RE.finditer(s):
        out += s[pos:match.start()].encode("utf-8")
        code = match[1]
        if code[0] == "x":
            out.append(int(code[1:], 16))
        elif code[0] in "01234567":
            out.append(int(code, 8) & 0xFF)
        else:
            out += SIMPLE_ESCAPES.get(code, code.encode("utf-8"))  # \" -> ", \\ -> \
        pos = match.end()
    out += s[pos:].encode("utf-8")
    return out.decode("utf-8", "backslashreplace")


def _absolute(path: str, cwd: str, dirfd: str | None = None, fd_dirs: dict | None = None) -> str:
    """Make a path absolute. A relative path is relative to the working
    directory when the call has no dirfd before it, or AT_FDCWD; otherwise to
    that dirfd's folder, if strace -y printed it (the install trace, #16)."""
    if path.startswith("/"):
        # normpath keeps exactly two leading slashes (POSIX allows "//" to mean
        # something special), but Linux opens "//etc/passwd" as "/etc/passwd".
        # Collapse them, or the path wouldn't match the policy's "/etc/passwd".
        return posixpath.normpath("/" + path.lstrip("/"))
    folder = (fd_dirs or {}).get(dirfd or "AT_FDCWD", "")
    if dirfd is None or dirfd == "AT_FDCWD":
        # With strace -y, AT_FDCWD<...> says the process's real working
        # directory (npm runs install scripts inside the package's folder).
        cwd = folder if folder.startswith("/") else cwd
        return posixpath.normpath(posixpath.join(cwd, path))
    if folder.startswith("/"):
        return posixpath.normpath(posixpath.join("/" + folder.lstrip("/"), path))
    # Relative to some other open directory fd; we can't know which without
    # strace -y, so mark it clearly. compare.py treats it as "not allowed".
    return f"<dirfd {dirfd}>/{path}"


def _dirfd_before(args: str, position: int) -> str | None:
    """The dirfd argument right before a path argument: "AT_FDCWD", "3", or None.
    openat(3, "x") -> "3"; symlinkat("t", 3, "p") -> "3" for "p"; open("x") -> None."""
    match = re.search(r"(?:^|[\s(,])(AT_FDCWD|\d+),\s*$", args[:position])
    return match[1] if match else None


# strace -y prints an fd argument with its path: 3</tmp/pip-x>, and
# AT_FDCWD</package> (the working directory). Inside the <...>, strace
# escapes "<", ">" and non-printable bytes, so the first plain ">" ends it.
# A '"' is NOT escaped there, which is why these are taken out (by a scanner
# that skips quoted strings) before the strings are read.
FD_PATH_RE = re.compile(r"(\d+|AT_FDCWD)<((?:[^<>\\]|\\.)*)>")
# -y also prints the path of a RETURNED fd: "= 17</home/x>". Removed before
# the call is parsed, so a ")" in such a path can't change the result. For
# an open, that path is the file actually opened (#122): through a symlink,
# it's where the link led, e.g. openat(.., "/tmp/x/link", ..) = 3</home/sandglass/.aws/credentials>.
RESULT_FD_PATH_RE = re.compile(r"(=\s+\d+)<((?:[^<>\\]|\\.)*)>$")


# /proc/<pid>/<rest>, as strace -y prints a file opened through /proc/self.
PROC_PID_RE = re.compile(r"^/proc/\d+(/.*)$")


def _proc_self(requested: str, opened: str) -> str:
    """The opened path, except that /proc/self is kept as it was asked for (#122).

    /proc/self (and /proc/mounts, which links to self/mounts) always leads to
    the process's OWN /proc/<pid> folder, so strace -y shows
    openat(.., "/proc/self/cgroup", ..) = 3</proc/42/cgroup>. That's the same
    file, not an escape: the opened path is then reported as the requested one.
    Only when the rest of the path is identical, so /proc/self/fd/3 or
    /proc/self/root/... (which lead elsewhere) are still judged by where they
    really lead.
    """
    match = PROC_PID_RE.match(opened)
    if match and requested in ("/proc/self" + match[1], "/proc" + match[1]):
        return requested
    return opened


def _strip_fd_paths(args: str) -> tuple[str, dict[str, str]]:
    """Remove strace -y fd paths from the arguments: ('3, "x"', {"3": "/tmp/a"}).

    Quoted strings are copied as they are, so a file NAME that looks like
    "3<...>" is never mistaken for an fd path. Without -y, nothing changes.
    """
    if "<" not in args:
        return args, {}
    out, paths, i = [], {}, 0
    while i < len(args):
        if args[i] == '"':
            string = STRING_RE.match(args, i)
            if string:
                out.append(string.group(0))
                i = string.end()
                continue
        elif ((args[i].isdigit() or args.startswith("AT_FDCWD<", i))
              and (i == 0 or args[i - 1] in " ,[{(")):
            fd_path = FD_PATH_RE.match(args, i)
            if fd_path:
                out.append(fd_path[1])
                paths[fd_path[1]] = _unescape(fd_path[2])
                i = fd_path.end()
                continue
        out.append(args[i])
        i += 1
    return "".join(out), paths


def _network_target(args: str) -> str | None:
    """Pull the address out of a network syscall's arguments, or None."""
    match = re.search(r"\{sa_family=.*?\}", args)
    return match.group(0) if match else None


def _path_unreadable(syscall: str, args: str, strings: list[str]) -> bool:
    """Did strace fail to read a path argument (#98)?

    strace prints a path it can't read from the process's memory as a bare
    address (openat(AT_FDCWD, 0xffff83995370, ...)). So: fewer readable
    paths than the call takes, and an address in the arguments. (A NULL path
    is printed as NULL: nothing is hidden, the call just fails.) Such an event
    must never be dropped; compare.py makes the run INCOMPLETE.
    """
    needed = 2 if syscall in TWO_PATH_SYSCALLS else 1
    return len(strings) < needed and ADDRESS_RE.search(args) is not None


LINK_SYSCALLS = {"symlink", "symlinkat", "link", "linkat"}


def _link_target(syscall: str, args: str, cwd: str, link_path: str) -> str | None:
    """Where a new symlink or hard link points, as an absolute path (#16).

    symlink(target, linkpath): a relative target is relative to the link's
    own folder. link(oldpath, newpath): oldpath is an ordinary path.
    """
    args, fd_dirs = _strip_fd_paths(args)
    strings, path_of = _strings_and_paths(args, cwd, fd_dirs)
    if syscall not in LINK_SYSCALLS or len(strings) < 2:
        return None
    if syscall.startswith("symlink"):
        target = strings[0]
        if target.startswith("/"):
            return posixpath.normpath("/" + target.lstrip("/"))
        return posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
    return path_of(0)


def exec_argv(raw: str) -> list[str] | None:
    """The argument list of an execve/execveat line, or None if strace
    couldn't read it (#120). Used by the report's "Programs run" section.

        execve("/usr/bin/sh", ["sh", "-c", "node postinstall.js"], 0x55f6 /* 49 vars */) = 0
        -> ["sh", "-c", "node postinstall.js"]

    strace cuts long strings short and marks them with "..." after the
    closing quote ("\\"\\"\\"The local network sink: a fak"...); the "..." is kept.
    """
    path = STRING_RE.search(raw)  # the program's path comes first
    start = raw.find("[", path.end()) if path else -1
    if start < 0:
        return None
    argv, pos = [], start + 1
    while True:
        string = STRING_RE.match(raw, pos)
        if not string:
            break
        text, pos = _unescape(string[1]), string.end()
        if raw.startswith("...", pos):  # cut short by strace
            text, pos = text + "...", pos + 3
        argv.append(text)
        if not raw.startswith(", ", pos):
            break
        pos += 2
    return argv


def _strings_and_paths(args: str, cwd: str, fd_dirs: dict):
    """The quoted strings of the arguments, and path_of(i): string i as an
    absolute path, relative to the dirfd argument just before it (if any)."""
    matches = list(STRING_RE.finditer(args))
    strings = [_unescape(m[1]) for m in matches]

    def path_of(i: int) -> str:
        return _absolute(strings[i], cwd, _dirfd_before(args, matches[i].start()), fd_dirs)
    return strings, path_of


def _classify(syscall: str, args: str, cwd: str) -> tuple[str, str, str | None] | None:
    """Return (kind, target, mode) for a syscall we care about, else None."""
    args, fd_dirs = _strip_fd_paths(args)  # fd folders: strace -y only (the install trace)
    strings, path_of = _strings_and_paths(args, cwd, fd_dirs)

    if syscall in OPEN_SYSCALLS:
        if syscall == "creat" or any(flag in args for flag in WRITE_FLAGS):
            mode = "write"
        elif "O_DIRECTORY" in args:
            mode = "list"  # opening a directory to read its entries (os.listdir)
        else:
            mode = "read"
        if not strings:
            return ("file", UNREADABLE, mode) if _path_unreadable(syscall, args, strings) else None
        return "file", path_of(0), mode

    if syscall == "memfd_create":
        return "file", MEMFD_PREFIX + (strings[0] if strings else ""), "write"

    if syscall in IO_URING_SYSCALLS:
        return "io_uring", syscall, None

    # (#84) mode "evade"; the target names what was tried, e.g.
    # "clone CLONE_UNTRACED", "ptrace PTRACE_ATTACH", "process_vm_writev".
    if syscall in CLONE_SYSCALLS:
        return ("evasion", f"{syscall} {UNTRACED_FLAG}", "evade") if UNTRACED_FLAG in args else None
    if syscall == "ptrace":
        return "evasion", f"ptrace {args.split(',', 1)[0].strip()}", "evade"
    if syscall in EVASION_SYSCALLS:
        return "evasion", syscall, "evade"

    if syscall in WRITE_SYSCALLS:
        if _path_unreadable(syscall, args, strings):
            return "file", UNREADABLE, "write"
        if strings:
            # rename(old, new): the destination is the interesting path.
            return "file", path_of(-1), "write"

    if syscall in PROBE_SYSCALLS:
        if _path_unreadable(syscall, args, strings):
            return "probe", UNREADABLE, None
        if strings and strings[0]:
            # An empty path (e.g. newfstatat(3, "", AT_EMPTY_PATH)) inspects an
            # already-open fd, not a new path, so it's skipped.
            return "probe", path_of(0), None

    if syscall in EXEC_SYSCALLS:
        if not strings:
            # strace couldn't read the arguments (shown as addresses). This
            # happens for the very first exec, because the strace binary is
            # non-dumpable (see sandbox.py). Keep it: compare.py treats only the
            # FIRST exec as the server launch; any other is still a violation.
            return "process", UNREADABLE, None
        return "process", path_of(0), None

    if syscall in NETWORK_SYSCALLS:
        address = _network_target(args)
        if syscall in SEND_SYSCALLS and address is None:
            return None  # no destination: connected socket or socketpair, see above
        return "network", address or args, None

    return None


def parse_trace_file(path, cwd: str = "/project",
                     max_bytes: int = MAX_TRACE_BYTES) -> tuple[list[Event], bool]:
    """Parse a trace file one line at a time, never reading it whole (#83).

    Stops after `max_bytes`. Returns (events, cut_short): cut_short is True
    if the file was bigger than that, so the events are only its beginning
    (compare.py then makes the run INCOMPLETE). A missing file gives no events.
    """
    state = {"read": 0, "cut_short": False}

    def lines(f):
        for line in f:
            state["read"] += len(line.encode("utf-8", "replace"))
            if state["read"] > max_bytes:
                state["cut_short"] = True
                return  # stop reading: the rest of the file is never loaded
            yield line.rstrip("\r\n")

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            events = parse_trace(lines(f), cwd)
    except FileNotFoundError:
        return [], False
    return events, state["cut_short"]


def parse_trace(text: str | Iterable[str], cwd: str = "/project") -> list[Event]:
    """Parse strace output into events, in the order they happened.

    `text` is the whole trace as one string, or any iterable of its lines
    (e.g. an open file, read line by line by parse_trace_file).
    `cwd` is the server's working directory, used to make relative paths
    absolute (the sandbox runs with -w /project).
    """
    events: list[Event] = []
    pending: dict[int, tuple[str, str]] = {}  # pid -> (first line, its body), unfinished

    for line in (text.splitlines() if isinstance(text, str) else text):
        match = LINE_RE.match(line)
        if not match:
            continue
        pid, timestamp, body = int(match[1]), match[2], match[3]

        # Process exit: "+++ exited with 0 +++" / "+++ killed by SIGKILL +++"
        exit_match = EXIT_RE.match(body)
        if exit_match:
            events.append(Event("exit", "exit", pid, timestamp, exit_match[1],
                                None, True, None, line))
            continue

        # With -f, a call in one thread can be interrupted by another thread's
        # output. strace then prints it in two halves; stitch them together.
        if body.endswith(UNFINISHED):
            pending[pid] = (line[: -len(UNFINISHED)].rstrip(), body[: -len(UNFINISHED)].rstrip())
            continue
        resumed = RESUMED_RE.match(body)
        if resumed:
            first_line, first_body = pending.pop(pid, (line, f"{resumed[1]}("))
            body = first_body + resumed[2]
            # Evidence = the whole call, as strace would have printed it
            # uninterrupted: the first half's line plus the resumed ending.
            line = first_line + resumed[2]

        returned = RESULT_FD_PATH_RE.search(body)  # strace -y: "= 3</x>"
        call = CALL_RE.match(RESULT_FD_PATH_RE.sub(r"\1", body))  # -> "= 3"
        if not call:
            continue  # signals ("--- SIGCHLD ---") and anything unrecognised
        syscall, args, result, errno = call[1], call[2], call[3], call[4]

        classified = _classify(syscall, args, cwd)
        if classified is None:
            continue
        kind, target, mode = classified

        # strace reports failure as a negative return plus an errno name.
        succeeded = errno is None and not result.startswith("-")
        link_target = _link_target(syscall, args, cwd, target) if syscall in LINK_SYSCALLS else None
        # The file a successful open really opened (#122), as an absolute path.
        # (Not a path, e.g. "pipe:[123]" for a reopened pipe: not a file, skipped.)
        opened = None
        if (syscall in OPEN_SYSCALLS and succeeded and returned and target != UNREADABLE
                and returned[2].startswith("/")):
            opened = _proc_self(target, _absolute(_unescape(returned[2]), cwd))
        events.append(Event(kind, syscall, pid, timestamp, target, mode,
                            succeeded, errno, line, link_target, opened))

    return events
