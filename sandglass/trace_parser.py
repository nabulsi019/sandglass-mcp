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
    kind: str           # file | probe | process | network | io_uring | exit
    syscall: str        # e.g. "openat"
    pid: int
    timestamp: str      # HH:MM:SS.micro, from strace -tt
    target: str         # path, program, network address, or exit status
    mode: str | None    # "read"/"write"/"list" for file events, else None
    succeeded: bool
    error: str | None   # e.g. "ENOENT" when succeeded is False
    raw: str            # the original strace line, kept as evidence

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


def _absolute(path: str, args: str, cwd: str) -> str:
    """Make a path absolute. Relative paths are relative to the working
    directory only when the call uses AT_FDCWD (or has no dirfd at all)."""
    if path.startswith("/"):
        # normpath keeps exactly two leading slashes (POSIX allows "//" to mean
        # something special), but Linux opens "//etc/passwd" as "/etc/passwd".
        # Collapse them, or the path wouldn't match the policy's "/etc/passwd".
        return posixpath.normpath("/" + path.lstrip("/"))
    if args.startswith("AT_FDCWD") or not re.match(r"^\d+,", args):
        return posixpath.normpath(posixpath.join(cwd, path))
    # Relative to some other open directory fd; we can't know which without
    # strace -y, so mark it clearly. compare.py treats it as "not allowed".
    dirfd = args.split(",", 1)[0]
    return f"<dirfd {dirfd}>/{path}"


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


def _classify(syscall: str, args: str, cwd: str) -> tuple[str, str, str | None] | None:
    """Return (kind, target, mode) for a syscall we care about, else None."""
    strings = [_unescape(s) for s in STRING_RE.findall(args)]

    if syscall in OPEN_SYSCALLS:
        if syscall == "creat" or any(flag in args for flag in WRITE_FLAGS):
            mode = "write"
        elif "O_DIRECTORY" in args:
            mode = "list"  # opening a directory to read its entries (os.listdir)
        else:
            mode = "read"
        if not strings:
            return ("file", UNREADABLE, mode) if _path_unreadable(syscall, args, strings) else None
        return "file", _absolute(strings[0], args, cwd), mode

    if syscall == "memfd_create":
        return "file", MEMFD_PREFIX + (strings[0] if strings else ""), "write"

    if syscall in IO_URING_SYSCALLS:
        return "io_uring", syscall, None

    if syscall in WRITE_SYSCALLS:
        if _path_unreadable(syscall, args, strings):
            return "file", UNREADABLE, "write"
        if strings:
            # rename(old, new): the destination is the interesting path.
            return "file", _absolute(strings[-1], args, cwd), "write"

    if syscall in PROBE_SYSCALLS:
        if _path_unreadable(syscall, args, strings):
            return "probe", UNREADABLE, None
        if strings and strings[0]:
            # An empty path (e.g. newfstatat(3, "", AT_EMPTY_PATH)) inspects an
            # already-open fd, not a new path, so it's skipped.
            return "probe", _absolute(strings[0], args, cwd), None

    if syscall in EXEC_SYSCALLS:
        if not strings:
            # strace couldn't read the arguments (shown as addresses). This
            # happens for the very first exec, because the strace binary is
            # non-dumpable (see sandbox.py). Keep it: compare.py treats only the
            # FIRST exec as the server launch; any other is still a violation.
            return "process", UNREADABLE, None
        return "process", _absolute(strings[0], args, cwd), None

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

        call = CALL_RE.match(body)
        if not call:
            continue  # signals ("--- SIGCHLD ---") and anything unrecognised
        syscall, args, result, errno = call[1], call[2], call[3], call[4]

        classified = _classify(syscall, args, cwd)
        if classified is None:
            continue
        kind, target, mode = classified

        # strace reports failure as a negative return plus an errno name.
        succeeded = errno is None and not result.startswith("-")
        events.append(Event(kind, syscall, pid, timestamp, target, mode,
                            succeeded, errno, line))

    return events
