"""Turn strace output into a list of simple Event objects.

Expected input: a file produced by `strace -f -tt -o trace.txt`. Each line
looks like:

    17  18:04:49.654027 openat(AT_FDCWD, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 3
    ^pid ^timestamp     ^syscall(arguments)                                    ^result

A failed call ends with an error name, e.g. `= -1 ENOENT (No such file or directory)`.

Failed syscalls are KEPT, with succeeded=False and the error name. They matter:
under --network none every connect() fails, and a failed attempt to open a
credentials file still shows intent. compare.py decides what each one means.

Event kinds:
  file     open/openat/... with mode "read", "write", or "list" (a directory
           opened with O_DIRECTORY, i.e. listing its contents), plus
           path-changing syscalls like rename/unlink (always "write")
  probe    stat/access/readlink: checks a path without reading its contents
  process  execve/execveat: a program was launched
  network  connect/bind/listen/accept, and sendto/sendmsg WITH a destination
  exit     a traced process exited ("+++ exited with 0 +++")
"""

import posixpath
import re
from dataclasses import dataclass, asdict

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

# connect/bind/listen/accept always count. sendto/sendmsg only count when they
# carry a destination address: without one they're sending on an already
# connected socket (whose connect() we already recorded) or on a local
# socketpair, which can't reach the network. asyncio uses a socketpair
# internally, so counting every sendto would flag every Python server.
NETWORK_SYSCALLS = {"connect", "bind", "listen", "accept", "accept4", "sendto", "sendmsg"}

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
# Target for an exec whose arguments strace couldn't read.
UNREADABLE = "<unreadable>"


@dataclass
class Event:
    kind: str           # file | probe | process | network | exit
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
    """Undo strace's C-style escaping of strings (\\", \\\\, \\n, \\x41, ...)."""
    return s.encode("latin-1", "backslashreplace").decode("unicode_escape")


def _absolute(path: str, args: str, cwd: str) -> str:
    """Make a path absolute. Relative paths are relative to the working
    directory only when the call uses AT_FDCWD (or has no dirfd at all)."""
    if path.startswith("/"):
        return posixpath.normpath(path)
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


def _classify(syscall: str, args: str, cwd: str) -> tuple[str, str, str | None] | None:
    """Return (kind, target, mode) for a syscall we care about, else None."""
    strings = [_unescape(s) for s in STRING_RE.findall(args)]

    if syscall in OPEN_SYSCALLS:
        if not strings:
            return None
        if syscall == "creat" or any(flag in args for flag in WRITE_FLAGS):
            mode = "write"
        elif "O_DIRECTORY" in args:
            mode = "list"  # opening a directory to read its entries (os.listdir)
        else:
            mode = "read"
        return "file", _absolute(strings[0], args, cwd), mode

    if syscall in WRITE_SYSCALLS and strings:
        # rename(old, new): the destination is the interesting path.
        return "file", _absolute(strings[-1], args, cwd), "write"

    if syscall in PROBE_SYSCALLS and strings and strings[0]:
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
        if syscall in ("sendto", "sendmsg") and address is None:
            return None  # no destination: connected socket or socketpair, see above
        return "network", address or args, None

    return None


def parse_trace(text: str, cwd: str = "/project") -> list[Event]:
    """Parse a whole strace file into events, in the order they happened.

    `cwd` is the server's working directory, used to make relative paths
    absolute (the sandbox runs with -w /project).
    """
    events: list[Event] = []
    pending: dict[int, tuple[str, str]] = {}  # pid -> (first line, its body), unfinished

    for line in text.splitlines():
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
