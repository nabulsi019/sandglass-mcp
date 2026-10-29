"""Compare recorded events with a policy and write the JSON + Markdown report.

Rules (one place, so they're easy to explain):

  What counts as allowed (note the asymmetry):
    read  -> read_allow, runtime_allow, baseline
    list  -> the same as read, plus exact "=" entries (that directory only)
    write -> write_allow ONLY. runtime_allow and the baseline never allow writes.
    read_deny (#121) wins over all of them: a read or listing under it is
    never allowed (and a probe under it is always listed).

  Files (open/rename/unlink/...) that are not allowed:
    succeeded                 -> VIOLATION
    failed with EACCES/EPERM  -> VIOLATION (the file exists; access was blocked)
    failed otherwise          -> "attempted" (listed, does not change the verdict)
  Probes (stat/access/readlink) outside the read allow-list:
    -> "probes" (informational only)
  A file or probe whose path strace couldn't read ("<unreadable>", #98):
    -> INCOMPLETE, from any process. Never dropped, never guessed.
  Network (when network.allow is false):
    any attempt, even a failed one -> VIOLATION
    except a SUCCESSFUL connect to the local network sink (sandglass/netsink.py):
      the sink then records the domain the server asked for, and
    a domain not in network.allow_domains -> VIOLATION naming the domain
    a record with no readable domain (#136) -> "unidentified connection to
      the sink": VIOLATION if no domain is allowed, INCOMPLETE if some are
    successful connects to the sink != the sink's records (#136) -> INCOMPLETE
  The sink (the first process to stat its "ready" marker, which the launcher
  waits for before any server code runs) and the stdin relay (found the same
  way, from its own "ready" marker) are Sandglass's helpers. Only an exact
  list of their known events is skipped (#99):
    sink   its own exec, its ready marker, bind/listen/accept on the proxy
           port, and the isolation check: its connect to a public IP and
           the marker where it reports the outcome (#100). The outcome comes
           only from that marker, before "ready": anything but isolated, or
           no marker at all -> INCOMPLETE
    relay  its own exec and its ready / tool-call / eof / server-exited markers
  Everything else from those pids is judged like the server's, by the rules
  here: they run as the same user, so it may not be the helper's own code.
  If the relay ends before the client closed stdin (no "eof" marker, or not
  a clean exit) -> INCOMPLETE. Its "server-exited" marker (the server process
  went away first, #24) is a normal end too.
  Server exits during startup (#24): no tool was called and the server's exit
  record comes before the client hung up -> INCOMPLETE, with the exit status
  and, for Python servers, the error message the launcher recorded
  (/sandglass-server-error/<message>, from the server's own process: used
  only as the wording of that reason, and skipped as a probe).
  Process exec:
    the first exec in the trace is the server itself -> allowed
    (Node servers: the launcher then execs node in that same process; that
    one exec is part of the launch too, but only when runtime is "node")
    anything else not in exec_allow: same rules as files
  io_uring (#75): file access through a ring is invisible to strace, so
    failed (e.g. EPERM: seccomp blocked it) -> "attempted" (Node's libuv tries
                                               this at every startup)
    succeeded                               -> INCOMPLETE: the trace may be
                                               missing file access
  Evasion (#84): clone/clone3 with CLONE_UNTRACED, ptrace, process_vm_readv/writev
    any attempt, even refused -> VIOLATION "tried to evade tracing"
    succeeded                 -> also INCOMPLETE (a child or memory strace can't see)
  Syscall filter self-test (#84): the launcher's io_uring_setup and
    CLONE_UNTRACED clone, before the sink is ready, must both fail with EPERM;
    missing or not refused -> INCOMPLETE. Not otherwise reported.

Phases (#18): every reported event gets a phase:
  install    `sandglass scan` only: the install's own trace, judged by
             compare_install() (#16). Empty for fixture runs.
  startup    before the first tool call reached the server
  tool-call  from the first tool call on
  unknown    the boundary is missing from the trace; never guessed
  The boundary is the stdin relay's "tool-call" marker (#91): events before
  that line in the trace are startup, events after it are tool-call. Only the
  ORDER of lines is used, never a clock, and only the relay's own marker counts.

Verdicts:
  INCOMPLETE  the run can't be trusted: the server didn't start (or exited
              during startup, e.g. a missing API key), the session
              errored, nothing was exercised, the trace is missing/truncated,
              the trace was bigger than MAX_TRACE_BYTES (only its start was read, #83),
              the network sink didn't start, the sandbox could reach the internet,
              the stdin relay didn't start or ended early (the server may have
              tampered with it), an io_uring call succeeded, or a file
              event's path couldn't be read.
              Never treated as clean, even when no violations were seen.
  VIOLATIONS  at least one violation.
  CLEAN       a complete run with zero violations.
"""

import json
import posixpath
import re
from dataclasses import asdict
from pathlib import Path

from mcp.types import CONNECTION_CLOSED, REQUEST_TIMEOUT

from sandglass import launcher, netsink, sandbox, stdin_relay
from sandglass.policy import InstallBaseline, Policy
from sandglass.trace_parser import MAX_TRACE_BYTES, NETWORK_SYSCALLS, UNREADABLE, Event, exec_argv

# Errors that mean "this exists but you're not allowed": a real access attempt.
BLOCKED_ERRORS = {"EACCES", "EPERM"}

IO_URING_INCOMPLETE = "io_uring was available, file access may be missing from the trace"
EVADED_INCOMPLETE = ("a process got out of strace's sight (a CLONE_UNTRACED child, ptrace or "
                     "another process's memory), so its actions may be missing from the trace")
FILTER_INACTIVE = ("Sandglass's syscall filter is not active (#84): its self-test before the server "
                   "started")
EVADE_REASON = "tried to evade tracing"


def _filter_self_test(events: list[Event], sink_pid: int | None) -> tuple[list[Event], str | None]:
    """The launcher's self-test of the syscall filter (#84): (its events, problem or None).

    Right after installing the filter, the launcher (the first process to
    exec) tries io_uring_setup and a clone with CLONE_UNTRACED. Only the FIRST
    of each, from the launcher, before the sink marks itself ready (so before
    any server code ran) counts. Both must be there and both must have failed
    with EPERM; anything else means the filter isn't doing its job.
    """
    launch = next((e for e in events if e.kind == "process" and e.succeeded), None)
    if launch is None:
        return [], None  # no launch at all: INCOMPLETE for that reason already
    end = next((i for i, e in enumerate(events) if e.pid == sink_pid and e.kind == "probe"
                and e.target == netsink.SINK_READY), len(events))
    found = {}
    for event in events[:end]:
        if event.pid != launch.pid:
            continue
        if event.syscall == "io_uring_setup":
            found.setdefault("io_uring_setup", event)
        elif event.kind == "evasion" and event.syscall == "clone":
            found.setdefault("clone(CLONE_UNTRACED)", event)
    problems = []
    for name in ("io_uring_setup", "clone(CLONE_UNTRACED)"):
        event = found.get(name)
        if event is None:
            problems.append(f"{name} missing")
        elif event.succeeded or event.error != "EPERM":
            problems.append(f"{name} {'succeeded' if event.succeeded else 'failed with ' + str(event.error)}"
                            " instead of being refused (EPERM)")
    problem = f"{FILTER_INACTIVE}: {'; '.join(problems)}" if problems else None
    return list(found.values()), problem


def _is_under(path: str, roots: list) -> bool:
    """True if `path` is one of `roots` or inside one of them (textual check)."""
    for root in roots:
        root = str(root)
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _file_reason(mode: str, path: str, read_deny: list, prefix: str = "") -> str:
    """Why a file event is a violation. read_deny wins over every allow-list
    (#121), so say so when that's the reason."""
    if mode != "write" and _is_under(path, read_deny):
        return f"{prefix}{mode} matches read_deny"
    return f"{prefix}{mode} outside allowed paths"


def _is_address(target: str, host: str, port: int) -> bool:
    """Does a network event's target (strace's sockaddr text) name host:port?"""
    return f"sin_port=htons({port})" in target and f'inet_addr("{host}")' in target


# (#142) strace -y prints the socket behind an fd: bind(3<socket:[22946]>, ...).
SOCKET_INODE_RE = re.compile(r"\b(?:bind|listen|accept4?)\(\d+<socket:\[(\d+)\]>")
# The two loopback addresses with port 0, as strace prints them.
LOOPBACK_PORT0 = (('inet_addr("127.0.0.1")', "sin_port=htons(0)"),
                  ('inet_pton(AF_INET6, "::1"', "sin6_port=htons(0)"))


def _socket_inode(raw: str) -> str | None:
    match = SOCKET_INODE_RE.search(raw)
    return match[1] if match else None


def _listening_sockets(events: list[Event]) -> set[str]:
    """The sockets (by inode) that listen() or accept() anywhere in the trace."""
    return {inode for e in events
            if e.kind == "network" and e.syscall in ("listen", "accept", "accept4")
            and (inode := _socket_inode(e.raw)) is not None}


def _is_ipv6_probe_bind(event: Event, listening: set[str]) -> bool:
    """A bind() to 127.0.0.1 or ::1 with port 0, on a socket that never
    listens or accepts (#142). urllib3 does this to check whether IPv6 works:
    such a socket can't receive anything. A real port, another address, or a
    listen() on the same socket is still a violation, and so is anything the
    socket then connects to or sends."""
    if event.syscall != "bind":
        return False
    inode = _socket_inode(event.raw)
    return (inode is not None and inode not in listening
            and any(address in event.target and port in event.target
                    for address, port in LOOPBACK_PORT0))


def _baseline_exec(event: Event, policy: Policy) -> dict | None:
    """The baseline's exec_exact entry this exec matches (#142): same path,
    same whole argv. None if it doesn't match one exactly."""
    for entry in policy.baseline_exec_exact:
        if event.target == entry["path"] and exec_argv(event.raw) == entry["argv"]:
            return entry
    return None


def _sink_request(target: str) -> tuple[str, str, int] | None:
    """(method, host, port) from a sink marker path like /sandglass-netsink/GET/example.com/80."""
    parts = target[len(netsink.SINK_MARKER_DIR) + 1:].split("/")
    if not target.startswith(netsink.SINK_MARKER_DIR + "/") or len(parts) != 3 or not parts[2].isdigit():
        return None
    return parts[0], parts[1], int(parts[2])


# (#136) A sink record with no domain: the connection sent nothing readable.
UNIDENTIFIED = "unidentified connection to the sink"
UNIDENTIFIED_TARGET = "(unidentified)"


def _connects_to_sink(events: list[Event], sink_pid: int | None) -> int:
    """How many connections to the sink the trace shows (#136): connect()s to
    its address that worked (or are completing: EINPROGRESS), from anyone but
    the sink itself. The sink makes exactly one record per connection."""
    return sum(1 for e in events
               if e.kind == "network" and e.syscall == "connect" and e.pid != sink_pid
               and _is_address(e.target, netsink.SINK_HOST, netsink.SINK_PORT)
               and (e.succeeded or e.error == "EINPROGRESS"))


def _domain_allowed(host: str, policy: Policy) -> bool:
    """network.allow -> everything; else exact match or a "*.example.com" suffix rule."""
    if policy.network_allow:
        return True
    for domain in policy.allow_domains:
        if host == domain or (domain.startswith("*.") and host.endswith(domain[1:])):
            return True
    return False


PHASES = ("install", "startup", "tool-call", "unknown")
# Event kinds counted in every report ("evasion": #84).
EVENT_KINDS = ("file", "probe", "process", "network", "io_uring", "evasion", "exit")


def _first_pid_to_stat(events: list[Event], path: str) -> int | None:
    """The pid of the FIRST process to stat a marker path (Sandglass's own helpers)."""
    for event in events:
        if event.kind == "probe" and event.target == path:
            return event.pid
    return None


# Sandglass's helpers (the network sink and the stdin relay) run as the same
# user as the server, so an event in a helper's pid isn't proof the helper's
# own code did it (#99). Only an exact list of each helper's known events is
# skipped; everything else from those pids is judged like the server's.

def _helper_exec(events: list[Event], pid: int | None) -> Event | None:
    """A helper's own launch: the FIRST event of its pid, if that is a
    successful exec of the venv Python (the launcher posix_spawns it)."""
    first = next((e for e in events if e.pid == pid), None)
    if (first is not None and first.kind == "process" and first.succeeded
            and first.target == str(sandbox.CONTAINER_PYTHON)):
        return first
    return None


RELAY_MARKERS = {stdin_relay.RELAY_READY, stdin_relay.TOOL_CALL_MARKER, stdin_relay.EOF_MARKER,
                 stdin_relay.SERVER_EXITED_MARKER, stdin_relay.SERVER_STOPPED_MARKER}
# In the report when the relay had to stop the server after eof (#140).
SERVER_STOPPED_NOTE = ("the server did not exit after the client closed its stdin "
                       f"(within {stdin_relay.STOP_GRACE_SECONDS:g} s); Sandglass stopped it")

# Statuses of a call the server never answered (client.py, #140). Every other
# status (OK, ERROR, UNEXPECTED) means the server answered: the call completed.
NO_ANSWER_STATUSES = {"TIMED OUT", "NO ANSWER", "FAILED"}
# The relay ends normally with one of these: the client closed stdin, or the
# server exited while the client was still connected (#24).
RELAY_NORMAL_ENDS = {stdin_relay.EOF_MARKER, stdin_relay.SERVER_EXITED_MARKER}


def _is_relay_own(event: Event, relay_exec: Event | None) -> bool:
    """The relay's known events: its launch and its marker stats."""
    return event is relay_exec or (event.kind == "probe" and event.target in RELAY_MARKERS)


def _is_sink_own(event: Event, sink_exec: Event | None, before_ready: bool) -> bool:
    """The sink's known events, apart from its request records (handled in compare()):
    its launch, its ready marker, its proxy socket, the isolation check (its
    connect, and the marker reporting the outcome, read by _isolation), and
    (#141) its read of /etc/resolv.conf before "ready" and the markers
    reporting the nameservers (read by _resolvers)."""
    if event is sink_exec:
        return True
    if event.kind == "probe":
        return (event.target == netsink.SINK_READY
                or event.target.startswith(netsink.ISOLATION_MARKER_DIR + "/")
                or event.target.startswith(netsink.RESOLVER_MARKER_DIR + "/"))
    if event.kind == "file":
        return (before_ready and event.mode == "read" and event.target == netsink.RESOLVER_FILE
                and event.opened in (None, netsink.RESOLVER_FILE))
    if event.kind != "network":
        return False
    if event.syscall == "bind":
        return _is_address(event.target, netsink.SINK_HOST, netsink.SINK_PORT)
    if event.syscall == "listen":
        return True
    if event.syscall in ("accept", "accept4"):
        # A client of the proxy, which only listens on loopback (or no client yet).
        return not event.succeeded or f'inet_addr("{netsink.SINK_HOST}")' in event.target
    if event.syscall == "connect":
        return _is_address(event.target, *netsink.ISOLATION_CHECK)
    return False


def _resolvers(events: list[Event], sink_pid: int | None) -> list[str] | None:
    """The container's nameservers, as the sink reported them (#141), or None
    if they are unknown (no report before "ready", or the file was unreadable).
    Only the sink's markers before its ready marker count, like _isolation."""
    found = []
    for event in events:
        if event.pid != sink_pid or event.kind != "probe":
            continue
        if event.target == netsink.SINK_READY:
            return None  # ready without a complete report
        prefix = netsink.RESOLVER_MARKER_DIR + "/"
        if event.target == prefix + "done":
            return found
        if event.target == prefix + "unreadable":
            return None
        if event.target.startswith(prefix + "nameserver/"):
            found.append(event.target[len(prefix + "nameserver/"):])
    return None


def _isolation(events: list[Event], sink_pid: int | None) -> dict | None:
    """The sink's own report of the isolation check (#100), or None if missing.

    Only the sink's FIRST isolation marker counts, and only if it comes before
    the sink's ready marker (so before any server code ran). The connect's
    errno isn't used: with a timeout it's EINPROGRESS even when the connect
    then succeeds, so only the sink, after the connect finished, can tell.
    """
    for event in events:
        if event.pid != sink_pid or event.kind != "probe":
            continue
        if event.target == netsink.SINK_READY:
            return None  # ready without having reported the check
        if event.target.startswith(netsink.ISOLATION_MARKER_DIR + "/"):
            result, _, outcome = event.target[len(netsink.ISOLATION_MARKER_DIR) + 1:].partition("/")
            return {"target": "%s:%d" % netsink.ISOLATION_CHECK, "isolated": result == "isolated",
                    "outcome": outcome, "evidence": event.raw}
    return None


def _phase_of(events: list[Event], session: dict, relay_pid: int | None):
    """Return (function: event index -> phase, note explaining "unknown" or None).

    The boundary is the position of the relay's tool-call marker in the trace.
    Positions, not timestamps: no clock is involved, so a VM clock that is a
    few ms off the host's can't move an event into the wrong phase.
    """
    if relay_pid is None:
        return (lambda index: "unknown"), "the stdin relay did not start, so there is no tool-call marker"
    boundary = next((i for i, e in enumerate(events) if e.pid == relay_pid
                     and e.kind == "probe" and e.target == stdin_relay.TOOL_CALL_MARKER), None)
    if boundary is not None:
        return (lambda index: "tool-call" if index > boundary else "startup"), None
    if session.get("calls"):
        # Tools were called but the relay never marked it: don't guess.
        return (lambda index: "unknown"), "tools were called, but the tool-call marker is missing from the trace"
    return (lambda index: "startup"), None  # the relay saw every message: no tool call


def _relay_problem(events: list[Event], relay_pid: int | None) -> str | None:
    """Why the relay can't be trusted, or None. A normal end is its eof (or
    server-exited) marker followed by a clean exit; anything else means it
    died or was killed early."""
    if relay_pid is None:
        return "the stdin relay did not start, so the tool-call phase can't be found"
    saw_eof = any(e.pid == relay_pid and e.kind == "probe" and e.target in RELAY_NORMAL_ENDS
                  for e in events)
    exit_event = next((e for e in events if e.pid == relay_pid and e.kind == "exit"), None)
    if saw_eof and exit_event is not None and exit_event.target == "exited with 0":
        return None
    how = exit_event.target if exit_event else "no exit record"
    return (f"the stdin relay exited or was killed before the run ended ({how}); "
            "the server may have tampered with it")


def _bucket_for_failure_or_success(event: Event) -> str:
    """Shared rule for files and execs: 'violation' or 'attempted'."""
    if event.succeeded or event.error in BLOCKED_ERRORS:
        return "violation"
    return "attempted"


def _record(event: Event, reason: str, phase: str, target: str | None = None) -> dict:
    """One reported event (a violation or an attempt). `target` overrides the
    event's path, e.g. a link's target or the file an open really opened."""
    record = {
        "reason": reason,
        "syscall": event.syscall,
        "target": target or event.target,
        "mode": event.mode,
        "timestamp": event.timestamp,
        "phase": phase,
        "pid": event.pid,
        "succeeded": event.succeeded,
        "error": event.error,
        "evidence": event.raw,
    }
    if event.opened and event.opened != event.target:
        # Both paths of an open through a symlink (#122).
        record["requested"], record["opened"] = event.target, event.opened
    return record


def _file_problems(event: Event, allowed, readable, reason_for, link_reason: str) -> list[tuple[str, str]]:
    """What's wrong with one file event: (reason, target) pairs, [] if nothing.

    Shared by the server's run and the install (#122), so links are judged
    the same way in every phase:
      - the requested path AND, for a successful open, the file really opened
        (strace -y): a violation if EITHER is not allowed (or in read_deny).
        One record per open, naming the first bad path, with both paths in
        its reason ("requested X, opened Y").
      - a new symlink or hard link counts as a READ of where it points (#16):
        a link in /tmp to ~/.aws/credentials would otherwise make reading the
        credentials look like reading /tmp.
    `allowed(path)` judges the event's own mode, `readable(path)` a read,
    `reason_for(path)` words the first kind of problem.
    """
    problems = []
    for path in dict.fromkeys(p for p in (event.target, event.opened) if p):  # requested, then opened
        if not allowed(path):
            reason = reason_for(path)
            if event.opened and event.opened != event.target:
                reason += f" (requested {event.target}, opened {event.opened})"
            problems.append((reason, path))
            break
    if event.link_target and not readable(event.link_target):
        problems.append((link_reason, event.link_target))
    return problems


def _program(event: Event, phase: str, note: str | None = None) -> dict:
    """One successful exec for the report's "Programs run" section (#120).
    Listed whether it was allowed or not: this is visibility, not a verdict."""
    return {"pid": event.pid, "timestamp": event.timestamp, "phase": phase,
            "path": event.target, "argv": exec_argv(event.raw), "note": note,
            "evidence": event.raw}


def compare(events: list[Event], policy: Policy, session: dict, runtime: str = "python",
            trace_cut_short: bool = False) -> dict:
    """Apply the rules above. Returns a plain dict (ready for JSON).

    `runtime` is "node" for a .js server: the launcher's exec of node is then
    part of the launch, not a violation.
    `trace_cut_short` means only the first MAX_TRACE_BYTES of the trace were
    read (#83), so events are missing: INCOMPLETE.
    """
    violations: list[dict] = []
    attempted: list[dict] = []
    probes: dict[str, dict] = {}  # path -> summary, deduplicated

    # Reads may come from the policy, the runtime (interpreter, venv, server
    # source) and the container baseline (libc, locale, ...).
    read_ok = policy.read_allow + policy.runtime_allow + policy.baseline_read_allow
    # Writes may ONLY go where the policy explicitly says. runtime_allow and the
    # baseline are deliberately left out: a server rewriting a library in /opt/venv
    # or /lib is exactly what we want to catch.
    write_ok = policy.write_allow
    server_launch: Event | None = None
    node_launch: Event | None = None  # runtime "node" only
    sink_pid = _first_pid_to_stat(events, netsink.SINK_READY)
    relay_pid = _first_pid_to_stat(events, stdin_relay.RELAY_READY)
    sink_exec, relay_exec = _helper_exec(events, sink_pid), _helper_exec(events, relay_pid)
    phase_of, phase_note = _phase_of(events, session, relay_pid)
    domains: list[dict] = []       # every request the sink recorded
    isolation = _isolation(events, sink_pid)  # the sink's own report of its check (#100)
    resolvers = _resolvers(events, sink_pid)  # the container's nameservers, or None (#141)
    sink_ready_index = next((i for i, e in enumerate(events) if e.pid == sink_pid and e.kind == "probe"
                             and e.target == netsink.SINK_READY), len(events))
    io_uring_used: list[Event] = []  # io_uring calls that succeeded (#75)
    evaded: list[Event] = []         # evasions that worked (#84): a child or memory strace can't see
    unidentified: list[Event] = []   # sink records with no domain, when some domains are allowed (#136)
    self_test, filter_problem = _filter_self_test(events, sink_pid)  # the syscall filter's (#84)
    unreadable: list[Event] = []     # file/stat events whose path strace couldn't read (#98)
    server_errors: list[str] = []    # the server's own error messages, via the launcher (#24)
    programs: list[dict] = []        # every successful exec, allowed or not (#120)
    listening = _listening_sockets(events)  # sockets that listen() or accept() (#142)

    for index, event in enumerate(events):
        if event.kind == "process" and event.succeeded:
            note = None
            if server_launch is None:
                note = "Sandglass's launcher, which then starts the server"
            elif event is sink_exec:
                note = "Sandglass's network sink"
            elif event is relay_exec:
                note = "Sandglass's stdin relay"
            elif _baseline_exec(event, policy):
                note = _baseline_exec(event, policy)["note"]  # e.g. uname -p (#142)
            programs.append(_program(event, phase_of(index), note))

        if event.kind in ("file", "probe") and event.target == UNREADABLE:
            # Fail closed: we can't tell what was touched, so we can't judge
            # it against any allow-list. From any pid; INCOMPLETE below.
            unreadable.append(event)
            continue

        if any(event is own for own in self_test):
            continue  # the launcher's filter self-test (#84), judged by _filter_self_test

        if event.pid == relay_pid and _is_relay_own(event, relay_exec):
            continue  # the relay's launch and markers; anything else it does is judged (#99)

        if event.pid == sink_pid and _is_sink_own(event, sink_exec, index < sink_ready_index):
            continue  # the sink's launch, ready marker, proxy socket, isolation check (#99)

        if (server_launch is not None and event.pid == server_launch.pid and event.kind == "probe"
                and event.target.startswith(launcher.SERVER_ERROR_DIR + "/")):
            # The launcher's record of the server's own error message (#24).
            server_errors.append(event.target[len(launcher.SERVER_ERROR_DIR) + 1:])
            continue

        request = _sink_request(event.target) if event.pid == sink_pid and event.kind == "probe" else None
        if request is not None:
            # A request the sink recorded: the domain the server asked for.
            method, host, port = request
            allowed = _domain_allowed(host, policy)
            domains.append({"method": method, "host": host, "port": port,
                            "allowed": allowed, "timestamp": event.timestamp,
                            "phase": phase_of(index)})
            if allowed:
                continue
            reason = "contacted a domain not in network.allow_domains"
            if host == netsink.INVALID:
                # (#136) The sink couldn't read a domain from this connection
                # (nothing sent, or not a proxy request). With no domains
                # allowed at all it's a violation like any other; if some are
                # allowed, it might have been one of them or not: INCOMPLETE.
                if policy.allow_domains:
                    unidentified.append(event)
                    continue
                reason, host = UNIDENTIFIED, UNIDENTIFIED_TARGET
            bucket = "violation"
            event = Event("domain", "proxy request", event.pid, event.timestamp, host,
                          "domain", True, None, event.raw)

        elif event.kind == "file":
            def readable(path: str) -> bool:
                return _is_under(path, read_ok) and not _is_under(path, policy.read_deny)

            def allowed(path: str, mode=event.mode) -> bool:
                if mode == "write":
                    # The baseline's write_exact (#142): that exact file only.
                    return _is_under(path, write_ok) or path in policy.baseline_write_exact
                if mode == "list":
                    # Exact entries match only the directory itself, never its children.
                    return readable(path) or (path in map(str, policy.list_exact)
                                              and not _is_under(path, policy.read_deny))
                return readable(path)

            # The requested path, the file really opened, and a link's target (#122).
            problems = _file_problems(
                event, allowed, readable,
                lambda path: _file_reason(event.mode, path, policy.read_deny),
                "linked to a path outside allowed reads")
            for reason, target in problems:
                (violations if _bucket_for_failure_or_success(event) == "violation" else attempted).append(
                    _record(event, reason, phase_of(index), target))
            continue

        elif event.kind == "probe":
            if _is_under(event.target, read_ok) and not _is_under(event.target, policy.read_deny):
                continue
            # One entry per path, counting calls per syscall, e.g.
            # /project/test_servers -> {"newfstatat": 150, "readlinkat": 7}
            entry = probes.setdefault(event.target, {
                "path": event.target, "count": 0, "syscalls": {},
                "first_timestamp": event.timestamp,
                "phase": phase_of(index),  # of the first occurrence
            })
            entry["count"] += 1
            entry["syscalls"][event.syscall] = entry["syscalls"].get(event.syscall, 0) + 1
            continue

        elif event.kind == "process":
            if server_launch is None and event.succeeded:
                server_launch = event  # strace launching the server itself
                continue
            if (runtime == "node" and node_launch is None and event.succeeded
                    and event.pid == server_launch.pid and event.target == str(sandbox.CONTAINER_NODE)):
                node_launch = event  # the launcher handing over to node, same process
                continue
            if _is_under(event.target, policy.exec_allow):
                continue
            if _baseline_exec(event, policy):
                continue  # e.g. uname -p (#142): listed under "Programs run", not a violation
            reason = "process exec not in exec_allow"
            bucket = _bucket_for_failure_or_success(event)

        elif event.kind == "network":
            if policy.network_allow:
                continue
            # Talking to the sink is fine if it worked: the sink records the
            # domain itself. A FAILED connect to it (e.g. the server killed the
            # sink first) could hide where it wanted to go, so it counts.
            if (event.syscall == "connect" and _is_address(event.target, netsink.SINK_HOST, netsink.SINK_PORT)
                    and (event.succeeded or event.error == "EINPROGRESS")):
                continue
            if _is_ipv6_probe_bind(event, listening):
                continue  # urllib3 checking whether IPv6 works (#142)
            reason = "network activity while network.allow is false"
            bucket = "violation"  # attempts count, even failed ones

        elif event.kind == "io_uring":
            if event.succeeded:
                # A working ring means file access we can't see: INCOMPLETE below.
                io_uring_used.append(event)
                continue
            reason = "io_uring blocked (file access through it would be invisible to strace)"
            bucket = "attempted"

        elif event.kind == "evasion":
            # (#84) Refused by the filter or not, trying is a violation: no
            # MCP server needs an untraced child or another process's memory.
            # If it worked, what followed is missing from the trace: INCOMPLETE below.
            if event.succeeded:
                evaded.append(event)
            reason = EVADE_REASON
            bucket = "violation"

        else:
            continue  # exit events are only used for the completeness check

        (violations if bucket == "violation" else attempted).append(_record(event, reason, phase_of(index)))

    # (#140) Only the relay's own marker counts: the server could stat that path too (#99).
    server_stopped = relay_pid is not None and any(
        e.pid == relay_pid and e.kind == "probe" and e.target == stdin_relay.SERVER_STOPPED_MARKER
        for e in events)
    incomplete = _incomplete_reasons(events, server_launch, session)
    startup_exit = _startup_exit_reason(events, server_launch, relay_pid, session, server_errors)
    if startup_exit:
        incomplete.append(startup_exit)
    if trace_cut_short:
        limit = MAX_TRACE_BYTES // (1024 * 1024)
        incomplete.append(f"the trace is larger than {limit} MiB; only the first {limit} MiB were "
                          "checked, so later events are missing")
    if events and sink_pid is None:
        incomplete.append("the network sink did not start, so contacted domains can't be recorded")
    elif events and isolation is None:
        incomplete.append("the network isolation result is missing from the trace")
    elif isolation and not isolation["isolated"]:
        incomplete.append("the sandbox may reach the internet: isolation check "
                          f"(connect to {isolation['target']}) outcome {isolation['outcome']}")
    relay_problem = _relay_problem(events, relay_pid) if events else None
    if relay_problem:
        incomplete.append(relay_problem)
    if unreadable:
        incomplete.append(f"{len(unreadable)} file event(s) with a path strace couldn't read "
                          "(the process may have stopped strace from reading its memory); "
                          f"first: {unreadable[0].raw}")
    if io_uring_used:
        incomplete.append(f"{IO_URING_INCOMPLETE} ({len(io_uring_used)} successful io_uring "
                          f"call(s), first: {io_uring_used[0].raw})")
    if filter_problem and events:
        incomplete.append(filter_problem)
    if unidentified:
        incomplete.append(f"a request could not be attributed to a domain: {len(unidentified)} "
                          f"{UNIDENTIFIED}(s), first: {unidentified[0].raw}")
    connects = _connects_to_sink(events, sink_pid)
    if sink_pid is not None and connects != len(domains):
        # (#136) Every connection to the sink gets exactly one record. A
        # different count means a request went unrecorded (or a record is fake).
        incomplete.append(f"the trace shows {connects} connection(s) to the network sink but the sink "
                          f"recorded {len(domains)} request(s); a request may be missing")
    if evaded:
        incomplete.append(f"{EVADED_INCOMPLETE} ({len(evaded)} call(s), first: {evaded[0].raw})")
    if incomplete:
        verdict = "INCOMPLETE"
    elif violations:
        verdict = "VIOLATIONS"
    else:
        verdict = "CLEAN"

    return {
        "verdict": verdict,
        "incomplete_reasons": incomplete,
        "violations": violations,
        "attempted": attempted,
        "probes": sorted(probes.values(), key=lambda p: p["first_timestamp"]),
        "domains": domains,
        "network_isolation": isolation,
        "resolvers": resolvers,  # None: unknown (#141)
        "phase_note": phase_note,
        "server_stopped": server_stopped,  # the relay killed it after eof (#140)
        "programs": programs,
        "event_counts": {
            kind: sum(1 for e in events if e.kind == kind)
            for kind in EVENT_KINDS
        },
    }


def _incomplete_reasons(events: list[Event], server_launch: Event | None, session: dict) -> list[str]:
    """Everything that means 'we didn't observe a full, trustworthy run'."""
    reasons = []
    if session.get("error"):
        reasons.append(f"MCP session failed: {session['error']}")
    calls = session.get("calls", [])
    if not calls:
        reasons.append("no tools were exercised")
    elif not any(c.get("status") not in NO_ANSWER_STATUSES for c in calls):
        # (#140) Timed-out tools alone don't make a run INCOMPLETE, but at
        # least one tool must have been answered.
        reasons.append("no tool call completed (every call timed out or got no answer)")
    if not events:
        reasons.append("trace is missing or empty")
    elif server_launch is None:
        reasons.append("trace does not show the server being launched")
    elif not any(e.kind == "exit" and e.pid == server_launch.pid for e in events):
        # If strace is killed mid-run, the end of the trace (including this
        # line) is missing, and so might be the very events we care about.
        reasons.append("trace has no exit record for the server process (possibly truncated)")
    return reasons


def _startup_exit_reason(events: list[Event], server_launch: Event | None, relay_pid: int | None,
                         session: dict, server_errors: list[str]) -> str | None:
    """'The server exited during startup', or None (#24).

    True when no tool was called and the server's process exited before the
    client hung up: its exit record comes before the relay's eof marker (or
    there is no eof marker; the relay then saw the server go, server-exited).
    A server that quits on its own this early usually needs something it
    doesn't have, e.g. an API key or a real account.
    """
    if session.get("calls") or server_launch is None:
        return None
    exit_index = next((i for i, e in enumerate(events)
                       if e.kind == "exit" and e.pid == server_launch.pid), None)
    if exit_index is None:
        return None
    eof_index = next((i for i, e in enumerate(events) if e.pid == relay_pid and e.kind == "probe"
                      and e.target == stdin_relay.EOF_MARKER), None)
    if eof_index is not None and eof_index < exit_index:
        return None  # the client closed the connection first: a normal shutdown
    reason = f"the server exited during startup ({events[exit_index].target}) before any tool call"
    if server_errors:
        # Recorded inside the server's own process, so the server could fake
        # it. It only explains a run that is INCOMPLETE anyway.
        reason += f"; its error message (as the server reported it): {server_errors[-1]}"
    return reason


# ---------------------------------------------------------------------------
# Install phase (#16): `sandglass scan` traces the install too
# ---------------------------------------------------------------------------

# How strace prints the loopback addresses in a sockaddr.
LOOPBACK_ADDRESSES = ('inet_addr("127.0.0.1")', 'inet_pton(AF_INET6, "::1"')


def compare_install(events: list[Event], policy: Policy, baseline: InstallBaseline,
                    exit_code: int | None, log: str = "", trace_cut_short: bool = False) -> dict:
    """Judge the install trace. Every reported event gets phase "install".

    Allowed (beyond the policy's own read_allow / write_allow / exec_allow):
      reads     the install baseline (sandglass/baselines/install.yaml: what
                pip and npm read, plus both runtimes' startup reads), and
                listing its exact folders (/etc) but nothing inside them
      writes    /package, /tmp, /dev/null (nothing else is writable anyway)
      programs  the first exec (the installer's shell), then the baseline's
                sh / cp / env / node / npm / Python / uname
      network   sockets of a family that can't leave the machine (AF_NETLINK),
                and bind() to the loopback address (pip checking for IPv6)
    A new symlink or hard link counts as a READ of where it points: a link in
    /tmp to ~/.aws/credentials would otherwise make that read look allowed.
    Everything else follows the same rules as the server's run (violation /
    attempted / probe; unreadable path or working io_uring -> INCOMPLETE).
    The install failing or timing out -> INCOMPLETE, with the end of its log.
    """
    read_ok = policy.read_allow + baseline.read_allow
    write_ok = policy.write_allow + baseline.write_allow
    exec_ok = policy.exec_allow + baseline.exec_allow
    violations, attempted, probes, incomplete = [], [], {}, []
    unreadable, io_uring_used, programs, evaded = [], [], [], []
    launch: Event | None = None

    def readable(path: str) -> bool:
        """Allowed to read: under read_ok and not in read_deny (deny wins, #121)."""
        return _is_under(path, read_ok) and not _is_under(path, policy.read_deny)

    def record(event: Event, reason: str, bucket: str, target: str | None = None) -> None:
        (violations if bucket == "violation" else attempted).append(
            _record(event, reason, "install", target))

    for event in events:
        if event.kind in ("file", "probe") and event.target == UNREADABLE:
            unreadable.append(event)
        elif event.kind == "file":
            def allowed(path: str, mode=event.mode) -> bool:
                if mode == "write":
                    return _is_under(path, write_ok)
                if mode == "list" and path in map(str, baseline.list_exact):
                    # e.g. pip listing /etc: that folder only, nothing inside it
                    return not _is_under(path, policy.read_deny)
                return readable(path)

            def reason_for(path: str, mode=event.mode) -> str:
                if mode == "write":
                    return "install wrote outside /package and /tmp"
                return _file_reason(mode, path, policy.read_deny, "install ")

            # Same rules as the server's run (#122): requested and opened path, links.
            for reason, target in _file_problems(event, allowed, readable, reason_for,
                                                 "install linked to a path outside allowed reads"):
                record(event, reason, _bucket_for_failure_or_success(event), target=target)
        elif event.kind == "probe":
            if not readable(event.target):
                entry = probes.setdefault(event.target, {
                    "path": event.target, "count": 0, "syscalls": {},
                    "first_timestamp": event.timestamp, "phase": "install"})
                entry["count"] += 1
                entry["syscalls"][event.syscall] = entry["syscalls"].get(event.syscall, 0) + 1
        elif event.kind == "process":
            if event.succeeded:  # "Programs run" (#120): every successful exec
                programs.append(_program(event, "install",
                                         "the installer's shell" if launch is None else None))
            if launch is None and event.succeeded:
                launch = event  # strace starting the installer's shell
            elif not _is_under(event.target, exec_ok):
                # A failed exec didn't run anything (#120): "tried to run".
                did = "ran" if event.succeeded else "tried to run"
                record(event, f"install {did} a program not in the install baseline or exec_allow",
                       _bucket_for_failure_or_success(event))
        elif event.kind == "network":
            family = re.search(r"sa_family=(\w+)", event.target)
            local_family = family is not None and family[1] in baseline.network_families_allow
            loopback_bind = (baseline.loopback_bind_allow and event.syscall == "bind"
                             and any(address in event.target for address in LOOPBACK_ADDRESSES))
            if not policy.network_allow and not local_family and not loopback_bind:
                record(event, "network activity during the install", "violation")
        elif event.kind == "io_uring":
            if event.succeeded:
                io_uring_used.append(event)
            else:
                record(event, "io_uring blocked (file access through it would be invisible to strace)",
                       "attempted")
        elif event.kind == "evasion":
            # (#84) Same rule as the server's run. The install has no launcher,
            # so nothing refuses these here: one that worked hid what followed.
            record(event, f"install {EVADE_REASON}", "violation")
            if event.succeeded:
                evaded.append(event)

    if exit_code is None:
        incomplete.append("the install took too long and was stopped")
    elif exit_code != 0:
        incomplete.append(f"the install failed (exit {exit_code}); the server was not run"
                          + (f". End of the install log: {log}" if log else ""))
    if not events:
        incomplete.append("the install trace is missing or empty")
    elif launch is None:
        incomplete.append("the install trace does not show the installer being launched")
    elif not any(e.kind == "exit" and e.pid == launch.pid for e in events):
        incomplete.append("the install trace has no exit record for the installer (possibly truncated)")
    if trace_cut_short:
        limit = MAX_TRACE_BYTES // (1024 * 1024)
        incomplete.append(f"the install trace is larger than {limit} MiB; only the first {limit} MiB "
                          "were checked")
    if unreadable:
        incomplete.append(f"{len(unreadable)} install file event(s) with a path strace couldn't read; "
                          f"first: {unreadable[0].raw}")
    if io_uring_used:
        incomplete.append(f"{IO_URING_INCOMPLETE} (during the install: {len(io_uring_used)} "
                          f"successful io_uring call(s), first: {io_uring_used[0].raw})")
    if evaded:
        incomplete.append(f"{EVADED_INCOMPLETE} (during the install: {len(evaded)} call(s), "
                          f"first: {evaded[0].raw})")

    return {
        "incomplete_reasons": incomplete,
        "violations": violations,
        "attempted": attempted,
        "probes": sorted(probes.values(), key=lambda p: p["first_timestamp"]),
        "programs": programs,
        "event_counts": {kind: sum(1 for e in events if e.kind == kind)
                         for kind in EVENT_KINDS},
    }


def with_install(result: dict, install: dict) -> dict:
    """The run's compare() result with the install phase added in front of it.

    The install's findings come first (they happened first), and the verdict
    covers both phases: INCOMPLETE if either is, else VIOLATIONS if either
    has one, else CLEAN.
    """
    merged = dict(result)
    for key in ("incomplete_reasons", "violations", "attempted", "probes", "programs"):
        merged[key] = install.get(key, []) + result.get(key, [])
    if merged["incomplete_reasons"]:
        merged["verdict"] = "INCOMPLETE"
    elif merged["violations"]:
        merged["verdict"] = "VIOLATIONS"
    else:
        merged["verdict"] = "CLEAN"
    return merged


# ---------------------------------------------------------------------------
# Coverage (#23): which tools ran, failed, or were skipped
# ---------------------------------------------------------------------------

COVERAGE_REASON_CHARS = 200  # error texts are cut to this length in the coverage table
COVERAGE_STATUSES = ("ran", "returned an error", "failed", "timed out", "not called", "skipped")
COVERAGE_KEYS = {"returned an error": "returned_error"}  # its key in the totals
# MCP errors that are not an answer from the server: the SDK raises them
# itself when the call timed out or the connection closed (#143).
NOT_AN_ANSWER_CODES = {REQUEST_TIMEOUT, CONNECTION_CLOSED}


def _returned_an_error(call: dict) -> bool:
    """The server answered the call with an error (#143): a result with
    isError set, or a JSON-RPC error response. Only these two MCP signals
    count; the result's text is never read, since a tool that worked can
    return text that mentions an error."""
    if call["status"] == "ERROR":
        return True
    return call["status"] == "FAILED" and call.get("error_code") not in NOT_AN_ANSWER_CODES | {None}


def coverage(session: dict) -> dict:
    """One row per tool the server listed, plus totals:

      ran                the call returned a normal result
      returned an error  the server answered with an error (#143): isError
                         set, or a JSON-RPC error response
      failed             the call raised, got an unexpected result, or got no
                         answer before the session ended
      timed out          no answer within the call's timeout (#140); the next
                         tool was still called
      not called         the calls had stopped first (#140): the time budget
                         was used up, or the server stopped answering after a timeout
      skipped            no valid input could be built (#22), or the session ended first

    Coverage is reported, not judged: it never changes the verdict.
    """
    calls = {c["tool"]: c for c in session.get("calls", [])}
    skipped = {s["tool"]: s["reason"] for s in session.get("skipped", [])}
    not_called = {s["tool"]: s["reason"] for s in session.get("not_called", [])}
    rows = []
    for tool in session.get("tools", []):
        name = tool["name"]
        if name in calls:
            call = calls[name]
            if call["status"] == "OK":
                rows.append({"tool": name, "status": "ran", "reason": None})
            elif call["status"] == "TIMED OUT":
                rows.append({"tool": name, "status": "timed out", "reason": call["result"]})
            else:
                text = " ".join(str(call["result"]).split())[:COVERAGE_REASON_CHARS]
                status = "returned an error" if _returned_an_error(call) else "failed"
                rows.append({"tool": name, "status": status, "reason": f"{call['status']}: {text}"})
        elif name in skipped:
            rows.append({"tool": name, "status": "skipped", "reason": skipped[name]})
        elif name in not_called:
            rows.append({"tool": name, "status": "not called", "reason": not_called[name]})
        else:
            why = f": {session['error']}" if session.get("error") else ""
            rows.append({"tool": name, "status": "skipped",
                         "reason": f"not called, the session ended first{why}"})

    # Totals keys use "_" for the statuses with a space: timed_out, not_called;
    # "returned an error" is returned_error.
    totals = {COVERAGE_KEYS.get(status, status.replace(" ", "_")):
              sum(1 for r in rows if r["status"] == status)
              for status in COVERAGE_STATUSES}
    totals["total"] = len(rows)
    note = None
    if not rows:
        note = ("the server's tool list was never received" if session.get("error")
                else "the server listed no tools")
    return {"tools": rows, "totals": totals, "note": note}


# The coverage summary's wording (#143), in this order; only counts above 0 show.
SUMMARY_WORDS = [("returned_error", "returned errors"), ("failed", "failed"),
                 ("timed_out", "timed out"), ("not_called", "not called"), ("skipped", "skipped")]


def coverage_summary(cov: dict | None) -> str | None:
    """Every tool that didn't run normally, in one phrase for the verdict line
    (#143), e.g. "6 of 9 tools returned errors" or "1 of 4 tools timed out,
    1 not called". None if every tool ran, or if no tools were listed (the
    coverage note and the INCOMPLETE reasons say why). Any count shows: a
    CLEAN verdict only covers what ran."""
    if not cov or not cov["tools"]:
        return None
    t = cov["totals"]
    parts = [f"{t[key]} {words}" for key, words in SUMMARY_WORDS if t.get(key)]
    if not parts:
        return None
    # The first part names the total: "6 of 9 tools returned errors".
    count, words = parts[0].split(" ", 1)
    parts[0] = f"{count} of {t['total']} {'tool' if t['total'] == 1 else 'tools'} {words}"
    return ", ".join(parts)


def verdict_line(r: dict) -> str:
    """The verdict with its coverage summary (#143): "but" after CLEAN, "and"
    otherwise. The verdict word itself never changes."""
    summary = r.get("coverage_summary")
    if not summary:
        return r["verdict"]
    return f"{r['verdict']} ({'but' if r['verdict'] == 'CLEAN' else 'and'} {summary})"


# ---------------------------------------------------------------------------
# Violation groups (#141): one entry per domain, per lookup, per address
# ---------------------------------------------------------------------------

# Where glibc asks the name service cache daemon (absent in the image) first.
NSCD_SOCKETS = ("/var/run/nscd/socket", "/run/nscd/socket")
NAME_LOOKUPS = "name lookups: domain not recorded (see #147)"
SOCKADDR_RE = {
    "AF_UNIX": re.compile(r'sa_family=AF_UNIX, sun_path="([^"]*)"'),
    "AF_INET": re.compile(r'sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)'),
    "AF_INET6": re.compile(r'sa_family=AF_INET6, sin6_port=htons\((\d+)\),.*?inet_pton\(AF_INET6, "([^"]+)"'),
}


def _sockaddr(target: str) -> tuple[str, str, int | None] | None:
    """(family, address, port) from strace's sockaddr text, or None.
    An AF_UNIX socket has a path instead of an address, and no port."""
    for family, pattern in SOCKADDR_RE.items():
        match = pattern.search(target)
        if match and family == "AF_UNIX":
            return family, match[1], None
        if match:
            return family, match[2], int(match[1])
    return None


def _group_key(v: dict, index: int, resolvers: list[str] | None) -> tuple[tuple, str, str | None]:
    """(key, label, breakdown line) of one violation record. Records with the
    same key (always within one phase) form one entry."""
    phase = v.get("phase")
    if v["syscall"] == "proxy request":
        return ("domain", phase, v["target"]), f"domain {v['target']}", None
    if v["syscall"] not in NETWORK_SYSCALLS:
        return ("event", index), "", None  # files, programs, evasions: one entry each
    address = _sockaddr(v["target"])
    error = f" ({v['error']})" if v.get("error") else ""
    if address is None:
        return ("network", phase, v["syscall"], v["target"]), f"{v['syscall']} {v['target']}", None
    family, host, port = address
    if family == "AF_UNIX" and host in NSCD_SOCKETS:
        return ("name lookups", phase), NAME_LOOKUPS, f"nscd socket{error}"
    if port == 53 and resolvers is not None and host in resolvers:
        # The system resolver, from the container's resolv.conf: the trace
        # doesn't contain the name looked up, so none is guessed.
        return ("name lookups", phase), NAME_LOOKUPS, f"port 53 at {host}{error}"
    if port == 53:
        # Never merged with the resolver's lookups: DNS sent somewhere else,
        # or (resolvers None) the resolver list couldn't be read.
        label = (f"direct DNS to {host}:53 (bypasses the system resolver)" if resolvers is not None
                 else f"port 53 to {host} (the container's resolver could not be read, so not "
                      "grouped as name lookups)")
        return ("dns", phase, host), label, None
    where = f"{host}:{port}" if port is not None else host
    return ("network", phase, v["syscall"], family, host, port), f"{v['syscall']} {family} {where}", None


def group_violations(violations: list[dict], domains: list[dict],
                     resolvers: list[str] | None) -> list[dict]:
    """The violations as report entries (#141), in order of first appearance.

    Network events are grouped: proxy requests per domain, the system
    resolver's lookup steps as one "name lookups" entry, port 53 anywhere
    else per address, any other network event per (syscall, family, address,
    port). Everything else stays one entry per event. Each entry lists the
    indexes of its events in `violations`, which is never changed: the
    verdict, the counts and check_fixtures.py use the raw list.
    `resolvers` None means the nameservers are unknown.
    """
    groups: dict[tuple, dict] = {}
    for index, v in enumerate(violations):
        key, label, part = _group_key(v, index, resolvers)
        group = groups.get(key)
        if group is None:
            group = groups[key] = {"label": label, "phase": v.get("phase"), "count": 0,
                                   "first": v["timestamp"], "last": v["timestamp"],
                                   "events": [], "breakdown": {}}
        group["count"] += 1
        group["last"] = v["timestamp"]
        group["events"].append(index)
        if part:
            group["breakdown"][part] = group["breakdown"].get(part, 0) + 1
    for (kind, *rest), group in groups.items():
        if kind == "domain":
            # How the server asked for it, from the sink's records.
            requests = [f"{d['method']} :{d['port']}" for d in domains
                        if d["host"] == rest[1] and d.get("phase") == rest[0]]
            group["breakdown"] = {r: requests.count(r) for r in dict.fromkeys(requests)}
    return list(groups.values())


def summary_lines(r: dict) -> list[str]:
    """The terminal summary of a report (#141). "violations: N" is the number
    of raw events, as in the JSON; the entries are the groups. An entry of one
    event prints as it always did."""
    groups = r["violation_groups"]
    lines = [f"Verdict: {verdict_line(r)}  (violations: {len(r['violations'])} in {len(groups)} "
             f"{'entry' if len(groups) == 1 else 'entries'}, attempted: {len(r['attempted'])}, "
             f"probes: {len(r['probes'])})"]
    lines += [f"  incomplete: {reason}" for reason in r["incomplete_reasons"]]
    for group in groups:
        if group["count"] == 1:
            v = r["violations"][group["events"][0]]
            lines.append(f"  VIOLATION {v['syscall']} {v['target']} at {v['timestamp']}")
            continue
        parts = ", ".join(f"{text} ×{n}" for text, n in group["breakdown"].items())
        lines.append(f"  VIOLATION {group['label']} ×{group['count']}" + (f" ({parts})" if parts else "")
                     + f", {group['first']} – {group['last']}, {group['phase']}")
    return lines


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

# Known limitation (#82), stated in every report: Sandglass doesn't hide
# strace, and doesn't try to.
TRACING_NOTE = ("the server could detect it was traced (strace shows in /proc/self/status, "
                "TracerPid); a CLEAN verdict only covers what it did while traced (#82).")

# In every scan report's "Not tested" section (#120): only the package's own
# file is checked against its registry (#21); its dependencies are not.
DEPENDENCY_HASH_NOTE = ("Dependency hashes were recorded but not compared to the registry; "
                        "only the package's own file was verified.")


def not_run(reason: str | None) -> dict:
    """compare()'s result for a scan whose server never ran (#19): the
    download or the install failed. INCOMPLETE, with nothing observed.
    (reason None: the install phase gives the reason, see with_install.)"""
    return {
        "verdict": "INCOMPLETE", "incomplete_reasons": [reason] if reason else [],
        "violations": [], "attempted": [], "probes": [], "domains": [],
        "network_isolation": None, "phase_note": "the server was not run", "programs": [],
        "event_counts": {kind: 0 for kind in EVENT_KINDS},
    }


def setup_line(setup: dict) -> str:
    """The server setup in one line (#144): arguments as given, environment
    names only (values are never recorded), the work dir."""
    env = ", ".join(f"`{name}`" for name in setup["env"]) or "none"
    return (f"arguments `{json.dumps(setup['args'])}`, environment {env} (values not recorded),"
            f" work dir `{setup['workdir']}`")


def build_report(server: str, timestamp: str, policy: Policy, session: dict,
                 result: dict, trace_file: Path | None, path_mapping: dict,
                 baseline: dict, package: dict | None = None,
                 server_setup: dict | None = None) -> dict:
    """Assemble everything into the final report dict.

    `package` (scan mode, #19): what was scanned, downloaded and installed.
    `trace_file` is None if the server never ran.
    `server_setup` (#144): the --server-arg/--env setup, env names only.
    """
    cov = coverage(session)
    return {
        "server": server,
        "timestamp": timestamp,
        "verdict": result["verdict"],
        # The tools that didn't run normally, shown next to the verdict (#143); None if all ran.
        "coverage_summary": coverage_summary(cov),
        "incomplete_reasons": result["incomplete_reasons"],
        "package": package,
        "server_setup": server_setup,  # arguments, env names (no values), work dir, command (#144)
        # Paths as text; the baseline's exec_exact entries (#142) stay mappings.
        "policy": {k: (v if v is None or isinstance(v, (str, bool))
                       else [p if isinstance(p, dict) else str(p) for p in v])
                   for k, v in asdict(policy).items()},
        "baseline": baseline,  # which container baseline was applied, and how
        "path_mapping": path_mapping,
        "trace_file": str(trace_file) if trace_file else None,
        "exercised": session.get("calls", []),
        # How the inputs were built (#145): the mode, and per called tool each
        # argument's {"value", "source"}, e.g. "param-description".
        "input_mode": (server_setup or {}).get("inputs"),
        "inputs": session.get("inputs", {}),
        "tools": session.get("tools", []),
        "coverage": cov,  # ran / returned an error / failed / ... per tool (#23, #143)
        "violations": result["violations"],  # every event, never grouped
        # The same violations as report entries (#141), for the summary and the Markdown.
        "violation_groups": group_violations(result["violations"], result["domains"],
                                             result.get("resolvers")),
        "attempted": result["attempted"],
        "probes": result["probes"],
        "domains": result["domains"],
        "network_isolation": result["network_isolation"],
        "resolvers": result.get("resolvers"),  # the container's nameservers, None if unknown (#141)
        "phase_note": result["phase_note"],
        "server_stopped_note": SERVER_STOPPED_NOTE if result.get("server_stopped") else None,
        "programs": result.get("programs", []),  # every successful exec (#120)
        "tracing_note": TRACING_NOTE,  # a known limitation, in every report (#82)
        # What a scan did not check (#120). Fixture runs have no package.
        "not_tested": [DEPENDENCY_HASH_NOTE] if package else [],
        "event_counts": result["event_counts"],
    }


def write_reports(report: dict, reports_dir: Path) -> tuple[Path, Path]:
    """Write reports/<server>_<timestamp>.json and .md; return both paths."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{report['server']}_{report['timestamp']}"
    json_path = reports_dir / f"{stem}.json"
    md_path = reports_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_markdown(report), encoding="utf-8")
    return json_path, md_path


def _markdown(r: dict) -> str:
    """Human-readable version of the report."""
    out = [
        f"# Sandglass report: {r['server']}",
        "",
        f"**Verdict: {r['verdict']}**" + verdict_line(r).removeprefix(r["verdict"]),
        "",
        f"- Run: `{r['timestamp']}`",
        f"- Policy: `{r['policy']['name']}`",
        *([f"- Server setup: {setup_line(r['server_setup'])}",
           f"- Reproduce: `{r['server_setup']['command']}`"] if r.get("server_setup") else []),
        *([f"- Inputs: `{r['input_mode']}` mode (where each value came from: \"Tools exercised\")"]
          if r.get("input_mode") else []),
        f"- Baseline: `{r['baseline']['name']}` (`{r['baseline']['file']}`,"
        f" multiarch `{r['baseline']['multiarch']}`; reads only)",
        f"- Trace: `{r['trace_file']}`" if r["trace_file"] else "- Trace: none (the server was not run)",
        f"- Violations: {len(r['violations'])} · Attempted: {len(r['attempted'])}"
        f" · Probes: {len(r['probes'])}",
        f"- Note: {r.get('tracing_note', TRACING_NOTE)}",
    ]
    if r.get("server_stopped_note"):
        out.append(f"- Note: {r['server_stopped_note']}.")
    if r["incomplete_reasons"]:
        out += ["", "## Why INCOMPLETE", ""]
        out += [f"- {reason}" for reason in r["incomplete_reasons"]]
    out += _package_section(r)

    out += ["", "## Tools exercised", ""]
    if r["exercised"]:
        out += ["| Tool | Input | Input sources | Status | Result |", "|---|---|---|---|---|"]
        for c in r["exercised"]:
            result = str(c["result"]).replace("|", "\\|").replace("\n", " ")
            # Where each argument's value came from (#145), e.g. "`timezone`: param-description".
            inputs = (r.get("inputs") or {}).get(c["tool"], {})
            sources = ", ".join(f"`{name}`: {entry['source']}" for name, entry in inputs.items()) or "-"
            arguments = json.dumps(c["arguments"]).replace("|", "\\|")
            out.append(f"| `{c['tool']}` | `{arguments}` | {sources} | {c['status']} | {result} |")
    else:
        out.append("None.")

    out += _coverage_section(r)
    if r.get("not_tested"):
        out += ["", "## Not tested", ""] + [f"- {line}" for line in r["not_tested"]]
    out += _network_section(r)
    out += _phase_sections(r)
    out += _programs_section(r)
    out += _attempted_section(r)

    out += ["", "## Probes (stat/access, informational only)", ""]
    if r["probes"]:
        # One line per path, most-probed first: "/project/test_servers: newfstatat x150, readlinkat x7"
        for p in sorted(r["probes"], key=lambda p: -p["count"]):
            calls = ", ".join(f"{name} x{n}" for name, n in p["syscalls"].items())
            out.append(f"- `{p['path']}`: {calls} (total {p['count']}, first at {p['first_timestamp']},"
                       f" {p.get('phase', '?')})")
    else:
        out.append("None.")

    out += ["", "## Path mapping", ""]
    out += [f"- `{container}` = `{host}`" for container, host in r["path_mapping"].items()]
    counts = ", ".join(f"{k}: {v}" for k, v in r["event_counts"].items())
    out += ["", f"Event counts: {counts}", ""]
    return "\n".join(out)


def _package_section(r: dict) -> list[str]:
    """Scan mode (#19): what was scanned, where it came from, how it was started."""
    p = r.get("package")
    if not p:
        return []
    lines = ["", "## Package", "",
             f"- Spec: `{p['spec']}` (from {p['source']})"]
    install = p.get("install")
    if install:
        exit_code = install["exit_code"]
        status = "timed out" if exit_code is None else f"exit {exit_code}"
        lines += [f"- Install: inside the sandbox, offline, traced ({status};"
                  f" {install['violations']} violation(s), see \"Install\" below;"
                  f" baseline `{install['baseline']}`)",
                  f"  - install trace: `{install['trace_file']}`",
                  f"  - install log: `{install['log_file']}`"]
    else:
        lines.append("- Install: not reached")
    if p["entry"]:
        lines.append(f"- Entry point: `{p['entry']['name']}` = `{p['entry']['path']}`")
    else:
        lines.append("- Entry point: none (not reached)")
    h = p.get("hash")
    if h:
        verdict = "matches" if h["match"] else "**DOES NOT MATCH**"
        lines.append(f"- Hash (#21): `{h['file']}` {h['algorithm']} `{h['ours']}` {verdict}"
                     f" the value published by {h['source']}"
                     + ("" if h["match"] else f" (`{h['published']}`)"))
    else:
        lines.append("- Hash: not checked (the download didn't get that far)")
    lines += ["- Downloaded on the host:" if p["files"] else "- Downloaded on the host: nothing"]
    lines += [f"  - `{f['name']}` ({f['size']} bytes, sha256 `{f.get('sha256', '?')}`)" for f in p["files"]]
    return lines


def _coverage_section(r: dict) -> list[str]:
    """Every listed tool with its coverage status, the reason and totals (#23, #140)."""
    cov = r.get("coverage")
    if cov is None:
        return []
    t = cov["totals"]
    lines = ["", "## Coverage", "",
             f"Ran {t['ran']} · Returned an error {t.get('returned_error', 0)}"
             f" · Failed {t['failed']} · Timed out {t.get('timed_out', 0)}"
             f" · Not called {t.get('not_called', 0)} · Skipped {t['skipped']} · Total {t['total']}"
             " (each tool is called once, with one input; see the README)", ""]
    if cov["note"]:
        return lines + [f"No tools: {cov['note']}."]
    lines += ["| Tool | Status | Reason |", "|---|---|---|"]
    for row in cov["tools"]:
        reason = (row["reason"] or "").replace("|", "\\|")
        lines.append(f"| `{row['tool']}` | {row['status']} | {reason} |")
    return lines


def _network_section(r: dict) -> list[str]:
    """Contacted domains (via the local sink) and the isolation check."""
    lines = ["", "## Network", ""]
    iso = r.get("network_isolation")
    if iso is None:
        lines.append("- Isolation check: **result not in the trace**")
    elif not iso["isolated"]:
        lines.append(f"- Isolation check: connect to `{iso['target']}`: **NOT isolated ({iso['outcome']})**"
                     " (the sandbox may reach the internet)")
    else:
        lines.append(f"- Isolation check: connect to `{iso['target']}`: isolated ({iso['outcome']}):"
                     " no route to the internet")
    resolvers = r.get("resolvers")
    lines.append("- Nameservers in the container's resolv.conf: "
                 + (", ".join(f"`{a}`" for a in resolvers) or "none" if resolvers is not None
                    else "**unknown** (port 53 to any address is listed separately)"))
    lines += ["", "Domains the server asked the local sink for (nothing was sent anywhere):", ""]
    if not r.get("domains"):
        return lines + ["None."]
    # One row per identical request (#141); the JSON lists every one.
    rows: dict[tuple, int] = {}
    for d in r["domains"]:
        key = (d["host"], d["port"], d["method"], d["allowed"], d.get("phase", "?"))
        rows[key] = rows.get(key, 0) + 1
    lines += ["| Domain | Port | Method | Allowed | Phase | Requests |", "|---|---|---|---|---|---|"]
    for (host, port, method, allowed, phase), count in rows.items():
        lines.append(f"| `{host}` | {port} | {method} | {'yes' if allowed else '**no**'} | {phase} | {count} |")
    return lines


def _phase_sections(r: dict) -> list[str]:
    """Violations grouped by phase: install / startup / tool calls."""
    titles = {"install": "Install", "startup": "Startup", "tool-call": "Tool calls",
              "unknown": "Phase unknown"}
    lines = ["", "## Violations by phase"]
    if r.get("phase_note"):
        lines += ["", f"Phases are unknown: {r['phase_note']}."]
    groups = r.get("violation_groups")
    if groups is None:  # a report from before #141: one entry per event
        groups = [{"count": 1, "events": [i], "phase": v.get("phase")} for i, v in enumerate(r["violations"])]
    for phase in PHASES:
        records = [v for v in r["violations"] if v.get("phase") == phase]
        if phase == "unknown" and not records:
            continue  # only shown when the boundary was missing
        section = _event_section(titles[phase], records, level="###",
                                 groups=[g for g in groups if g["phase"] == phase],
                                 violations=r["violations"])
        if phase == "install" and not records and not r.get("package"):
            section[-1:] = ["Nothing is installed in a fixture run; `sandglass scan` traces "
                            "the install of a package (see #16)."]
        lines += section
    return lines


def _command_line(argv: list[str] | None) -> str:
    """argv as one readable line: sh -c "node postinstall.js"."""
    if argv is None:
        return "(arguments not readable)"
    # json.dumps quotes an argument (and escapes its quotes) when it needs it.
    return " ".join(a if a and not any(c.isspace() or c in "\"'\\" for c in a) else json.dumps(a)
                    for a in argv)


def _programs_section(r: dict) -> list[str]:
    """Every successful exec, by phase (#120). Allowed or not: violations are
    listed in their own section; this shows what actually ran."""
    titles = {"install": "Install", "startup": "Startup", "tool-call": "Tool calls",
              "unknown": "Phase unknown"}
    lines = ["", "## Programs run", "",
             "Every program that was started successfully, allowed or not "
             "(violations are listed above)."]
    programs = r.get("programs", [])
    for phase in PHASES:
        rows = [p for p in programs if p["phase"] == phase]
        if phase == "unknown" and not rows:
            continue
        lines += ["", f"### {titles[phase]}", ""]
        if phase == "install" and not rows and not r.get("package"):
            lines.append("Nothing is installed in a fixture run.")
        elif not rows:
            lines.append("None.")
        for p in rows:
            note = f" ({p['note']})" if p.get("note") else ""
            lines.append(f"- pid {p['pid']} at {p['timestamp']}: `{p['path']}`{note}:"
                         f" `{_command_line(p['argv'])}`")
    return lines


# A failed exec with one of these errors may be part of a PATH search (#120).
PATH_SEARCH_ERRORS = {"ENOENT", "EACCES"}


def _path_searches(attempted: list[dict], programs: list[dict]) -> dict[int, dict]:
    """Find PATH searches in the Attempted list (#120): {id(record): search}.

    A shell or npm looking for "node" tries every folder in PATH in turn, so
    one `node` command leaves a run of failed execs (ENOENT, or EACCES)
    from the same pid, with the same argv, whose paths share the basename
    "node". That run is one PATH search, not N programs. Records of other
    pids in between don't end a run; any other record of the same pid does.
    A run counts as a search if it has 2+ places, or if the same pid then
    successfully runs that basename ("found at"). Never "ran a program".
    """
    runs, current = [], {}  # current: pid -> the run being built for it
    for record in attempted:
        pid = record["pid"]
        if record["syscall"] not in ("execve", "execveat") or record["error"] not in PATH_SEARCH_ERRORS:
            current.pop(pid, None)  # anything else from this pid ends its run
            continue
        argv, name = exec_argv(record["evidence"]), posixpath.basename(record["target"])
        run = current.get(pid)
        if run is None or (run["argv"], run["basename"], run["phase"]) != (argv, name, record["phase"]):
            run = {"pid": pid, "argv": argv, "basename": name, "phase": record["phase"], "records": []}
            current[pid] = run
            runs.append(run)
        run["records"].append(record)

    searches = {}
    for run in runs:
        last = run["records"][-1]["timestamp"]
        found = next((p["path"] for p in programs if p["pid"] == run["pid"] and p["phase"] == run["phase"]
                      and posixpath.basename(p["path"]) == run["basename"] and p["timestamp"] >= last), None)
        if len(run["records"]) >= 2 or found:
            run["found_at"] = found
            for record in run["records"]:
                searches[id(record)] = run
    return searches


def group_attempted(attempted: list[dict], programs: list[dict]) -> list[dict]:
    """The Attempted list grouped for the Markdown report (#120). The JSON
    keeps every event; this only shortens what a person has to read.

    Each group: "label", "target", "error", "phase", "count", "first" (the
    first record, for its time, pid and evidence), and for a PATH search
    "found_at". Groups are in the order of their first record.
      - a PATH search (see _path_searches) is one group, labelled
        "looked for <basename> in PATH (N places)"
      - everything else: one group per (category, path, errno, phase)
    """
    searches = _path_searches(attempted, programs)
    groups, by_key = [], {}
    for record in attempted:
        search = searches.get(id(record))
        if search is not None:
            key = ("PATH search", id(search))
            label = f"looked for {search['basename']} in PATH ({len(search['records'])} places)"
        else:
            key = (record["reason"], record["target"], record["error"], record["phase"])
            label = record["reason"]
        group = by_key.get(key)
        if group is None:
            group = {"label": label, "target": record["target"], "error": record["error"],
                     "phase": record["phase"], "count": 0, "first": record,
                     "found_at": search.get("found_at") if search else None,
                     "path_search": search is not None}
            by_key[key] = group
            groups.append(group)
        group["count"] += 1
    return groups


def _attempted_section(r: dict) -> list[str]:
    """Attempted (failed, not violations), grouped like the Probes section (#120)."""
    lines = ["", "## Attempted (failed, not violations)", ""]
    groups = group_attempted(r["attempted"], r.get("programs", []))
    if not groups:
        return lines + ["None."]
    lines += [f"{len(r['attempted'])} failed attempt(s) in {len(groups)} group(s); "
              "the JSON report lists each one.", ""]
    for i, g in enumerate(groups, 1):
        first = g["first"]
        if g["path_search"]:
            found = f", found at `{g['found_at']}`" if g["found_at"] else ", not found"
            title = f"{i}. **{g['label']}**{found}: `{_command_line(exec_argv(first['evidence']))}`"
        else:
            title = f"{i}. **{g['label']}**: `{g['target']}`"
        lines += [
            title,
            f"   - syscall `{first['syscall']}`, failed ({g['error']}), x{g['count']},"
            f" first at {first['timestamp']}, pid {first['pid']} ({g['phase']})",
            "   - evidence (first occurrence):",
            "",
            "     ```",
            f"     {first['evidence']}",
            "     ```",
        ]
    return lines


def _event_section(title: str, records: list[dict], level: str = "##",
                   groups: list[dict] | None = None, violations: list[dict] | None = None) -> list[str]:
    """Numbered events with their evidence. With `groups` (#141), one item per
    entry: an entry of one event exactly as before, an entry of several as
    one item with its count, breakdown and first evidence line."""
    lines = ["", f"{level} {title}", ""]
    if not records:
        return lines + ["None."]
    if groups is None:
        groups = [{"count": 1, "events": [i]} for i in range(len(records))]
        violations = records
    for i, group in enumerate(groups, 1):
        v = violations[group["events"][0]]
        if group["count"] > 1:
            parts = ", ".join(f"{t} ×{n}" for t, n in group["breakdown"].items())
            lines += [
                f"{i}. **{group['label']}** ×{group['count']}" + (f" ({parts})" if parts else ""),
                f"   - {v['reason']}; from {group['first']} to {group['last']} ({group['phase']})",
                f"   - all {group['count']} events are in the JSON report's `violations`"
                " (this entry's `events` in `violation_groups` gives their indexes)",
                "   - first evidence:",
                "",
                "     ```",
                f"     {v['evidence']}",
                "     ```",
            ]
            continue
        status = "succeeded" if v["succeeded"] else f"failed ({v['error']})"
        lines += [
            f"{i}. **{v['reason']}**: `{v['target']}`",
            f"   - syscall `{v['syscall']}`, {status}, pid {v['pid']}, at {v['timestamp']}"
            f" ({v.get('phase', '?')})",
            "   - evidence:",
            "",
            "     ```",
            f"     {v['evidence']}",
            "     ```",
        ]
    return lines
