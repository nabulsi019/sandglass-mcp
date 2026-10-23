"""Compare recorded events with a policy and write the JSON + Markdown report.

Rules (one place, so they're easy to explain):

  What counts as allowed (note the asymmetry):
    read  -> read_allow, runtime_allow, baseline
    list  -> the same as read, plus exact "=" entries (that directory only)
    write -> write_allow ONLY. runtime_allow and the baseline never allow writes.

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
import re
from dataclasses import asdict
from pathlib import Path

from sandglass import launcher, netsink, sandbox, stdin_relay
from sandglass.policy import InstallBaseline, Policy
from sandglass.trace_parser import MAX_TRACE_BYTES, UNREADABLE, Event

# Errors that mean "this exists but you're not allowed": a real access attempt.
BLOCKED_ERRORS = {"EACCES", "EPERM"}

IO_URING_INCOMPLETE = ("io_uring was available, file access may be missing from the trace; "
                       "rerun on Docker 25+ or with a seccomp profile that blocks io_uring")


def _is_under(path: str, roots: list) -> bool:
    """True if `path` is one of `roots` or inside one of them (textual check)."""
    for root in roots:
        root = str(root)
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _is_address(target: str, host: str, port: int) -> bool:
    """Does a network event's target (strace's sockaddr text) name host:port?"""
    return f"sin_port=htons({port})" in target and f'inet_addr("{host}")' in target


def _sink_request(target: str) -> tuple[str, str, int] | None:
    """(method, host, port) from a sink marker path like /sandglass-netsink/GET/example.com/80."""
    parts = target[len(netsink.SINK_MARKER_DIR) + 1:].split("/")
    if not target.startswith(netsink.SINK_MARKER_DIR + "/") or len(parts) != 3 or not parts[2].isdigit():
        return None
    return parts[0], parts[1], int(parts[2])


def _domain_allowed(host: str, policy: Policy) -> bool:
    """network.allow -> everything; else exact match or a "*.example.com" suffix rule."""
    if policy.network_allow:
        return True
    for domain in policy.allow_domains:
        if host == domain or (domain.startswith("*.") and host.endswith(domain[1:])):
            return True
    return False


PHASES = ("install", "startup", "tool-call", "unknown")


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
                 stdin_relay.SERVER_EXITED_MARKER}
# The relay ends normally with one of these: the client closed stdin, or the
# server exited while the client was still connected (#24).
RELAY_NORMAL_ENDS = {stdin_relay.EOF_MARKER, stdin_relay.SERVER_EXITED_MARKER}


def _is_relay_own(event: Event, relay_exec: Event | None) -> bool:
    """The relay's known events: its launch and its marker stats."""
    return event is relay_exec or (event.kind == "probe" and event.target in RELAY_MARKERS)


def _is_sink_own(event: Event, sink_exec: Event | None) -> bool:
    """The sink's known events, apart from its request records (handled in compare()):
    its launch, its ready marker, its proxy socket, and the isolation check
    (its connect, and the marker reporting the outcome, read by _isolation)."""
    if event is sink_exec:
        return True
    if event.kind == "probe":
        return (event.target == netsink.SINK_READY
                or event.target.startswith(netsink.ISOLATION_MARKER_DIR + "/"))
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
    io_uring_used: list[Event] = []  # io_uring calls that succeeded (#75)
    unreadable: list[Event] = []     # file/stat events whose path strace couldn't read (#98)
    server_errors: list[str] = []    # the server's own error messages, via the launcher (#24)

    for index, event in enumerate(events):
        if event.kind in ("file", "probe") and event.target == UNREADABLE:
            # Fail closed: we can't tell what was touched, so we can't judge
            # it against any allow-list. From any pid; INCOMPLETE below.
            unreadable.append(event)
            continue

        if event.pid == relay_pid and _is_relay_own(event, relay_exec):
            continue  # the relay's launch and markers; anything else it does is judged (#99)

        if event.pid == sink_pid and _is_sink_own(event, sink_exec):
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
            bucket = "violation"
            event = Event("domain", "proxy request", event.pid, event.timestamp, host,
                          "domain", True, None, event.raw)

        elif event.kind == "file":
            if event.mode == "write":
                allowed = _is_under(event.target, write_ok)
            elif event.mode == "list":
                # Exact entries match only the directory itself, never its children.
                allowed = _is_under(event.target, read_ok) or event.target in map(str, policy.list_exact)
            else:
                allowed = _is_under(event.target, read_ok)
            if allowed:
                continue
            reason = f"{event.mode} outside allowed paths"
            bucket = _bucket_for_failure_or_success(event)

        elif event.kind == "probe":
            if _is_under(event.target, read_ok):
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
            reason = "network activity while network.allow is false"
            bucket = "violation"  # attempts count, even failed ones

        elif event.kind == "io_uring":
            if event.succeeded:
                # A working ring means file access we can't see: INCOMPLETE below.
                io_uring_used.append(event)
                continue
            reason = "io_uring blocked (file access through it would be invisible to strace)"
            bucket = "attempted"

        else:
            continue  # exit events are only used for the completeness check

        record = {
            "reason": reason,
            "syscall": event.syscall,
            "target": event.target,
            "mode": event.mode,
            "timestamp": event.timestamp,
            "phase": phase_of(index),
            "pid": event.pid,
            "succeeded": event.succeeded,
            "error": event.error,
            "evidence": event.raw,
        }
        (violations if bucket == "violation" else attempted).append(record)

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
        "phase_note": phase_note,
        "event_counts": {
            kind: sum(1 for e in events if e.kind == kind)
            for kind in ("file", "probe", "process", "network", "io_uring", "exit")
        },
    }


def _incomplete_reasons(events: list[Event], server_launch: Event | None, session: dict) -> list[str]:
    """Everything that means 'we didn't observe a full, trustworthy run'."""
    reasons = []
    if session.get("error"):
        reasons.append(f"MCP session failed: {session['error']}")
    if not session.get("calls"):
        reasons.append("no tools were exercised")
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
      network   sockets of a family that can't leave the machine (AF_NETLINK)
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
    unreadable, io_uring_used = [], []
    launch: Event | None = None

    def record(event: Event, reason: str, bucket: str, target: str | None = None) -> None:
        (violations if bucket == "violation" else attempted).append({
            "reason": reason, "syscall": event.syscall, "target": target or event.target,
            "mode": event.mode, "timestamp": event.timestamp, "phase": "install",
            "pid": event.pid, "succeeded": event.succeeded, "error": event.error,
            "evidence": event.raw,
        })

    for event in events:
        if event.kind in ("file", "probe") and event.target == UNREADABLE:
            unreadable.append(event)
        elif event.kind == "file":
            if event.mode == "write":
                if not _is_under(event.target, write_ok):
                    record(event, "install wrote outside /package and /tmp",
                           _bucket_for_failure_or_success(event))
                if event.link_target and not _is_under(event.link_target, read_ok):
                    record(event, "install linked to a path outside allowed reads",
                           _bucket_for_failure_or_success(event), target=event.link_target)
            elif event.mode == "list" and event.target in map(str, baseline.list_exact):
                continue  # e.g. pip listing /etc: that folder only, nothing inside it
            elif not _is_under(event.target, read_ok):
                record(event, f"install {event.mode} outside allowed paths",
                       _bucket_for_failure_or_success(event))
        elif event.kind == "probe":
            if not _is_under(event.target, read_ok):
                entry = probes.setdefault(event.target, {
                    "path": event.target, "count": 0, "syscalls": {},
                    "first_timestamp": event.timestamp, "phase": "install"})
                entry["count"] += 1
                entry["syscalls"][event.syscall] = entry["syscalls"].get(event.syscall, 0) + 1
        elif event.kind == "process":
            if launch is None and event.succeeded:
                launch = event  # strace starting the installer's shell
            elif not _is_under(event.target, exec_ok):
                record(event, "install ran a program not in the install baseline or exec_allow",
                       _bucket_for_failure_or_success(event))
        elif event.kind == "network":
            family = re.search(r"sa_family=(\w+)", event.target)
            if not policy.network_allow and not (family and family[1] in baseline.network_families_allow):
                record(event, "network activity during the install", "violation")
        elif event.kind == "io_uring":
            if event.succeeded:
                io_uring_used.append(event)
            else:
                record(event, "io_uring blocked (file access through it would be invisible to strace)",
                       "attempted")

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

    return {
        "incomplete_reasons": incomplete,
        "violations": violations,
        "attempted": attempted,
        "probes": sorted(probes.values(), key=lambda p: p["first_timestamp"]),
        "event_counts": {kind: sum(1 for e in events if e.kind == kind)
                         for kind in ("file", "probe", "process", "network", "io_uring", "exit")},
    }


def with_install(result: dict, install: dict) -> dict:
    """The run's compare() result with the install phase added in front of it.

    The install's findings come first (they happened first), and the verdict
    covers both phases: INCOMPLETE if either is, else VIOLATIONS if either
    has one, else CLEAN.
    """
    merged = dict(result)
    for key in ("incomplete_reasons", "violations", "attempted", "probes"):
        merged[key] = install[key] + result[key]
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


def coverage(session: dict) -> dict:
    """One row per tool the server listed: ran / failed / skipped, plus totals.

      ran      the call returned a normal result
      failed   the call returned an MCP error (isError), raised (e.g. timed
               out), or got no answer before the session ended
      skipped  no valid input could be built (#22), or the session ended first

    Coverage is reported, not judged: it never changes the verdict.
    """
    calls = {c["tool"]: c for c in session.get("calls", [])}
    skipped = {s["tool"]: s["reason"] for s in session.get("skipped", [])}
    rows = []
    for tool in session.get("tools", []):
        name = tool["name"]
        if name in calls:
            call = calls[name]
            if call["status"] == "OK":
                rows.append({"tool": name, "status": "ran", "reason": None})
            else:
                text = " ".join(str(call["result"]).split())[:COVERAGE_REASON_CHARS]
                rows.append({"tool": name, "status": "failed", "reason": f"{call['status']}: {text}"})
        elif name in skipped:
            rows.append({"tool": name, "status": "skipped", "reason": skipped[name]})
        else:
            why = f": {session['error']}" if session.get("error") else ""
            rows.append({"tool": name, "status": "skipped",
                         "reason": f"not called, the session ended first{why}"})

    totals = {status: sum(1 for r in rows if r["status"] == status)
              for status in ("ran", "failed", "skipped")}
    totals["total"] = len(rows)
    note = None
    if not rows:
        note = ("the server's tool list was never received" if session.get("error")
                else "the server listed no tools")
    return {"tools": rows, "totals": totals, "note": note}


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def not_run(reason: str | None) -> dict:
    """compare()'s result for a scan whose server never ran (#19): the
    download or the install failed. INCOMPLETE, with nothing observed.
    (reason None: the install phase gives the reason, see with_install.)"""
    return {
        "verdict": "INCOMPLETE", "incomplete_reasons": [reason] if reason else [],
        "violations": [], "attempted": [], "probes": [], "domains": [],
        "network_isolation": None, "phase_note": "the server was not run",
        "event_counts": {kind: 0 for kind in ("file", "probe", "process", "network", "io_uring", "exit")},
    }


def build_report(server: str, timestamp: str, policy: Policy, session: dict,
                 result: dict, trace_file: Path | None, path_mapping: dict,
                 baseline: dict, package: dict | None = None) -> dict:
    """Assemble everything into the final report dict.

    `package` (scan mode, #19): what was scanned, downloaded and installed.
    `trace_file` is None if the server never ran.
    """
    return {
        "server": server,
        "timestamp": timestamp,
        "verdict": result["verdict"],
        "incomplete_reasons": result["incomplete_reasons"],
        "package": package,
        "policy": {k: (v if v is None or isinstance(v, (str, bool)) else [str(p) for p in v])
                   for k, v in asdict(policy).items()},
        "baseline": baseline,  # which container baseline was applied, and how
        "path_mapping": path_mapping,
        "trace_file": str(trace_file) if trace_file else None,
        "exercised": session.get("calls", []),
        "tools": session.get("tools", []),
        "coverage": coverage(session),  # ran / failed / skipped per tool (#23)
        "violations": result["violations"],
        "attempted": result["attempted"],
        "probes": result["probes"],
        "domains": result["domains"],
        "network_isolation": result["network_isolation"],
        "phase_note": result["phase_note"],
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
        f"**Verdict: {r['verdict']}**",
        "",
        f"- Run: `{r['timestamp']}`",
        f"- Policy: `{r['policy']['name']}`",
        f"- Baseline: `{r['baseline']['name']}` (`{r['baseline']['file']}`,"
        f" multiarch `{r['baseline']['multiarch']}`; reads only)",
        f"- Trace: `{r['trace_file']}`" if r["trace_file"] else "- Trace: none (the server was not run)",
        f"- Violations: {len(r['violations'])} · Attempted: {len(r['attempted'])}"
        f" · Probes: {len(r['probes'])}",
    ]
    if r["incomplete_reasons"]:
        out += ["", "## Why INCOMPLETE", ""]
        out += [f"- {reason}" for reason in r["incomplete_reasons"]]
    out += _package_section(r)

    out += ["", "## Tools exercised", ""]
    if r["exercised"]:
        out += ["| Tool | Input | Status | Result |", "|---|---|---|---|"]
        for c in r["exercised"]:
            result = str(c["result"]).replace("|", "\\|").replace("\n", " ")
            out.append(f"| `{c['tool']}` | `{json.dumps(c['arguments'])}` | {c['status']} | {result} |")
    else:
        out.append("None.")

    out += _coverage_section(r)
    out += _network_section(r)
    out += _phase_sections(r)
    out += _event_section("Attempted (failed, not violations)", r["attempted"])

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
    """Every listed tool as ran / failed / skipped, with the reason and totals (#23)."""
    cov = r.get("coverage")
    if cov is None:
        return []
    t = cov["totals"]
    lines = ["", "## Coverage", "",
             f"Ran {t['ran']} · Failed {t['failed']} · Skipped {t['skipped']} · Total {t['total']}"
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
    lines += ["", "Domains the server asked the local sink for (nothing was sent anywhere):", ""]
    if not r.get("domains"):
        return lines + ["None."]
    lines += ["| Domain | Port | Method | Allowed | Phase |", "|---|---|---|---|---|"]
    for d in r["domains"]:
        lines.append(f"| `{d['host']}` | {d['port']} | {d['method']} |"
                     f" {'yes' if d['allowed'] else '**no**'} | {d.get('phase', '?')} |")
    return lines


def _phase_sections(r: dict) -> list[str]:
    """Violations grouped by phase: install / startup / tool calls."""
    titles = {"install": "Install", "startup": "Startup", "tool-call": "Tool calls",
              "unknown": "Phase unknown"}
    lines = ["", "## Violations by phase"]
    if r.get("phase_note"):
        lines += ["", f"Phases are unknown: {r['phase_note']}."]
    for phase in PHASES:
        records = [v for v in r["violations"] if v.get("phase") == phase]
        if phase == "unknown" and not records:
            continue  # only shown when the boundary was missing
        section = _event_section(titles[phase], records, level="###")
        if phase == "install" and not records and not r.get("package"):
            section[-1:] = ["Nothing is installed in a fixture run; `sandglass scan` traces "
                            "the install of a package (see #16)."]
        lines += section
    return lines


def _event_section(title: str, records: list[dict], level: str = "##") -> list[str]:
    lines = ["", f"{level} {title}", ""]
    if not records:
        return lines + ["None."]
    for i, v in enumerate(records, 1):
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
