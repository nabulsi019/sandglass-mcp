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
  Network (when network.allow is false):
    any attempt, even a failed one -> VIOLATION
    except a SUCCESSFUL connect to the local network sink (sandglass/netsink.py):
      the sink then records the domain the server asked for, and
    a domain not in network.allow_domains -> VIOLATION naming the domain
  The sink itself (the first process to stat its "ready" marker, which the
  launcher waits for before any server code runs) is Sandglass, not the
  server: its own exec and sockets are not violations. Its startup connect to
  a public IP is the isolation check; if that ever succeeds -> INCOMPLETE.
  Process exec:
    the first exec in the trace is the server itself -> allowed
    (Node servers: the launcher then execs node in that same process; that
    one exec is part of the launch too, but only when runtime is "node")
    anything else not in exec_allow: same rules as files

Phases (#18): every reported event gets a phase:
  install    nothing is installed at run time yet (see #16), so always empty
  startup    before the client sent its first tool call
  tool-call  from the first tool call on
  The boundary is the client's UTC clock just before the first call_tool,
  compared with strace's -tt times (same clock, UTC inside the container).

Verdicts:
  INCOMPLETE  the run can't be trusted: the server didn't start, the session
              errored, nothing was exercised, the trace is missing/truncated,
              the network sink didn't start, or the sandbox could reach the internet.
              Never treated as clean, even when no violations were seen.
  VIOLATIONS  at least one violation.
  CLEAN       a complete run with zero violations.
"""

import json
from dataclasses import asdict
from pathlib import Path

from sandglass import netsink, sandbox
from sandglass.policy import Policy
from sandglass.trace_parser import Event

# Errors that mean "this exists but you're not allowed": a real access attempt.
BLOCKED_ERRORS = {"EACCES", "EPERM"}


def _is_under(path: str, roots: list) -> bool:
    """True if `path` is one of `roots` or inside one of them (textual check)."""
    for root in roots:
        root = str(root)
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _sink_pid(events: list[Event]) -> int | None:
    """The network sink's pid: the FIRST process to stat the sink's ready marker."""
    for event in events:
        if event.kind == "probe" and event.target == netsink.SINK_READY:
            return event.pid
    return None


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


PHASES = ("install", "startup", "tool-call")


def _seconds(timestamp: str) -> float:
    """'HH:MM:SS.micro' -> seconds since midnight."""
    hours, minutes, seconds = timestamp.split(":")
    return int(hours) * 3600 + int(minutes) * 60 + float(seconds)


def _phase_of(events: list[Event], session: dict):
    """Return a function timestamp -> "startup" / "tool-call".

    strace's -tt has no date, so times are measured from the first trace line
    and wrapped at 24h: a run that crosses midnight still sorts correctly.
    """
    boundary = session.get("tool_calls_started")
    if not events or not boundary:
        return lambda timestamp: "startup"  # no tool was called
    start = _seconds(events[0].timestamp)
    since_start = lambda timestamp: (_seconds(timestamp) - start) % 86400
    cutoff = since_start(boundary)
    return lambda timestamp: "tool-call" if since_start(timestamp) >= cutoff else "startup"


def _bucket_for_failure_or_success(event: Event) -> str:
    """Shared rule for files and execs: 'violation' or 'attempted'."""
    if event.succeeded or event.error in BLOCKED_ERRORS:
        return "violation"
    return "attempted"


def compare(events: list[Event], policy: Policy, session: dict, runtime: str = "python") -> dict:
    """Apply the rules above. Returns a plain dict (ready for JSON).

    `runtime` is "node" for a .js server: the launcher's exec of node is then
    part of the launch, not a violation.
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
    sink_pid = _sink_pid(events)
    phase_of = _phase_of(events, session)
    domains: list[dict] = []       # every request the sink recorded
    isolation: dict | None = None  # the sink's connect-to-a-public-IP check

    for event in events:
        if sink_pid is not None and event.pid == sink_pid and event.kind in ("process", "network", "probe"):
            # Sandglass's own sink: its exec and sockets are ours, not the server's.
            if event.kind == "network" and _is_address(event.target, *netsink.ISOLATION_CHECK):
                isolation = {"target": "%s:%d" % netsink.ISOLATION_CHECK,
                             "succeeded": event.succeeded, "error": event.error,
                             "evidence": event.raw}
            request = _sink_request(event.target) if event.kind == "probe" else None
            if request is None:
                continue  # its own exec/bind/listen/accept, or the ready marker
            method, host, port = request
            allowed = _domain_allowed(host, policy)
            domains.append({"method": method, "host": host, "port": port,
                            "allowed": allowed, "timestamp": event.timestamp,
                            "phase": phase_of(event.timestamp)})
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
                "phase": phase_of(event.timestamp),  # of the first occurrence
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

        else:
            continue  # exit events are only used for the completeness check

        record = {
            "reason": reason,
            "syscall": event.syscall,
            "target": event.target,
            "mode": event.mode,
            "timestamp": event.timestamp,
            "phase": phase_of(event.timestamp),
            "pid": event.pid,
            "succeeded": event.succeeded,
            "error": event.error,
            "evidence": event.raw,
        }
        (violations if bucket == "violation" else attempted).append(record)

    incomplete = _incomplete_reasons(events, server_launch, session)
    if events and sink_pid is None:
        incomplete.append("the network sink did not start, so contacted domains can't be recorded")
    elif events and isolation is None:
        incomplete.append("the network isolation check is missing from the trace")
    elif isolation and isolation["succeeded"]:
        incomplete.append(f"the sandbox reached the internet: connect to {isolation['target']} succeeded")
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
        "event_counts": {
            kind: sum(1 for e in events if e.kind == kind)
            for kind in ("file", "probe", "process", "network", "exit")
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


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def build_report(server: str, timestamp: str, policy: Policy, session: dict,
                 result: dict, trace_file: Path, path_mapping: dict,
                 baseline: dict) -> dict:
    """Assemble everything into the final report dict."""
    return {
        "server": server,
        "timestamp": timestamp,
        "verdict": result["verdict"],
        "incomplete_reasons": result["incomplete_reasons"],
        "policy": {k: (v if v is None or isinstance(v, (str, bool)) else [str(p) for p in v])
                   for k, v in asdict(policy).items()},
        "baseline": baseline,  # which container baseline was applied, and how
        "path_mapping": path_mapping,
        "trace_file": str(trace_file),
        "exercised": session.get("calls", []),
        "tools": session.get("tools", []),
        "violations": result["violations"],
        "attempted": result["attempted"],
        "probes": result["probes"],
        "domains": result["domains"],
        "network_isolation": result["network_isolation"],
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
        f"- Trace: `{r['trace_file']}`",
        f"- Violations: {len(r['violations'])} · Attempted: {len(r['attempted'])}"
        f" · Probes: {len(r['probes'])}",
    ]
    if r["incomplete_reasons"]:
        out += ["", "## Why INCOMPLETE", ""]
        out += [f"- {reason}" for reason in r["incomplete_reasons"]]

    out += ["", "## Tools exercised", ""]
    if r["exercised"]:
        out += ["| Tool | Input | Status | Result |", "|---|---|---|---|"]
        for c in r["exercised"]:
            result = str(c["result"]).replace("|", "\\|").replace("\n", " ")
            out.append(f"| `{c['tool']}` | `{json.dumps(c['arguments'])}` | {c['status']} | {result} |")
    else:
        out.append("None.")

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


def _network_section(r: dict) -> list[str]:
    """Contacted domains (via the local sink) and the isolation check."""
    lines = ["", "## Network", ""]
    iso = r.get("network_isolation")
    if iso is None:
        lines.append("- Isolation check: **not in the trace**")
    elif iso["succeeded"]:
        lines.append(f"- Isolation check: connect to `{iso['target']}` **SUCCEEDED** (the sandbox can reach the internet)")
    else:
        lines.append(f"- Isolation check: connect to `{iso['target']}` failed ({iso['error']}): no route to the internet")
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
    titles = {"install": "Install", "startup": "Startup", "tool-call": "Tool calls"}
    lines = ["", "## Violations by phase"]
    for phase in PHASES:
        records = [v for v in r["violations"] if v.get("phase") == phase]
        section = _event_section(titles[phase], records, level="###")
        if phase == "install" and not records:
            section[-1:] = ["Not captured in this version: nothing is installed at run time (see #16)."]
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
