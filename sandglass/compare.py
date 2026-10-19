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
  Process exec:
    the first exec in the trace is the server itself -> allowed
    anything else not in exec_allow: same rules as files

Verdicts:
  INCOMPLETE  the run can't be trusted: the server didn't start, the session
              errored, nothing was exercised, or the trace is missing/truncated.
              Never treated as clean, even when no violations were seen.
  VIOLATIONS  at least one violation.
  CLEAN       a complete run with zero violations.
"""

import json
from dataclasses import asdict
from pathlib import Path

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


def _bucket_for_failure_or_success(event: Event) -> str:
    """Shared rule for files and execs: 'violation' or 'attempted'."""
    if event.succeeded or event.error in BLOCKED_ERRORS:
        return "violation"
    return "attempted"


def compare(events: list[Event], policy: Policy, session: dict) -> dict:
    """Apply the rules above. Returns a plain dict (ready for JSON)."""
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

    for event in events:
        if event.kind == "file":
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
            })
            entry["count"] += 1
            entry["syscalls"][event.syscall] = entry["syscalls"].get(event.syscall, 0) + 1
            continue

        elif event.kind == "process":
            if server_launch is None and event.succeeded:
                server_launch = event  # strace launching the server itself
                continue
            if _is_under(event.target, policy.exec_allow):
                continue
            reason = "process exec not in exec_allow"
            bucket = _bucket_for_failure_or_success(event)

        elif event.kind == "network":
            if policy.network_allow:
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
            "pid": event.pid,
            "succeeded": event.succeeded,
            "error": event.error,
            "evidence": event.raw,
        }
        (violations if bucket == "violation" else attempted).append(record)

    incomplete = _incomplete_reasons(events, server_launch, session)
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

    out += _event_section("Violations", r["violations"])
    out += _event_section("Attempted (failed, not violations)", r["attempted"])

    out += ["", "## Probes (stat/access, informational only)", ""]
    if r["probes"]:
        # One line per path, most-probed first: "/project/test_servers: newfstatat x150, readlinkat x7"
        for p in sorted(r["probes"], key=lambda p: -p["count"]):
            calls = ", ".join(f"{name} x{n}" for name, n in p["syscalls"].items())
            out.append(f"- `{p['path']}`: {calls} (total {p['count']}, first at {p['first_timestamp']})")
    else:
        out.append("None.")

    out += ["", "## Path mapping", ""]
    out += [f"- `{container}` = `{host}`" for container, host in r["path_mapping"].items()]
    counts = ", ".join(f"{k}: {v}" for k, v in r["event_counts"].items())
    out += ["", f"Event counts: {counts}", ""]
    return "\n".join(out)


def _event_section(title: str, records: list[dict]) -> list[str]:
    lines = ["", f"## {title}", ""]
    if not records:
        return lines + ["None."]
    for i, v in enumerate(records, 1):
        status = "succeeded" if v["succeeded"] else f"failed ({v['error']})"
        lines += [
            f"{i}. **{v['reason']}**: `{v['target']}`",
            f"   - syscall `{v['syscall']}`, {status}, pid {v['pid']}, at {v['timestamp']}",
            "   - evidence:",
            "",
            "     ```",
            f"     {v['evidence']}",
            "     ```",
        ]
    return lines
