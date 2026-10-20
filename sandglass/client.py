"""Minimal Sandglass client.

Launches an MCP server as a subprocess over stdio, lists its tools, calls
each tool once with a simple safe input, and prints what came back.

With --sandbox, the server runs inside Docker under strace instead, and
afterwards the trace is compared with the policy and a report is written
to reports/<server>_<timestamp>.json and .md.

Usage:
    uv run python -m sandglass.client <server.py> [--policy <policy.yaml>] [--sandbox]

With --sandbox the exit code is the verdict: 0 CLEAN, 1 VIOLATIONS, 2 INCOMPLETE.
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent, Tool

from sandglass import PROJECT_ROOT, sandbox
from sandglass.compare import build_report, compare, write_reports
from sandglass.policy import BASELINE_FILE, Policy, load_policy
from sandglass.trace_parser import parse_trace

# The one input value we use for every string argument. For the notes
# servers this means read_note("hello") -> allowed_notes/hello.txt.
SAFE_STRING = "hello"

REPORTS_DIR = PROJECT_ROOT / "reports"

# Upper bound for the whole MCP session, so a hung server can't hang us.
SESSION_TIMEOUT_SECONDS = 120

# --sandbox exit codes, so scripts and CI can check the verdict.
EXIT_CODES = {"CLEAN": 0, "VIOLATIONS": 1, "INCOMPLETE": 2}


def build_safe_arguments(tool: Tool) -> dict:
    """Build a harmless argument dict from the tool's JSON input schema."""
    defaults = {"string": SAFE_STRING, "integer": 1, "number": 1.0, "boolean": False}
    properties = tool.input_schema.get("properties", {})
    return {
        name: defaults.get(spec.get("type"), SAFE_STRING)
        for name, spec in properties.items()
    }


def result_text(result) -> tuple[str, str]:
    """Return (status, text) for a tool result."""
    if not isinstance(result, CallToolResult):
        return "UNEXPECTED", f"(unexpected result type: {type(result).__name__})"
    texts = [c.text for c in result.content if isinstance(c, TextContent)]
    return ("ERROR" if result.is_error else "OK"), "\n".join(texts).strip()


def print_policy(policy: Policy) -> None:
    print(f"Policy: {policy.name} (loaded, NOT enforced yet)")
    print(f"  {policy.description}")
    print(f"  read_allow:    {[str(p) for p in policy.read_allow]}")
    print(f"  write_allow:   {[str(p) for p in policy.write_allow]}")
    print(f"  network_allow: {policy.network_allow}")
    print("  runtime_allow (reads only, excluded from violations):")
    for p in policy.runtime_allow:
        print(f"    - {p}")
    for p in policy.list_exact:
        print(f"    = {p}  (exact, directory listing only)")
    if policy.baseline_name:
        print(f"  baseline: {policy.baseline_name} ({len(policy.baseline_read_allow)} read paths)")
    print()


async def run(params: StdioServerParameters, server_name: str, errlog=sys.stderr) -> dict:
    """Run one MCP session and return a record of what was exercised.

    `errlog` receives the subprocess's stderr. In the sandbox that stream is
    the strace trace, so run_sandboxed passes the trace file here.
    """
    session_record = {"tools": [], "calls": []}

    # stdio_client spawns the subprocess and gives us its stdin/stdout streams.
    async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()  # MCP handshake

            tools = (await session.list_tools()).tools
            print(f"Server: {server_name}")
            print(f"Tools ({len(tools)}):")
            for tool in tools:
                print(f"  - {tool.name}: {tool.description}")
                print(f"    input schema: {json.dumps(tool.input_schema)}")
                session_record["tools"].append({"name": tool.name, "description": tool.description})
            print()

            for tool in tools:
                args = build_safe_arguments(tool)
                print(f"Calling {tool.name}({args})")
                result = await session.call_tool(tool.name, args)
                status, text = result_text(result)
                print(f"  -> [{status}] {text}")
                session_record["calls"].append(
                    {"tool": tool.name, "arguments": args, "status": status, "result": text}
                )
    # Leaving the `async with` closes the server's stdin and waits for it to
    # exit. In the sandbox, that's what lets strace finish writing the trace.
    return session_record


def run_host(server_script: Path) -> None:
    """Original behaviour: run the server directly, no tracing, no report."""
    # Start the server with the same Python interpreter running this client,
    # so it sees the same installed packages (the project's .venv).
    params = StdioServerParameters(command=sys.executable, args=[str(server_script)])
    asyncio.run(run(params, server_script.name))


def run_sandboxed(server_script: Path, policy_path: Path) -> dict:
    """Run the server in Docker under strace, compare, write and return the report."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    server = server_script.stem
    trace_dir = REPORTS_DIR / "trace" / f"{server}_{timestamp}"
    trace_dir.mkdir(parents=True)
    # Written on the HOST from the container's stderr (strace's output). The
    # container never sees this file: reports/ is hidden inside it.
    trace_file = trace_dir / sandbox.TRACE_FILENAME

    # Container paths, because that's what the trace will contain. The
    # multiarch triplet comes from inside the image (arm64 Mac vs x86_64 CI).
    multiarch = sandbox.detect_multiarch()
    policy = load_policy(policy_path, server_script=server_script,
                         in_sandbox=True, multiarch=multiarch)
    print_policy(policy)

    command, args = sandbox.docker_command(server_script)
    params = StdioServerParameters(command=command, args=args)

    # Any failure (image missing, server crash, timeout) is recorded, not
    # raised: the report must still be written, with verdict INCOMPLETE.
    # The container's stderr (the trace) goes straight into trace_file.
    with open(trace_file, "w", encoding="utf-8") as trace_out:
        try:
            session = asyncio.run(asyncio.wait_for(run(params, server_script.name, trace_out),
                                                   SESSION_TIMEOUT_SECONDS))
        except BaseException as exc:  # includes ExceptionGroup from anyio task groups
            if isinstance(exc, KeyboardInterrupt):
                raise
            session = {"tools": [], "calls": [], "error": f"{type(exc).__name__}: {exc}"}
            print(f"Session failed: {session['error']}")

    trace_text = trace_file.read_text(encoding="utf-8", errors="replace") if trace_file.exists() else ""
    events = parse_trace(trace_text, cwd=str(sandbox.CONTAINER_PROJECT))
    result = compare(events, policy, session)

    path_mapping = {
        str(sandbox.CONTAINER_PROJECT): f"{PROJECT_ROOT} (read-only)",
        str(sandbox.CONTAINER_REPORTS): "hidden (empty read-only tmpfs)",
        "(container stderr)": f"strace output, saved on the host as {trace_file}",
        str(sandbox.CONTAINER_VENV): "dependencies baked into the image",
        str(sandbox.CONTAINER_PYTHON_BASE): "Python from python:3.12-slim",
    }
    baseline = {
        "name": policy.baseline_name,
        "file": str(BASELINE_FILE.relative_to(PROJECT_ROOT)),
        "multiarch": multiarch,
    }
    report = build_report(server, timestamp, policy, session, result, trace_file,
                          path_mapping, baseline)
    json_path, md_path = write_reports(report, REPORTS_DIR)

    print()
    print(f"Verdict: {result['verdict']}  "
          f"(violations: {len(result['violations'])}, attempted: {len(result['attempted'])}, "
          f"probes: {len(result['probes'])})")
    for reason in result["incomplete_reasons"]:
        print(f"  incomplete: {reason}")
    for v in result["violations"]:
        print(f"  VIOLATION {v['syscall']} {v['target']} at {v['timestamp']}")
    print(f"Report: {json_path.relative_to(PROJECT_ROOT)}")
    print(f"        {md_path.relative_to(PROJECT_ROOT)}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Exercise an MCP server's tools over stdio.")
    parser.add_argument("server", type=Path, help="path to the server .py file")
    parser.add_argument("--policy", type=Path, help="policy YAML to load (required with --sandbox)")
    parser.add_argument("--sandbox", action="store_true",
                        help="run in Docker under strace and write a report")
    args = parser.parse_args()

    # The server path is a normal CLI argument, so it's relative to the CWD.
    # (Paths INSIDE the policy file are relative to the project root instead.)
    server_script = args.server.resolve()
    if not server_script.is_file():
        parser.error(f"server script not found: {server_script}")

    if args.sandbox:
        if not args.policy:
            parser.error("--sandbox needs --policy (the report compares against it)")
        if not server_script.is_relative_to(PROJECT_ROOT):
            parser.error("--sandbox only mounts the project, so the server must be inside it")
        try:
            report = run_sandboxed(server_script, args.policy)
        except sandbox.SandboxError as exc:
            # No sandbox -> nothing observed -> never "clean".
            print(f"Sandbox error: {exc}", file=sys.stderr)
            sys.exit(EXIT_CODES["INCOMPLETE"])
        sys.exit(EXIT_CODES[report["verdict"]])

    if args.policy:
        print_policy(load_policy(args.policy, server_script=server_script))
    run_host(server_script)


if __name__ == "__main__":
    main()
