"""Minimal Sandglass client.

Launches an MCP server as a subprocess over stdio, lists its tools, calls
each tool once with a valid, harmless input built from its JSON schema
(sandglass/inputs.py), and prints what came back.

With --sandbox, the server runs inside Docker under strace instead, and
afterwards the trace is compared with the policy and a report is written
to reports/<server>_<timestamp>.json and .md.

Usage:
    uv run python -m sandglass.client <server.py> [--policy <policy.yaml>] [--sandbox]
    uv run sandglass scan <pypi|npm>:<package>@<exact-version> --policy <policy.yaml>

`scan` (#19) downloads a published package on the host, installs it inside
the sandbox and runs it the same way (see sandglass/scan.py).

With --sandbox (and for scan) the exit code is the verdict: 0 CLEAN,
1 VIOLATIONS, 3 INCOMPLETE. 2 is a usage error (argparse's own code).
"""

import argparse
import asyncio
import json
import re
import shlex
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from mcp.types import REQUEST_TIMEOUT, CallToolResult, TextContent, Tool

from sandglass import PROJECT_ROOT, sandbox, scan
from sandglass.compare import (build_report, compare, compare_install, not_run, setup_line, summary_lines,
                               with_install, write_reports)
from sandglass.inputs import InputError, build_arguments
from sandglass.policy import (BASELINE_FILES, Policy, PolicyError, check_scan_paths,
                              load_install_baseline, load_policy)
from sandglass.trace_parser import parse_trace_file

REPORTS_DIR = PROJECT_ROOT / "reports"
# The work dir in every run's path mapping (#144).
WORKDIR_MAPPING = {str(sandbox.CONTAINER_WORKDIR): "the server's working directory: "
                                                   "an empty folder in the scratch /tmp (in memory)"}

# Total time budget for the tool calls (#140). Once it is used up, no more
# tools are called; the ones left are reported "not called (time budget)".
TIME_BUDGET_SECONDS = 120
# Upper bound for one tool call (#23); a call that takes longer is recorded
# as TIMED OUT and the next tool is still called (#140).
CALL_TIMEOUT_SECONDS = 30
# After a timed-out call, the server must answer a ping within this time, or
# no more tools are called: a stuck server would time out every call (#140).
PING_TIMEOUT_SECONDS = 5
# Safety net on top of the budget, for a handshake or shutdown that hangs.
# Hitting it is a session failure (INCOMPLETE).
SESSION_GRACE_SECONDS = 30

# --sandbox exit codes, so scripts and CI can check the verdict. INCOMPLETE
# is 3, not 2: argparse exits with 2 on a usage error, and a script must be
# able to tell "you called it wrong" from "the run can't be trusted" (#124).
EXIT_CODES = {"CLEAN": 0, "VIOLATIONS": 1, "INCOMPLETE": 3}

# --env names the user may not set (#144), with the reason. "X*" is a prefix.
# Compared upper-cased, so http_proxy is refused like HTTP_PROXY. The values
# reach the whole container (sh and strace too), not only the server.
REFUSED_ENV = [
    (("PATH", "HOME"), "set by Sandglass (HOME is the decoy home)"),
    (("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"), "set or removed by the launcher for the network sink"),
    (("SANDGLASS_*",), "read by Sandglass's launcher"),
    (("LD_*", "PYTHON*"), "read before the launcher hides the trace stream"),
    (("NODE_OPTIONS",), "changes how Sandglass starts Node"),
    (("DOCKER_*",), "read by the docker command on the host, which passes the values on"),
    (("GCONV_PATH", "LOCPATH", "GLIBC_TUNABLES", "MALLOC_*", "IFS", "ENV", "BASH_ENV"),
     "read by glibc or the shell before tracing starts"),
]
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def env_refusal(name: str) -> str | None:
    """Why Sandglass refuses this --env name, or None if it's allowed."""
    upper = name.upper()
    for names, reason in REFUSED_ENV:
        for refused in names:
            if upper == refused or (refused.endswith("*") and upper.startswith(refused[:-1])):
                return reason
    return None


def parse_server_env(items: list[str]) -> dict[str, str]:
    """--env KEY=VALUE items -> {KEY: VALUE} (#144). Raises ValueError with a
    message for the usage error: no "=", a bad or repeated name, a refused name."""
    env = {}
    for item in items:
        name, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"--env {item!r}: expected KEY=VALUE")
        if not ENV_NAME_RE.fullmatch(name):
            raise ValueError(f"--env {name!r}: not a valid variable name (letters, digits, _)")
        if name in env:
            raise ValueError(f"--env {name}: given twice")
        reason = env_refusal(name)
        if reason:
            raise ValueError(f"--env {name}: refused, {reason} (see README)")
        env[name] = value
    return env


def server_setup(command: list[str], server_args: list[str], server_env: dict) -> dict:
    """The server setup for the report (#144): the arguments as given, the
    environment's NAMES only (values are never recorded), the work dir, and a
    command line that reproduces the run, with the values redacted."""
    full = (command + [f"--server-arg={arg}" for arg in server_args]
            + [f"--env={name}=<redacted>" for name in server_env])
    return {"args": list(server_args), "env": list(server_env),
            "workdir": str(sandbox.CONTAINER_WORKDIR), "command": shlex.join(full)}


def build_safe_arguments(tool: Tool) -> dict:
    """Build a harmless, valid argument dict from the tool's JSON input schema
    (see sandglass/inputs.py). Raises InputError if the schema is unsupported."""
    return build_arguments(tool.input_schema)


def result_text(result) -> tuple[str, str]:
    """Return (status, text) for a tool result."""
    if not isinstance(result, CallToolResult):
        return "UNEXPECTED", f"(unexpected result type: {type(result).__name__})"
    texts = [c.text for c in result.content if isinstance(c, TextContent)]
    return ("ERROR" if result.is_error else "OK"), "\n".join(texts).strip()


def describe_error(exc: BaseException) -> str:
    """"Type: message" for the report. anyio wraps errors in an ExceptionGroup
    ("unhandled errors in a TaskGroup"), so name the first real error inside."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return f"{type(exc).__name__}: {exc}"


def print_policy(policy: Policy, enforced: bool) -> None:
    """Print the policy. `enforced` is True only in --sandbox mode, where the
    trace is compared with it; host mode just loads and shows it."""
    status = "enforced" if enforced else "not enforced (host mode)"
    print(f"Policy: {policy.name} ({status})")
    print(f"  {policy.description}")
    print(f"  read_allow:    {[str(p) for p in policy.read_allow]}")
    if policy.read_deny:
        print(f"  read_deny:     {[str(p) for p in policy.read_deny]}  (wins over every allow-list)")
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


def new_session_record() -> dict:
    """What run() fills in. tools: what the server listed; calls: tools that
    were called (status OK, ERROR, UNEXPECTED, TIMED OUT, FAILED, or NO ANSWER
    if the session ended during the call; a FAILED call that raised an MCP
    error also has its "error_code", #143); skipped: tools we couldn't build
    an input for; not_called: tools left when the calls stopped (#140)."""
    return {"tools": [], "calls": [], "skipped": [], "not_called": []}


def is_timeout(exc: BaseException) -> bool:
    """Did this call fail because it took longer than its timeout?"""
    return isinstance(exc, MCPError) and exc.code == REQUEST_TIMEOUT


async def server_answers_ping(session: ClientSession) -> bool:
    """Any answer counts, even an MCP error such as method-not-found: the
    server is still reading its messages. Only silence means it is stuck."""
    try:
        await asyncio.wait_for(session.send_ping(), PING_TIMEOUT_SECONDS)
    except MCPError as exc:
        return not is_timeout(exc)
    except TimeoutError:
        return False
    return True


async def run(params: StdioServerParameters, server_name: str, errlog=sys.stderr,
              session_record: dict | None = None) -> dict:
    """Run one MCP session and return a record of what was exercised.

    `errlog` receives the subprocess's stderr. In the sandbox that stream is
    the strace trace, so run_sandboxed passes the trace file here.
    `session_record` is filled in as the session goes, so if the session
    fails half-way the caller still has everything recorded until then (#23).
    The calls share TIME_BUDGET_SECONDS, counted from the start (#140).
    """
    if session_record is None:
        session_record = new_session_record()
    deadline = time.monotonic() + TIME_BUDGET_SECONDS

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

            stop_reason = None  # set once no more tools may be called (#140)
            for tool in tools:
                try:
                    args = build_safe_arguments(tool)
                except InputError as exc:
                    # Not guessed: the tool isn't called, and the report says why.
                    print(f"Skipping {tool.name}: no valid input ({exc})")
                    session_record["skipped"].append({"tool": tool.name, "reason": f"no valid input: {exc}"})
                    continue
                remaining = deadline - time.monotonic()
                if stop_reason is None and remaining <= 0:
                    stop_reason = "time budget"
                if stop_reason is not None:
                    # Never dropped silently: the report lists it as not called.
                    print(f"Not calling {tool.name}: {stop_reason}")
                    session_record["not_called"].append({"tool": tool.name, "reason": stop_reason})
                    continue
                print(f"Calling {tool.name}({args})")
                # Recorded BEFORE the call, so a session that dies during it
                # still shows the call was made and never answered (#23).
                call = {"tool": tool.name, "arguments": args, "status": "NO ANSWER",
                        "result": "the session ended before the call returned"}
                session_record["calls"].append(call)
                timeout = min(CALL_TIMEOUT_SECONDS, remaining)
                try:
                    result = await session.call_tool(tool.name, args, read_timeout_seconds=timeout)
                    call["status"], call["result"] = result_text(result)
                except Exception as exc:  # recorded, and the next tool is still called (#23)
                    call["status"] = "TIMED OUT" if is_timeout(exc) else "FAILED"
                    call["result"] = (f"no answer within {timeout:.0f} s" if is_timeout(exc)
                                      else describe_error(exc))
                    if isinstance(exc, MCPError):
                        # Kept for coverage (#143): an error response from the
                        # server is "returned an error", not a failed call. The
                        # status stays FAILED, so the verdict rules don't change.
                        call["error_code"] = exc.code
                print(f"  -> [{call['status']}] {call['result']}")
                # The SDK has already sent a cancel for the timed-out call. A
                # server that can't even answer a ping now would time out
                # every remaining call, so stop here instead.
                if call["status"] == "TIMED OUT" and not await server_answers_ping(session):
                    stop_reason = f"server stopped responding after {tool.name} timed out"
    # Leaving the `async with` closes the server's stdin and waits for it to
    # exit. In the sandbox, that's what lets strace finish writing the trace.
    return session_record


def run_host(server_script: Path) -> None:
    """Original behaviour: run the server directly, no tracing, no report."""
    # Start the server with the same Python interpreter running this client,
    # so it sees the same installed packages (the project's .venv). A .js
    # server runs with the `node` on your PATH.
    command = "node" if sandbox.runtime_for(server_script) == "node" else sys.executable
    params = StdioServerParameters(command=command, args=[str(server_script)])
    asyncio.run(run(params, server_script.name))


def run_sandboxed(server_script: Path, policy_path: Path, server_args: list[str] = (),
                  server_env: dict | None = None) -> dict:
    """Run the server in Docker under strace, compare, write and return the report.
    `server_args`, `server_env`: --server-arg and --env (#144), already checked."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    server = server_script.stem

    # Container paths, because that's what the trace will contain. The
    # multiarch triplet comes from inside the image (arm64 Mac vs x86_64 CI).
    multiarch = sandbox.detect_multiarch()
    runtime = sandbox.runtime_for(server_script)  # "python" or "node"
    policy = load_policy(policy_path, server_script=server_script,
                         in_sandbox=True, multiarch=multiarch, runtime=runtime)
    print_policy(policy, enforced=True)

    server_env = server_env or {}
    setup = server_setup(["sandglass", str(server_script.relative_to(PROJECT_ROOT)),
                          "--policy", str(policy_path), "--sandbox"], server_args, server_env)
    command, args = sandbox.docker_command(server_script, server_args, list(server_env))
    path_mapping = {
        str(sandbox.CONTAINER_PROJECT): f"{PROJECT_ROOT} (read-only)",
        str(sandbox.CONTAINER_REPORTS): "hidden (empty read-only tmpfs)",
        str(sandbox.CONTAINER_VENV): "dependencies baked into the image",
        str(sandbox.CONTAINER_PYTHON_BASE): "Python from python:3.12-slim",
        **WORKDIR_MAPPING,
    }
    return _trace_and_report(server, timestamp, command, args, policy, runtime, multiarch,
                             path_mapping, setup=setup, server_env=server_env)


def _trace_and_report(server: str, timestamp: str, command: str, args: list[str], policy: Policy,
                      runtime: str, multiarch: str, path_mapping: dict,
                      package: dict | None = None,
                      install: dict | None = None, setup: dict | None = None,
                      server_env: dict | None = None) -> dict:
    """Run the docker command under strace, compare, write and return the report.

    Shared by fixture mode (run_sandboxed) and scan mode (run_scan). The
    server runs in sandbox.CONTAINER_WORKDIR, so the trace's relative paths
    start there (#144). `install` (scan mode, #16) is compare_install()'s
    result, added in front. `setup` is server_setup()'s record for the report;
    `server_env` the --env values, given only to the docker command's own
    environment (its -e NAME copies them into the container).
    """
    if setup:
        print(f"Server setup: {setup_line(setup)}")
    # Written on the HOST from the container's stderr (strace's output). The
    # container never sees this file: reports/ is hidden inside it.
    trace_file = _trace_dir(server, timestamp) / sandbox.TRACE_FILENAME
    params = StdioServerParameters(command=command, args=args, env=server_env or None)

    # Any failure (image missing, server crash, timeout) is recorded, not
    # raised: the report must still be written, with verdict INCOMPLETE.
    # The container's stderr (the trace) goes straight into trace_file.
    session = new_session_record()  # filled in by run(), kept even if it fails half-way
    with open(trace_file, "w", encoding="utf-8") as trace_out:
        try:
            # run() keeps to the time budget itself (#140); this is only the
            # safety net for a handshake or shutdown that hangs.
            asyncio.run(asyncio.wait_for(run(params, server, trace_out, session),
                                         TIME_BUDGET_SECONDS + SESSION_GRACE_SECONDS))
        except BaseException as exc:  # includes ExceptionGroup from anyio task groups
            if isinstance(exc, KeyboardInterrupt):
                raise
            session["error"] = describe_error(exc)
            print(f"Session failed: {session['error']}")

    # Line by line, up to MAX_TRACE_BYTES: a huge trace can't use up memory (#83).
    events, cut_short = parse_trace_file(trace_file, cwd=str(sandbox.CONTAINER_WORKDIR))
    result = compare(events, policy, session, runtime=runtime, trace_cut_short=cut_short)
    if install is not None:
        result = with_install(result, install)

    path_mapping = {**path_mapping,
                    "(container stderr)": f"strace output, saved on the host as {trace_file}"}
    report = build_report(server, timestamp, policy, session, result, trace_file,
                          path_mapping, _baseline(policy, runtime, multiarch), package, setup)
    return _write_and_print(report)


def _trace_dir(server: str, timestamp: str) -> Path:
    """reports/trace/<server>_<timestamp>/, for this run's trace files."""
    trace_dir = REPORTS_DIR / "trace" / f"{server}_{timestamp}"
    trace_dir.mkdir(parents=True, exist_ok=True)
    return trace_dir


def _baseline(policy: Policy, runtime: str, multiarch: str) -> dict:
    """Which container baseline was applied, and how (for the report)."""
    return {
        "name": policy.baseline_name,
        "file": ", ".join(str(f.relative_to(PROJECT_ROOT)) for f in BASELINE_FILES[runtime]),
        "runtime": runtime,
        "multiarch": multiarch,
    }


def _write_and_print(report: dict) -> dict:
    """Write the JSON + Markdown report and print the summary."""
    json_path, md_path = write_reports(report, REPORTS_DIR)
    print()
    # Network events grouped per domain / lookup / address (#141), like the Markdown.
    for line in summary_lines(report):
        print(line)
    shown = [p.relative_to(PROJECT_ROOT) if p.is_relative_to(PROJECT_ROOT) else p
             for p in (json_path, md_path)]
    print(f"Report: {shown[0]}")
    print(f"        {shown[1]}")
    return report


# ---------------------------------------------------------------------------
# sandglass scan (#19)
# ---------------------------------------------------------------------------

# The entry point isn't known until the package is downloaded; the policy is
# loaded once before that (so a broken policy fails before any download),
# with this stand-in for {server_script}.
PENDING_ENTRY = f"{sandbox.CONTAINER_PACKAGE}/(entry point not known yet)"


def _scan_policy(policy_path: Path, server_path: str, multiarch: str, runtime: str) -> Policy:
    return load_policy(policy_path, in_sandbox=True, multiarch=multiarch, runtime=runtime,
                       container_script=server_path, package_dir=str(sandbox.CONTAINER_PACKAGE))


def run_scan(spec: scan.PackageSpec, policy_path: Path, registry_dir: Path | None = None,
             entry: str | None = None, server_args: list[str] = (),
             server_env: dict | None = None) -> dict:
    """Download (host), install (sandbox), run and trace one package; return the report.

    Any failing step makes a report too, with verdict INCOMPLETE and the reason.
    `server_args`, `server_env`: --server-arg and --env (#144), already checked.
    """
    server_env = server_env or {}
    setup = server_setup(["sandglass", "scan", str(spec), "--policy", str(policy_path)]
                         + (["--entry", entry] if entry else [])
                         + (["--registry-dir", str(registry_dir)] if registry_dir else []),
                         server_args, server_env)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    multiarch = sandbox.detect_multiarch()
    runtime = "node" if spec.ecosystem == "npm" else "python"
    policy = _scan_policy(policy_path, PENDING_ENTRY, multiarch, runtime)
    package = {
        "spec": str(spec), "ecosystem": spec.ecosystem, "name": spec.name, "version": spec.version,
        "source": (f"local test registry {registry_dir}" if registry_dir else
                   "PyPI" if spec.ecosystem == "pypi" else "the npm registry"),
        "files": [], "entry": None,
        "hash": None,     # the package hash vs the registry's (#21)
        "install": None,  # filled in once the install has run (#16)
    }
    print(f"Scanning {spec} (from {package['source']})")

    # Docker volume names: letters, digits, "_", ".", "-".
    volume = re.sub(r"[^A-Za-z0-9_.-]", "-", f"sandglass-{spec.slug}-{timestamp}")
    with tempfile.TemporaryDirectory(prefix="sandglass-download-") as tmp:
        folder = Path(tmp)
        folder.chmod(0o755)  # the install container's user must be able to read it
        try:
            prepared = scan.download(spec, folder, multiarch, registry_dir)
            package["files"] = scan.describe_files(prepared)  # each with its sha256
            # The package hash (#21): compared with the registry's before any install.
            package["hash"] = scan.verify_hash(prepared, registry_dir)
            h = package["hash"]
            print(f"Hash of {h['file']}: {h['ours']} ({'matches' if h['match'] else 'DOES NOT MATCH'}"
                  f" {h['source']})")
            if not h["match"]:
                raise scan.ScanError(f"package hash mismatch: {h['file']} has {h['algorithm']} {h['ours']}, "
                                     f"but {h['source']} publishes {h['published']}; not installed")
            entry_name, server_path = scan.choose_entry(prepared, entry)
            package["entry"] = {"name": entry_name, "path": server_path}
            print(f"Entry point: {entry_name} -> {server_path}")

            policy = _scan_policy(policy_path, server_path, multiarch, runtime)
            print_policy(policy, enforced=True)
            sandbox.create_volume(volume)
            try:
                # The install, traced (#16). Judged even if it failed: a
                # failing install may still have misbehaved first.
                trace_dir = _trace_dir(spec.slug, timestamp)
                install_trace = trace_dir / scan.INSTALL_TRACE_FILENAME
                install_log = trace_dir / scan.INSTALL_LOG_FILENAME
                print("Installing inside the sandbox (offline, traced)...")
                exit_code = scan.install(prepared, volume, install_trace, install_log)
                baseline = load_install_baseline(multiarch)
                install_events, cut_short = parse_trace_file(install_trace,
                                                             cwd=str(sandbox.CONTAINER_PACKAGE))
                install = compare_install(install_events, policy, baseline, exit_code,
                                          scan.log_tail(install_log), cut_short)
                package["install"] = {
                    "trace_file": str(install_trace), "log_file": str(install_log),
                    "exit_code": exit_code, "baseline": baseline.name,
                    "violations": len(install["violations"]), "event_counts": install["event_counts"],
                }
                print(f"Install: exit {exit_code}, {len(install['violations'])} violation(s)")
                if exit_code != 0:  # failed or timed out: nothing to run
                    report = build_report(spec.slug, timestamp, policy, new_session_record(),
                                          with_install(not_run(None), install), None, {},
                                          _baseline(policy, runtime, multiarch), package, setup)
                    return _write_and_print(report)

                command, args = sandbox.scan_run_command(volume, server_path, runtime,
                                                         server_args, list(server_env))
                path_mapping = {
                    str(sandbox.CONTAINER_PACKAGE): "the installed package (a Docker volume, read-only)",
                    str(sandbox.CONTAINER_PROJECT): "not mounted: the project is never visible to a scan (#20)",
                    str(sandbox.CONTAINER_VENV): "Sandglass's dependencies, baked into the image",
                    str(sandbox.CONTAINER_PYTHON_BASE): "Python from python:3.12-slim",
                    **WORKDIR_MAPPING,
                }
                return _trace_and_report(spec.slug, timestamp, command, args, policy, runtime,
                                         multiarch, path_mapping, package, install=install,
                                         setup=setup, server_env=server_env)
            finally:
                sandbox.remove_volume(volume)
        except scan.ScanError as exc:
            print(f"Scan failed: {exc}")
            report = build_report(spec.slug, timestamp, policy, new_session_record(),
                                  not_run(str(exc)), None, {}, _baseline(policy, runtime, multiarch),
                                  package, setup)
            return _write_and_print(report)


def add_setup_arguments(parser: argparse.ArgumentParser) -> None:
    """--server-arg and --env (#144), for both `sandglass scan` and --sandbox."""
    parser.add_argument("--server-arg", action="append", default=[], metavar="ARG",
                        help="an argument for the server (repeatable, in order). Recorded in the "
                             "report as given. One starting with '-' needs --server-arg=ARG")
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                        help="an environment variable for the server (repeatable). Fake values "
                             "only; the report records the name, never the value")


def checked_env(parser: argparse.ArgumentParser, args: argparse.Namespace) -> dict[str, str]:
    """--env as a dict, or a usage error (exit 2) naming the problem (#144)."""
    try:
        return parse_server_env(args.env)
    except ValueError as exc:
        parser.error(str(exc))


def scan_main(argv: list[str]) -> None:
    """`sandglass scan <pypi|npm>:<package>@<exact-version> --policy <file>`."""
    parser = argparse.ArgumentParser(
        prog="sandglass scan",
        description="Download a package on the host, install it in the sandbox (offline), "
                    "run its MCP server under strace and compare with a policy. "
                    "Exit code: 0 CLEAN, 1 VIOLATIONS, 2 usage error, 3 INCOMPLETE.")
    parser.add_argument("package", help="<pypi|npm>:<package>@<exact-version>, "
                                        "e.g. pypi:mcp-server-fetch@2025.4.7")
    parser.add_argument("--policy", type=Path, required=True, help="policy YAML to compare against")
    parser.add_argument("--entry", help="which console script / npm bin starts the server, "
                                        "if the package has several")
    parser.add_argument("--registry-dir", type=Path,
                        help="a local folder of test packages (e.g. test_packages/dist) "
                             "to use instead of PyPI/npm")
    add_setup_arguments(parser)
    args = parser.parse_args(argv)
    server_env = checked_env(parser, args)

    try:
        spec = scan.parse_spec(args.package)
    except scan.SpecError as exc:
        parser.error(str(exc))
    if not args.policy.is_file():
        parser.error(f"policy file not found: {args.policy}")
    try:
        # Before Docker or any download: a scan has no project folder (#123).
        check_scan_paths(args.policy)
    except PolicyError as exc:
        parser.error(str(exc))
    if args.registry_dir is not None and not args.registry_dir.is_dir():
        parser.error(f"--registry-dir is not a folder: {args.registry_dir}")
    registry_dir = args.registry_dir.resolve() if args.registry_dir else None

    try:
        report = run_scan(spec, args.policy, registry_dir, args.entry, args.server_arg, server_env)
    except sandbox.SandboxError as exc:
        print(f"Sandbox error: {exc}", file=sys.stderr)
        sys.exit(EXIT_CODES["INCOMPLETE"])
    except PolicyError as exc:
        parser.error(f"policy {args.policy}: {exc}")
    sys.exit(EXIT_CODES[report["verdict"]])


def main() -> None:
    if sys.argv[1:2] == ["scan"]:
        scan_main(sys.argv[2:])  # sandglass scan <pypi|npm>:<package>@<version> ...
        return
    parser = argparse.ArgumentParser(description="Exercise an MCP server's tools over stdio. "
                                                 "(To scan a published package: sandglass scan -h) "
                                                 "With --sandbox, exit code: 0 CLEAN, 1 VIOLATIONS, "
                                                 "2 usage error, 3 INCOMPLETE.")
    parser.add_argument("server", type=Path, help="path to the server (.py, or .js for Node.js)")
    parser.add_argument("--policy", type=Path, help="policy YAML to load (required with --sandbox)")
    parser.add_argument("--sandbox", action="store_true",
                        help="run in Docker under strace and write a report")
    add_setup_arguments(parser)
    args = parser.parse_args()
    server_env = checked_env(parser, args)
    if (args.server_arg or server_env) and not args.sandbox:
        parser.error("--server-arg and --env need --sandbox")

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
            report = run_sandboxed(server_script, args.policy, args.server_arg, server_env)
        except sandbox.SandboxError as exc:
            # No sandbox -> nothing observed -> never "clean".
            print(f"Sandbox error: {exc}", file=sys.stderr)
            sys.exit(EXIT_CODES["INCOMPLETE"])
        sys.exit(EXIT_CODES[report["verdict"]])

    if args.policy:
        print_policy(load_policy(args.policy, server_script=server_script), enforced=False)
    run_host(server_script)


if __name__ == "__main__":
    main()
