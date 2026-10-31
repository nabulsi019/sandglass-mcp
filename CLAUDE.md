# Sandglass: working rules

Sandglass runs an MCP server in a sandbox, records what it actually does
(files, processes, network), and compares that with a policy. See README.md.

## Workflow rules

- **One branch per issue**: `feat/<issue#>-short-name`. **Never commit or push to `main`.**
  (The `protect-main` ruleset enforces this on `main`: no deletion, no force-push, changes
  only through a PR, and the `pytest` and `fixtures` checks must pass.)
- **Commit as the owner**: before your first commit in any session, set git user.name
  to 'Mohammed AlNabulsi' and user.email to '223641424+nabulsi019@users.noreply.github.com'.
  Never commit as Claude.
- **Open a PR with `Closes #<n>`.**
- **Merging**: Claude may merge a PR into main only when: both required checks pass,
  there are no conflicts, and none of these protected items were changed:
  - every `EXPECTED` and `EXPECTED_DOMAINS` entry in `scripts/check_fixtures.py`
    (the verdict and exact violations of all 8 fixtures: good_notes_server,
    overreach_notes_server, listing_notes_server, aws_credentials_server,
    shell_command_server, undeclared_domain_server, good_notes_node_server.js,
    tamper_trace_server; and the sink requests undeclared_domain_server must make)
  - every `EXPECTED_V04`, `EXPECTED_SCANS`, `EXPECTED_SCAN_PHASES`,
    `EXPECTED_SCAN_STOPPED` and `EXPECTED_SCAN_ATTEMPTS` entry in
    `scripts/check_fixtures.py` (the verdict, exact violations and INCOMPLETE
    reasons of missing_api_key_server; the verdict and exact violations of all
    8 scans: pypi:sandglass-test-notes, npm:sandglass-test-notes,
    pypi:sandglass-test-peek, npm:sandglass-test-postinstall,
    pypi:sandglass-test-tampered, and the hostile archives
    npm:sandglass-test-traversal, pypi:sandglass-test-symlink and
    pypi:sandglass-test-bomb; the install phase of
    npm:sandglass-test-postinstall's violation; the stop reasons of
    pypi:sandglass-test-tampered and of the three hostile archives; and the
    failed attempts pypi:sandglass-test-peek must show)
  - the host-side archive checks in `sandglass/scan.py` (#133): `check_archive`
    on every downloaded file before anything reads it, its limits
    (`MAX_ARCHIVE_BYTES` 500 MB, `MAX_ARCHIVE_FILES` 20,000), and
    `--ignore-scripts` on every npm command run on the host
  - every `EXPECTED_POLICY_RUNS` entry in `scripts/check_fixtures.py` (the
    policy, verdict and exact violations of aws_credentials_server and
    symlink_escape_server under policies/templates/no_network.v1.yaml), and the `read_deny: [/home, /root]`
    of the no_network.v1 and listed_domains_only.v1 templates
  - every `EXPECTED_HOSTILE` entry in `scripts/check_fixtures.py`, and the
    `POLICIES` it names (the policy, verdict, exact violations and INCOMPLETE
    reasons of the hostile fixtures: proc_self_escape_server under
    no_network.v1 and notes_readonly; untraced_clone_server,
    iouring_node_server.js and ptrace_server under notes_readonly;
    stall_sink_server under listed_domains_only.v1 and notes_readonly, with
    the sink requests in `EXPECTED_HOSTILE_DOMAINS`), the
    `FIXTURE_DOCKER_OPTIONS` they run with, and every `EXPECTED_OLD_DOCKER`
    entry (the old-Docker simulation with `OLD_DOCKER_OPTIONS`, Docker's own
    seccomp profile off, test code only: good_notes_node_server.js CLEAN,
    untraced_clone_server and iouring_node_server.js VIOLATIONS)
  - Sandglass's syscall filter in `sandglass/launcher.py` (#84):
    `install_syscall_filter` and `filter_self_test`, run right after the fd
    swap; EPERM for io_uring_setup/enter/register, ptrace, process_vm_readv,
    process_vm_writev and clone with CLONE_UNTRACED, ENOSYS for clone3, every
    syscall refused for another ABI; and compare.py's rules for it (a missing
    or failed self-test is INCOMPLETE, an evasion attempt is a violation).
    `seccomp=unconfined` never appears in `sandglass/`
  - the network sink's accounting (#136): `sandglass/netsink.py` reads every
    connection side by side with a deadline and drains open and queued ones
    on shutdown (one record per connection); compare.py makes a trace/sink
    connection count mismatch INCOMPLETE, and an unidentified connection a
    violation (no network allowed) or INCOMPLETE (some domains allowed)
  - every `EXPECTED_NPM_REGISTRY_SCANS` entry in `scripts/check_fixtures.py`
    (#138: npm:sandglass-test-notes CLEAN and npm:sandglass-test-traversal
    INCOMPLETE `unsafe archive`, through the npm download container from a
    local registry), and the download container's hardening in
    `sandglass/sandbox.py` (`npm_download_container_args`: uid 10001,
    `--read-only`, `--cap-drop ALL`, no-new-privileges, only the scan's temp
    folder mounted, no project mount, `--ignore-scripts`; npm never runs on
    the host and node_modules never reaches it)
  - every `EXPECTED_TIMEOUTS` entry in `scripts/check_fixtures.py` (#140:
    hanging_tool_server CLEAN under notes_readonly, with `hang` timed out,
    `read_note` ran, and the report saying Sandglass stopped the server; run
    with `FIXTURE_CALL_TIMEOUT_SECONDS`, test code only)
  - every `EXPECTED_RUNTIME` entry in `scripts/check_fixtures.py` (#142:
    runtime_noise_server CLEAN under notes_readonly, with `uname -p` in
    "Programs run" and its baseline note; runtime_neighbours_server
    VIOLATIONS, exactly the bind to 127.0.0.1:8080, the listen, the exec of
    `uname -a` and the write to /dev/zero)
  - every `EXPECTED_COVERAGE_SUMMARY` entry in `scripts/check_fixtures.py`
    (#143: tool_error_server CLEAN under notes_readonly, with the coverage
    summary "1 of 2 tools returned errors")
  - every `EXPECTED_SERVER_SETUP` entry in `scripts/check_fixtures.py`, with
    `SETUP_ARGS`, `SETUP_ENV` and `SETUP_POLICIES` (#144:
    setup_required_server with its setup CLEAN under no_network.v1 and
    VIOLATIONS under read_only_folder.v1, exactly the write of
    /tmp/work/setup_note.txt; without its setup INCOMPLETE), the work dir
    `/tmp/work` made by sh before strace starts, and the refused `--env`
    names in `REFUSED_ENV` in `sandglass/client.py`
  - every `EXPECTED_INPUT_MODES` entry in `scripts/check_fixtures.py` (#145:
    described_input_server CLEAN under notes_readonly with `--inputs described`,
    its timezone "America/New_York" from param-description, no coverage
    summary; with `--inputs minimal` CLEAN with the coverage summary
    "1 of 1 tool returned errors", its timezone "hello" from fallback)
  - every `EXPECTED_ENVIRONMENT` entry in `scripts/check_fixtures.py`, with
    `PROXY_NAMES` and `BASE_ENV_NAMES` (#146: env_report_server and
    env_report_server.js CLEAN under no_network.v1, with exactly those
    variable names in both views and no "SANDGLASS" in any name or value),
    the runtime and site dir passed to the launcher as arguments (never
    `SANDGLASS_*` variables), and `UNSET_BEFORE_TRACING` in `sandglass/sandbox.py`
  - every `EXPECTED_MISSING_PROGRAM` entry in `scripts/check_fixtures.py`
    (#148: missing_program_server INCOMPLETE under notes_readonly, no
    violations, with exactly the reason "the server needs a program the
    sandbox doesn't have: sandglass-missing-program")
  - `EXPECTED_EXIT_CODES` in `scripts/check_fixtures.py` (the exit code of
    every verdict: 0 CLEAN, 1 VIOLATIONS, 3 INCOMPLETE; 2 is a usage error)
  - the sandbox hardening flags (--network none, --read-only, non-root user,
    no --cap-add)
  - the strace permissions: `chmod 0711 /usr/bin/strace` in the Dockerfile
    (executable but not readable, so the server can't reach strace's fds)
  - the read-only tmpfs over `reports/` in sandbox.py (hides traces and reports)
  - the launcher's fd swap: the server's stderr pointed at /dev/null and fd 3
    closed (`os.dup2(3, 2)`, `os.close(3)`) before any server code runs
  - the decoy HOME: `-e HOME=/home/sandglass` and the image's
    `sandbox/decoy_home/` (fake credentials only, never the host's home)
  - the CI workflows' required checks, or the ruleset.

  After every merge, pull main and rerun pytest and check_fixtures.py. If main
  is red, revert the PR that caused it; if the failure already existed before
  that PR, stop and report instead. Never force-push. If a task requires
  changing any protected item, stop and report.
- **Before opening a PR**: tests pass locally, and the fixtures give the expected
  verdicts (see Commands below). Put the real results in the PR's "How I tested it".
- **If CI fails or the owner leaves review comments**, fix them on the same branch.
- **Plan before code** for anything touching the sandbox, trace parsing, or policy:
  write the plan, wait for approval, then implement.
- **The Safety rules in README.md apply to every change**: only servers we wrote or
  may test, only fake credentials, never real secrets, disclose real findings privately.

## Commands

```bash
uv sync                      # install (including pytest)
uv run pytest                # unit tests, no Docker needed

# Run one server (the `sandglass` command = `python -m sandglass.client`):
uv run sandglass test_servers/good_notes_server.py --policy policies/notes_readonly.yaml --sandbox

# Expected verdicts of all 8 fixtures (see EXPECTED in the script), required before every PR:
docker build -t sandglass-sandbox .
uv run python scripts/check_fixtures.py   # must print "all ... fixtures match expectations"
```

## Code style

- Keep code simple and commented: the owner must be able to explain every file
  in an interview.
- Match the surrounding code's naming and comment density.
- Report outcomes honestly: if a check fails or was skipped, say so with the output.
