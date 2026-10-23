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
    5 scans: pypi:sandglass-test-notes, npm:sandglass-test-notes,
    pypi:sandglass-test-peek, npm:sandglass-test-postinstall,
    pypi:sandglass-test-tampered; the install phase of
    npm:sandglass-test-postinstall's violation; the stop reasons of
    pypi:sandglass-test-tampered; and the failed attempts
    pypi:sandglass-test-peek must show)
  - every `EXPECTED_POLICY_RUNS` entry in `scripts/check_fixtures.py` (the
    policy, verdict and exact violations of aws_credentials_server under
    policies/templates/no_network.v1.yaml), and the `read_deny: [/home, /root]`
    of the no_network.v1 and listed_domains_only.v1 templates
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
