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
  there are no conflicts, and none of these were changed: the expected fixture
  verdicts (good=0, overreach=1, listing=2), the sandbox hardening flags
  (--network none, --read-only, non-root user, no --cap-add), the CI workflows'
  required checks, or the ruleset. After every merge, pull main and rerun pytest
  and check_fixtures.py; if main is red, revert that PR and stop. Never
  force-push. If a task requires changing any protected item, stop and report.
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

# Expected fixture verdicts (good CLEAN, overreach 1, listing 2), required before every PR:
docker build -t sandglass-sandbox .
uv run python scripts/check_fixtures.py   # must print "all ... fixtures match expectations"
```

## Code style

- Keep code simple and commented: the owner must be able to explain every file
  in an interview.
- Match the surrounding code's naming and comment density.
- Report outcomes honestly: if a check fails or was skipped, say so with the output.
