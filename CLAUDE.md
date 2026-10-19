# MCP Guard: working rules

MCP Guard runs an MCP server in a sandbox, records what it actually does
(files, processes, network), and compares that with a policy. See README.md.

## Workflow rules

- **One branch per issue**: `feat/<issue#>-short-name`. **Never commit or push to `main`.**
  (Branch protection is not available on this private repo, so this rule is the only guard.)
- **Open a PR with `Closes #<n>`. Never merge.** The owner reviews and merges.
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

# Fixture checks. Until the sandbox is merged (v0.2), run both fixtures in host mode:
uv run python -m guard.client test_servers/good_notes_server.py --policy policies/notes_readonly.yaml
uv run python -m guard.client test_servers/overreach_notes_server.py --policy policies/notes_readonly.yaml

# Once the sandbox is merged, the expected verdicts are checked with:
docker build -t mcp-guard-sandbox .
uv run python scripts/check_fixtures.py   # must print "all ... fixtures match expectations"
```

## Code style

- Keep code simple and commented: the owner must be able to explain every file
  in an interview.
- Match the surrounding code's naming and comment density.
- Report outcomes honestly: if a check fails or was skipped, say so with the output.
