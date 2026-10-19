# Sandglass: working rules

Sandglass runs an MCP server in a sandbox, records what it actually does
(files, processes, network), and compares that with a policy. See README.md.

## Workflow rules

- **One branch per issue**: `feat/<issue#>-short-name`. **Never commit or push to `main`.**
  (Branch protection was not available while the repo was private. Once it is public it can
  be turned on for `main`; until then this rule is the only guard.)
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
