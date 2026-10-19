# Security policy

Sandglass runs untrusted MCP servers in a sandbox and reports what they do.
A security bug in Sandglass can make a misbehaving server look clean, so
reports are very welcome.

## Reporting a vulnerability in Sandglass

**Please do not open a public issue, pull request or discussion.** Report privately instead:

1. **GitHub private vulnerability reporting (preferred):**
   [Report a vulnerability](https://github.com/nabulsi019/sandglass-mcp/security/advisories/new)
   (or the repo's **Security** tab, then **Report a vulnerability**). Only you and
   the maintainer can see the report.
2. **Email:** mohammadnabulsi019@gmail.com, with "Sandglass security" in the subject.

Please include:

- what you found and why it matters (e.g. "server X reads file Y but the verdict is CLEAN")
- steps to reproduce: the server or trace you used, the policy, the command line
- the Sandglass version (commit or tag) and your OS / Docker setup

You'll get a reply through the same channel. Once a fix is ready, it's released
first and the details are published afterwards in a GitHub security advisory,
crediting you unless you prefer otherwise.

Only the latest commit on `main` is supported. Fixes are not backported to older tags.

## Scope

**In scope:**

- **Detection bypasses**: a server reads, writes, executes or connects in a
  way that should be a violation, yet the report shows it as allowed or CLEAN
  (e.g. trace parsing mistakes, path-matching tricks, events missing from the trace).
- **Verdict integrity**: a run that should be INCOMPLETE (server didn't start,
  truncated trace, failed session) is reported as CLEAN.
- **Sandbox weaknesses in our configuration**: the `docker run` command or the
  Dockerfile letting a server write outside `/trace` and `/tmp`, reach the
  network despite `--network none`, gain privileges, or affect the host.
- **Unsafe handling of inputs**: policy files, baselines, traces or MCP responses
  that can make Sandglass itself misbehave (code execution, writing outside `reports/`).
- **This repository**: secrets committed by mistake, or CI workflows that can be abused.

**Out of scope:**

- **Vulnerabilities in third-party MCP servers.** Report those to the server's
  maintainers (see below for how Sandglass handles its own findings).
- **Bugs in Docker, strace, Python or the base image.** Please report them upstream.
  If our configuration makes one exploitable, that part *is* in scope.
- **Limitations already documented** in the README's "Known limitations" section
  (e.g. the whole project is mounted read-only, paths are compared as text, a
  container is not a VM).
- **The fixtures in `test_servers/`.** They misbehave on purpose and only touch
  fake decoy files (e.g. `FAKE_KEY_FOR_TESTING` is not a real key).

## Findings in third-party MCP packages

When Sandglass finds a real MCP server doing something its description doesn't
admit, the finding is **disclosed privately to that server's maintainers first**:
through their security policy, GitHub private vulnerability reporting, or a
direct contact. Nothing is published (no issue, write-up, report or example)
until the maintainers have had a chance to respond and fix it. Example reports in
this repository only ever come from our own fixtures or from findings that have
already been disclosed and resolved.
