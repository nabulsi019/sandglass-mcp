# Sandglass

Sandglass runs a [Model Context Protocol](https://modelcontextprotocol.io)
server in a sandbox, calls its tools, records what it **actually does**
(files, processes, network), and compares that with a **policy**.

A server's tool description says what it *claims* to do. Sandglass checks
what it *does*: every file it opens, every program it runs and every domain
it tries to contact, before you approve it.

Repository: <https://github.com/nabulsi019/sandglass-mcp>. Formerly **MCP Guard**
(the `v0.2` tag predates the rename).

> **Status: v0.4.2 on `main`** (last tag: v0.4.1). Works: scanning a PyPI
> or npm package, or a local `.py`/`.js` server, in a Docker sandbox under
> `strace`, with a quick scan or a `--deep` one, judged against a policy,
> with a JSON and Markdown report. Not yet: real network answers for tools
> (every lookup gets NXDOMAIN, #173), pinning a package's dependencies
> (#157), sdist-only PyPI packages, CPUs other than x86_64 and aarch64.

## Quick start

Requires [Docker](https://docs.docker.com/get-docker/) (OrbStack or Docker
Desktop on macOS) and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/nabulsi019/sandglass-mcp.git && cd sandglass-mcp
uv sync
docker build -t sandglass-sandbox .
uv run sandglass scan pypi:mcp-server-time@2026.10.19 --policy policies/templates/no_network.v1.yaml
```

The last command downloads the package (wheels only, nothing runs on your
machine), installs it inside the sandbox, starts it with no network, calls
each tool, and prints the verdict and where the report is.

- **Quick scan** (the default): one call per tool, a first look. About
  10 to 40 s once the package is downloaded.
- **Deep scan** (`--deep`): up to 5 calls per tool with sample files, two
  runs and a 60 s watch after the last call; recommended before approving
  a server. About 2 to 20 min.

Times are measured, with their sources, in [docs/results.md](docs/results.md).
All options (server arguments, `--env`, `--inputs`, `--deep`) are in
[docs/usage.md](docs/usage.md).

## What you get

An excerpt of a real report, from a fixture run (`check_fixtures.py`, on
2026-11-17): our test package `npm:sandglass-test-postinstall`, whose
`postinstall` script reads the sandbox's decoy credentials. Some lines are
left out and two long ones are wrapped or cut; nothing is changed.

```
# Sandglass report: npm_sandglass-test-postinstall_1.0.0

**Verdict: VIOLATIONS**

- Depth: quick scan: a first look
- Duration: 2.5 s (download 0.0 s (2 KB), install 1.1, run 1.0, analysis 0.2)
- Policy: `read_only_folder_v1`
- Violations: 1 · Attempted: 50 · Probes: 38
- Note: the server could detect it was traced (strace shows in /proc/self/status,
  TracerPid); a CLEAN verdict only covers what it did while traced (#82).

## Coverage

Ran 1 · Returned an error 0 · Failed 0 · Timed out 0 · Not called 0 · Skipped 0 · Total 1

## Not tested

- Dependency hashes were recorded but not compared to the registry; only the
  package's own file was verified.

## Violations by phase

### Install

1. **install read outside allowed paths**: `/home/sandglass/.aws/credentials`
   - syscall `openat`, succeeded, pid 23, at 21:12:34.475059 (install)
```

The server itself was clean; the read happened while npm installed it. The
full report also lists every tool call and its input, the domains and names
the server asked for, every program it ran, and the failed attempts. A JSON
report has the same data, and the raw `strace` trace is kept next to it.

## Verdicts and exit codes

| Verdict | Exit code | Meaning |
|---|---|---|
| CLEAN | `0` | nothing outside the policy was seen while the server was traced |
| VIOLATIONS | `1` | the server read, wrote, contacted or ran something the policy doesn't allow |
| INCOMPLETE | `3` | the run can't be trusted or didn't finish (the server didn't start, the trace is incomplete, a sandbox check failed); never CLEAN |

`2` is a usage error (a wrong argument, a missing file).

**CLEAN never means safe.** It only covers what ran, with the inputs
Sandglass gave, while traced. Next to the verdict the report says how many
tools returned errors or weren't called, e.g. `CLEAN (but 1 of 2 tools
returned errors)`. How each event is judged: [docs/policies.md](docs/policies.md#how-behaviour-is-judged).

## Policy templates

Copy one of these from `policies/templates/` and edit the lines marked
`EDIT` (format and rules: [docs/policies.md](docs/policies.md)):

| Template | What it allows |
|---|---|
| `policies/templates/read_only_folder.v1.yaml` | reads inside one folder only; no writes, no network, no other programs |
| `policies/templates/no_network.v1.yaml` | reads anywhere except `/home` and `/root`, writes in `/tmp`; no network at all, no other programs |
| `policies/templates/listed_domains_only.v1.yaml` | like `no_network`, plus requests to the listed domains through the local sink |

## Known limitations

A server can tell it's being traced (`TracerPid` in `/proc/self/status`,
#82) or in a sandbox, and behave well only then. Anything it does more than
60 s after the last call, only with other inputs, or only in another
environment isn't seen. All of them: [docs/limitations.md](docs/limitations.md).

## Documentation

- [docs/usage.md](docs/usage.md): setup, scanning a package, server setup
  (`--server-arg`, `--env` and the refused `--env` names), tool inputs,
  `--deep`, exit codes.
- [docs/how-it-works.md](docs/how-it-works.md): the sandbox, the launcher,
  the syscall filter, the network sink, the DNS recorder, the observation
  window, the server's environment, the repository layout, related work.
- [docs/policies.md](docs/policies.md): the policy format, the templates,
  how behaviour is judged (phases, coverage, durations).
- [docs/limitations.md](docs/limitations.md): known limitations in full.
- [docs/fixtures.md](docs/fixtures.md): the fixtures, their expected
  verdicts, and how to run the tests.
- [docs/results.md](docs/results.md): every number we quote, with its
  source: tests, fixtures, real-server scans, scan times, the outside review.

## Safety rules

1. **Only run servers you wrote or have explicit permission to test.** The
   sandbox reduces risk, but it is a container, not a VM. Treat any server as
   untrusted code.
2. **Only use fake credentials.** Decoys like `test_servers/decoy_home/.fake_credentials`
   must contain obviously fake values (e.g. `FAKE_KEY_FOR_TESTING`).
3. **Never put real secrets anywhere a tested server can reach**, including the
   project folder (it is mounted into the container) and environment variables
   (`--env` values are never recorded, but the server can read them).
4. **Disclose real findings privately.** If you find a real server misbehaving,
   report it privately to its maintainers (security contact or private advisory)
   and give them time to fix it before you publish anything.

To report a vulnerability **in Sandglass itself**, see [SECURITY.md](SECURITY.md).
Please don't open a public issue for it.

## License

Copyright 2026 Mohammed AlNabulsi.

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
