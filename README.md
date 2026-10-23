# Sandglass

Sandglass is a security research tool for [Model Context Protocol](https://modelcontextprotocol.io)
servers. The goal: run an MCP server in isolation, exercise its tools, record
what it **actually does** (files, processes, network), and compare that with a
stated **policy**.

A server's tool description says what it *claims* to do. Sandglass checks what
it *really* does.

Repository: <https://github.com/nabulsi019/sandglass-mcp>. Formerly **MCP Guard**
(the `v0.2` tag predates the rename).

> **Status: v0.2 (first demo).** Servers run in a Docker sandbox under `strace`.
> Every file open, process exec and network attempt is recorded and compared
> with a policy, and a JSON + Markdown report is written.

## Layout

```
sandglass/
  client.py          Runs a server over stdio, calls each tool once; --sandbox adds tracing + report
  sandbox.py         Container paths and the `docker run ... strace ...` command
  launcher.py        Runs first in the container: hides the trace, starts the sink and relay, runs the server
  netsink.py         Local fake HTTP(S) proxy: records contacted domains, never connects anywhere
  stdin_relay.py     Passes the client's messages to the server; marks the first tool call in the trace
  trace_parser.py    strace output -> file / probe / process / network / exit events
  compare.py         Events vs policy -> verdict, violations, report files
  policy.py          Loads + validates a policy (and the container baseline)
  baselines/
    python312_slim.yaml   System files python:3.12-slim reads at startup (reads only)
    node_debian.yaml      Extra startup reads of Debian's Node.js, for .js servers (reads only)
policies/
  notes_readonly.yaml
scripts/
  check_fixtures.py  Runs all fixtures in the sandbox and checks the expected verdicts
test_servers/        Fixture servers written for testing Sandglass. Not real targets.
  good_notes_server.py       read_note(name): reads only from allowed_notes/
  overreach_notes_server.py  Same tool, but also reads decoy_home/.fake_credentials
  listing_notes_server.py    Same tool, but also reads /etc/passwd and lists decoy_home/
  tamper_trace_server.py     Same tool, but also tries to read, overwrite and delete its trace
  aws_credentials_server.py  Same tool, but also reads ~/.aws/credentials (the sandbox's decoy)
  shell_command_server.py    Same tool, but also runs `/bin/sh -c true`
  undeclared_domain_server.py  Same tool, but also sends a GET to undeclared.example (local sink only)
  good_notes_node_server.js  Node.js twin of good_notes_server (hand-written MCP, no npm packages)
  allowed_notes/             The only folder the notes servers are allowed to read
  decoy_home/                Fake "home" with an obviously fake credential file
sandbox/
  decoy_home/        Baked into the image as $HOME (/home/sandglass): fake .aws/credentials,
                     .ssh/id_rsa and .env, FAKE_ values only
tests/               Unit tests (no Docker needed)
reports/             Output: <server>_<timestamp>.json/.md, and trace/<run>/trace.txt
Dockerfile           The sandbox image
```

## Setup

Requires [uv](https://docs.astral.sh/uv/) and, for the sandbox, Docker
(OrbStack or Docker Desktop on macOS).

```bash
uv sync
docker build -t sandglass-sandbox .   # rebuild only when dependencies change
```

The image installs the project's locked dependencies (`uv.lock`) into
`/opt/venv` **inside the image**. Your macOS `.venv` is never mounted.

## Running a server in the sandbox

```bash
uv run sandglass test_servers/good_notes_server.py      --policy policies/notes_readonly.yaml --sandbox
uv run sandglass test_servers/overreach_notes_server.py --policy policies/notes_readonly.yaml --sandbox
uv run sandglass test_servers/listing_notes_server.py   --policy policies/notes_readonly.yaml --sandbox
```

`sandglass` is a console script for `python -m sandglass.client`; both work.

Expected verdicts:

| Fixture | Verdict | Violations |
|---|---|---|
| good_notes_server | CLEAN | 0 |
| overreach_notes_server | VIOLATIONS | 1: read of `decoy_home/.fake_credentials` |
| listing_notes_server | VIOLATIONS | 2: read of `/etc/passwd`, listing of `decoy_home/` |
| aws_credentials_server | VIOLATIONS | 1: read of `/home/sandglass/.aws/credentials` (the decoy) |
| shell_command_server | VIOLATIONS | 1: exec of `/bin/sh` |
| undeclared_domain_server | VIOLATIONS | 1: domain `undeclared.example` (recorded by the local sink) |
| good_notes_node_server.js | CLEAN | 0 (with the `node_debian` baseline) |
| tamper_trace_server | VIOLATIONS | 3: list `/proc/1/fd`, read and write `/proc/1/fd/2` (all blocked with EACCES) |

Every run must also show the isolation check failing (no route to the internet).

Check all of them at once (also what CI runs):

```bash
uv run python scripts/check_fixtures.py
```

With `--sandbox` the exit code is the verdict: `0` CLEAN, `1` VIOLATIONS,
`2` INCOMPLETE (including "the sandbox couldn't start").

### What the sandbox does

The client runs:

```
docker run -i --rm --network none --read-only --tmpfs /tmp --user 10001:10001 \
  -e HOME=/home/sandglass -v <project>:/project:ro --mount type=tmpfs,destination=/project/reports,tmpfs-mode=0555 \
  -w /project sandglass-sandbox \
  sh -c 'exec strace -f -tt -e trace=file,process,network,memfd_create,io_uring_setup,io_uring_enter,io_uring_register \
         --kill-on-exit -o /proc/self/fd/2 \
         /opt/venv/bin/python -S -c "<launcher.py>" <server> "<netsink.py>" "<stdin_relay.py>" 3>/dev/null'
```

- `--network none`: no network. Connection attempts still show up in the trace.
- `--read-only` + `--tmpfs /tmp`: the server can't modify the image; only `/tmp` is writable.
- `--user 10001:10001`: never root in the container.
- `-e HOME=/home/sandglass`: a **decoy home** baked into the image from
  `sandbox/decoy_home/`, with fake `.aws/credentials`, `.ssh/id_rsa` and `.env`
  (`FAKE_` values only). A server hunting for secrets finds these, and the
  read shows up in the report. Your real home folder is never mounted.
- No `--cap-add SYS_PTRACE`: strace only traces its own child process, which
  Docker's default seccomp profile already allows.
- **The server can't touch its own trace.** strace writes the trace to the
  container's stderr (never stdout, so it can't mix with MCP traffic), and the
  client saves it on the host as `reports/trace/<run>/trace.txt`. There is no
  trace file in the container, and `/project/reports` is hidden behind an
  empty read-only folder. A short launcher (`sandglass/sandbox.py`) gives the
  server a `/dev/null` stderr before any package code runs, and the strace
  binary is executable but not readable (Dockerfile), which stops the server
  from reopening strace's fds through `/proc/1/fd/`. Because of that, strace
  can't read the arguments of the very first exec; the report shows it as
  `<unreadable>`, and only the first exec counts as the server's launch.

### Network: a local sink, no route out

The container keeps `--network none`, so it has no route anywhere. To still
see *which domain* a server wanted, the launcher starts
`sandglass/netsink.py` on `127.0.0.1:18080` before the server and points
`HTTP_PROXY`/`HTTPS_PROXY` at it. The sink never connects anywhere. For each
request it records method, host and port, and answers locally (`200` for plain
HTTP, `403` for HTTPS `CONNECT`).

The sink records through the trace itself: it `stat()`s a path like
`/sandglass-netsink/GET/example.com/80`, which doesn't exist. So it needs no
log the server could tamper with. Only the process that marks itself ready
first counts as the sink, and the launcher waits for that before any server
code runs. A server forging those stats from its own process just produces
probes. The report's **Network** section lists every domain as allowed or
not.

At startup the sink also tries to `connect()` to `1.1.1.1:443` (the
**isolation check**). It must fail. If it ever succeeds, or the sink never
starts, the verdict is INCOMPLETE.

Limitation: a server that ignores the proxy variables and resolves names
itself shows up only as a failed `connect()` (a violation), without the
domain name.

### Node.js servers

A `.js` server runs with Debian's `node` (installed in the image, no npm).
The launcher still runs first (trace hidden, sink started), then `exec`s
`/usr/bin/node <server.js>` in the same process. That one exec counts as part
of the launch for `.js` servers only; any other exec is still a violation.

### Without `--sandbox`

```bash
uv run sandglass test_servers/good_notes_server.py --policy policies/notes_readonly.yaml
```

Runs the server directly on your machine with no tracing and no report. Useful
for checking a server works at all. (The server path on the command line is
relative to your current directory, like any CLI argument.)

## Policy format

```yaml
name: notes_readonly
description: Notes server may only read .txt files from its notes folder.
filesystem:
  read_allow: [test_servers/allowed_notes]   # any other file read = violation
  write_allow: []                            # no writes
network:
  allow: false                               # no connections (attempts count)
  allow_domains: [api.example.com, "*.example.org"]   # optional; see "Network" below
process:
  exec_allow: []                             # no programs besides the server itself
runtime_allow:                               # READS only, excluded from violations
  - "{python_base}"
  - "{venv}"
  - "{server_script}"
  - "={server_dir}"                          # "=": exact directory, listing only
```

**Path resolution:** relative paths in a policy are resolved against the
**project root**, **not the current working directory**: the folder that
contains `sandglass/` on the host, or `/project` in the sandbox. Absolute paths
are used as-is.

**Placeholders** are filled in at load time, with container paths in `--sandbox` mode:

| Placeholder | Host | Sandbox |
|---|---|---|
| `{python_base}` | `sys.base_prefix` | `/usr/local` |
| `{venv}` | `sys.prefix` | `/opt/venv` |
| `{server_script}` | the server file | `/project/<path to server>` |
| `{server_dir}` | its folder | `/project/<folder>` |
| `{multiarch}` | n/a | asked from Python inside the image: `aarch64-linux-gnu` (Apple chips), `x86_64-linux-gnu` (CI) |

**`runtime_allow`** lists what the interpreter and server need just to start:
the Python installation, the installed packages and the server's own source.
Python opens hundreds of these during imports. Entries are prefix matches,
except entries starting with `=`, which match **exactly that directory and only
for directory listings**. `={server_dir}` exists because Python's import
system lists the server's folder (`sys.path[0]`). A prefix entry there would
also cover `test_servers/decoy_home/` and hide the very thing we test for.

**Container baseline:** `sandglass/baselines/python312_slim.yaml` holds system files
the image reads at startup (dynamic linker cache, libc and friends under
`/lib/{multiarch}`, locale data, `/etc/localtime`, OpenSSL config, cgroup CPU
quota, `/dev/null`). It's loaded automatically with `--sandbox`, and every
report names it.

**Reads only.** `runtime_allow` and the baseline allow reads and listings,
**never writes**. Only `write_allow` permits writes, so a server rewriting a
library in `/opt/venv` or `/lib` is a violation.

## How behaviour is judged

| Event | Outside the allow-lists... |
|---|---|
| File read / listing / write that **succeeded** | VIOLATION |
| File open that failed with `EACCES`/`EPERM` (exists, access blocked) | VIOLATION |
| File open that failed otherwise (e.g. `ENOENT`) | listed under "attempted", verdict unchanged |
| `memfd_create` (a file that lives only in memory; code in it can run without touching disk) | recorded as a write to `memfd:<name>`, so the same rules as a file write: VIOLATION if it succeeded |
| `io_uring_setup`/`enter`/`register` that **failed** (e.g. `EPERM` from Docker's seccomp profile; Node's libuv tries this at every startup) | listed under "attempted", verdict unchanged |
| `io_uring_*` that **succeeded** | **INCOMPLETE**: the kernel does io_uring's file opens and reads itself, so strace can't see them and the trace may be missing file access |
| `stat` / `access` / `readlink` (looking, not reading) | listed under "probes", grouped by path with a count per syscall; informational |
| Any network attempt, even a failed one | VIOLATION |
| A successful connect to the local network sink | not counted itself; the sink records the domain |
| A domain asked of the sink that isn't in `network.allow_domains` | VIOLATION naming the domain |
| Any exec besides the server's own launch | VIOLATION (same failure rules as files) |

**Phases.** Every reported event has a phase, and the Markdown report
groups violations under three headings:

- **Install**: not captured yet. Nothing is installed at run time (see #16),
  so this section says so.
- **Startup**: before the first tool call reached the server (imports, the
  server setting itself up).
- **Tool calls**: from the first tool call on. A server that only
  misbehaves when a tool is used shows up here, like all our fixtures.

The boundary comes from the trace itself, not from a clock (#91). The
launcher starts a small **stdin relay** (`sandglass/stdin_relay.py`) as its
own process. It passes the client's messages to the server unchanged, and
just before it passes on the first `tools/call` request it `stat()`s
`/sandglass-phase/tool-call`. Events before that line in the trace are
startup; events after it are tool calls. Only the relay's marker counts: the
relay is the first process to stat `/sandglass-phase/ready`, before any server
code runs, so the server can't fake the boundary. If the marker is missing
although tools were called, the phase is **unknown** (with the reason in the
report), never guessed.

The verdict is **INCOMPLETE**, and never clean, if the server didn't start, the MCP
session failed, no tool was exercised, the trace is missing or has no
`+++ exited` line for the server (a truncated trace), the network sink didn't
start, the isolation check reached the internet, or the stdin relay didn't
start or ended before the client closed stdin (killed, crashed, or no exit
record: the server may have tampered with it), or an io_uring call succeeded
(Docker 25+ blocks io_uring by default; see #84 for a seccomp profile that
blocks it whatever the Docker version).

## Tests

```bash
uv run pytest
```

## Related work

Other tools look at the same problem from different angles. The descriptions
below are from each project's own paper or documentation.

- **mcp-sec-audit**: [*Auditing MCP Servers for Over-Privileged Tool
  Capabilities*](https://arxiv.org/abs/2603.21641) (Huang, Huang and Milani Fard).
  It combines static pattern matching on Python MCP servers and their metadata
  with optional dynamic fuzzing in Docker, monitored with eBPF, and reports a
  weighted risk score with mitigation advice. The paper notes the eBPF monitor
  needs privileged containers. *How Sandglass differs:* no risk score and no
  static analysis. Sandglass compares observed behaviour against an explicit
  policy, and its sandbox runs unprivileged (non-root, no `--cap-add`, no
  `--privileged`, `--network none`), with strace inside the container.
- **SandScope** ([repository](https://github.com/Wapiti08/SandScope), paper
  [arXiv:2601.01241](https://arxiv.org/abs/2601.01241), first published as
  MCP-SandboxScan). It runs WASI-compatible tools in a WebAssembly sandbox,
  or drives unmodified MCP servers over stdio. It records execution and MCP
  protocol evidence, and looks for source-to-sink flows: seeded canary values
  (environment, files, tool inputs) showing up in output the LLM reads. Its
  docs say native servers need extra OS- or VM-level isolation. *How Sandglass
  differs:* Sandglass doesn't track data flow. It records every file, process
  and network action of an unmodified server inside a container, and checks
  each one against what the policy allows.
- **OpenSSF Package Analysis** ([announcement](https://security.googleblog.com/2022/04/the-package-analysis-project-scalable.html),
  [repository](https://github.com/ossf/package-analysis)). It dynamically
  analyses packages uploaded to popular open-source registries, catalogues
  the results in a public BigQuery table, and is aimed at catching malicious
  packages, e.g. ones that act at install time. *How Sandglass differs:* it
  targets one MCP server a team is deciding whether to approve. It exercises
  the server's tools over MCP, and judges the result against that team's
  policy instead of looking for signs of malware across a whole registry.

## Known limitations

- **The server's own stderr is discarded in `--sandbox` mode** (it would share
  a stream with the trace). To see a server's tracebacks, run it without
  `--sandbox`.

- **The whole project is mounted read-only into the container**, so a server
  can read `sandglass/`, `policies/` and the other fixtures. That is acceptable for
  our own fixtures. For real packages, only the package itself should be mounted
  (planned for v0.4).
- **Paths are compared as text.** strace shows the path the server asked for, not
  where a symlink leads. The project mount is read-only and the container
  filesystem is read-only apart from `/tmp`, so a server can't plant new
  symlinks in allowed folders. But a symlink that already exists inside an
  allowed folder would not be followed.
- **Baselines are specific to the image.** `python312_slim` covers
  `python:3.12-slim`; `node_debian` covers Debian's `nodejs` package in the same
  image (`.js` servers get both, since the launcher is Python). Another base image
  or runtime needs its own baseline.
- **Only one call per tool, with `"hello"` as input.** Behaviour behind other
  inputs isn't exercised yet.

## Safety rules

1. **Only run servers you wrote or have explicit permission to test.** The
   sandbox reduces risk, but it is a container, not a VM. Treat any server as
   untrusted code.
2. **Only use fake credentials.** Decoys like `test_servers/decoy_home/.fake_credentials`
   must contain obviously fake values (e.g. `FAKE_KEY_FOR_TESTING`).
3. **Never put real secrets anywhere a tested server can reach**, including the
   project folder (it is mounted into the container) and environment variables.
4. **Disclose real findings privately.** If you find a real server misbehaving,
   report it privately to its maintainers (security contact or private advisory)
   and give them time to fix it before you publish anything.

To report a vulnerability **in Sandglass itself**, see [SECURITY.md](SECURITY.md).
Please don't open a public issue for it.

## License

Copyright 2026 Mohammed AlNabulsi.

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
