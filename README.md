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
  trace_parser.py    strace output -> file / probe / process / network / exit events
  compare.py         Events vs policy -> verdict, violations, report files
  policy.py          Loads + validates a policy (and the container baseline)
  baselines/
    python312_slim.yaml   System files python:3.12-slim reads at startup (reads only)
policies/
  notes_readonly.yaml
scripts/
  check_fixtures.py  Runs all fixtures in the sandbox and checks the expected verdicts
test_servers/        Fixture servers written for testing Sandglass. Not real targets.
  good_notes_server.py       read_note(name): reads only from allowed_notes/
  overreach_notes_server.py  Same tool, but also reads decoy_home/.fake_credentials
  listing_notes_server.py    Same tool, but also reads /etc/passwd and lists decoy_home/
  allowed_notes/             The only folder the notes servers are allowed to read
  decoy_home/                Fake "home" with an obviously fake credential file
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

Check all three at once (also what CI runs):

```bash
uv run python scripts/check_fixtures.py
```

With `--sandbox` the exit code is the verdict: `0` CLEAN, `1` VIOLATIONS,
`2` INCOMPLETE (including "the sandbox couldn't start").

### What the sandbox does

The client runs:

```
docker run -i --rm --network none --read-only --tmpfs /tmp --user 10001:10001 \
  -v <project>:/project:ro -v reports/trace/<run>:/trace:rw -w /project sandglass-sandbox \
  strace -f -tt -e trace=file,process,network -o /trace/trace.txt /opt/venv/bin/python <server>
```

- `--network none`: no network. Connection attempts still show up in the trace.
- `--read-only` + `--tmpfs /tmp`: the server can't modify the image; only `/tmp` is writable.
- `--user 10001:10001`: never root in the container.
- No `--cap-add SYS_PTRACE`: strace only traces its own child process, which
  Docker's default seccomp profile already allows.
- strace writes to a file (`-o`), never stderr, so it can't mix with MCP traffic.

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
| `stat` / `access` / `readlink` (looking, not reading) | listed under "probes", grouped by path with a count per syscall; informational |
| Any network attempt, even a failed one | VIOLATION |
| Any exec besides the server's own launch | VIOLATION (same failure rules as files) |

The verdict is **INCOMPLETE**, and never clean, if the server didn't start, the MCP
session failed, no tool was exercised, or the trace is missing or has no
`+++ exited` line for the server (a truncated trace).

## Tests

```bash
uv run pytest
```

## Known limitations

- **The whole project is mounted read-only into the container**, so a server
  can read `sandglass/`, `policies/` and the other fixtures. That is acceptable for
  our own fixtures. For real packages, only the package itself should be mounted
  (planned for v0.4).
- **Paths are compared as text.** strace shows the path the server asked for, not
  where a symlink leads. The project mount is read-only and the container
  filesystem is read-only apart from `/tmp`, so a server can't plant new
  symlinks in allowed folders. But a symlink that already exists inside an
  allowed folder would not be followed.
- **The baseline is specific to `python:3.12-slim`.** Another base image or language
  runtime (e.g. Node.js) needs its own baseline.
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

## License

Copyright 2026 Mohammed AlNabulsi.

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
