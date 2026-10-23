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
  inputs.py          Builds one valid tool input from a tool's JSON schema
  scan.py            `sandglass scan`: package spec, download on the host, install in the sandbox
  baselines/
    python312_slim.yaml   System files python:3.12-slim-trixie reads at startup (reads only)
    node_debian.yaml      Extra startup reads of Debian's Node.js, for .js servers (reads only)
    install.yaml          What pip and npm themselves do during a scan's install phase
policies/
  notes_readonly.yaml
  templates/         Standard, versioned policy templates to copy (see "Policy templates")
scripts/
  check_fixtures.py  Runs all fixtures in the sandbox and checks the expected verdicts
  build_test_packages.py  Builds test_packages/ into a local test registry (test_packages/dist/)
test_packages/       Packages written for testing `sandglass scan`. Never published.
  pypi/sandglass-test-notes/  Notes server as a Python wheel (console script)
  pypi/sandglass-test-peek/   Same, but also tries to read /project/guard and /project/CLAUDE.md
  npm/sandglass-test-notes/   Notes server as an npm tarball (bin)
  npm/sandglass-test-postinstall/  Clean server whose postinstall script reads ~/.aws/credentials
  pypi/sandglass-test-tampered/    Clean server whose (test) registry publishes a wrong hash
test_servers/        Fixture servers written for testing Sandglass. Not real targets.
  good_notes_server.py       read_note(name): reads only from allowed_notes/
  overreach_notes_server.py  Same tool, but also reads decoy_home/.fake_credentials
  listing_notes_server.py    Same tool, but also reads /etc/passwd and lists decoy_home/
  tamper_trace_server.py     Same tool, but also tries to read, overwrite and delete its trace
  aws_credentials_server.py  Same tool, but also reads ~/.aws/credentials (the sandbox's decoy)
  symlink_escape_server.py   Same tool, but reads ~/.aws/credentials through a symlink it makes in /tmp
  shell_command_server.py    Same tool, but also runs `/bin/sh -c true`
  undeclared_domain_server.py  Same tool, but also sends a GET to undeclared.example (local sink only)
  good_notes_node_server.js  Node.js twin of good_notes_server (hand-written MCP, no npm packages)
  missing_api_key_server.py  Exits at startup because its (fake) NOTES_API_KEY isn't set
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
| missing_api_key_server | INCOMPLETE | 0; reason: exited during startup, `RuntimeError: NOTES_API_KEY is not set` |
| aws_credentials_server under `policies/templates/no_network.v1.yaml` | VIOLATIONS | 1: read of `/home/sandglass/.aws/credentials` (`read_deny: /home`, #121) |
| symlink_escape_server under `policies/templates/no_network.v1.yaml` | VIOLATIONS | 2, both on `/home/sandglass/.aws/credentials`: the symlink to it made in `/tmp` (a link counts as a read of its target), and the read through that link (judged by the file really opened, #122) |

Every run must also show the sink reporting the isolation check as isolated (no route to the internet).

Check all of them at once (also what CI runs):

```bash
uv run python scripts/check_fixtures.py
```

With `--sandbox` the exit code is the verdict: `0` CLEAN, `1` VIOLATIONS,
`2` INCOMPLETE (including "the sandbox couldn't start").

## Scanning a published package

```bash
uv run sandglass scan pypi:<package>@<exact-version> --policy <policy.yaml>
uv run sandglass scan npm:<package>@<exact-version>  --policy <policy.yaml>
```

**Only scan packages you may test** (see Safety rules). The version must be
exact: `latest`, ranges (`^1.2.3`, `~1.2`, `>=1`, `1.*`, `1.x`) and local
versions are refused with a usage error, so a report always names exactly
what was scanned. Exit code: `0` CLEAN, `1` VIOLATIONS, `2` INCOMPLETE or a
usage error.

The policy's `read_allow`, `write_allow` and `read_deny` paths must be
absolute (or placeholders like `{venv}`) for a scan (#123): a relative path
means "inside the project", and a scan doesn't mount the project. A relative
path stops the scan before anything is downloaded, with exit code `2` and
`policy path '<path>' is relative; scans have no project folder, use an
absolute path`. Normal runs still accept relative paths.

What happens (`sandglass/scan.py`):

1. **Download, on your machine**, into a temporary folder. No package code
   runs here:
   - PyPI: `pip download`, **wheels only** (`--only-binary=:all:`), for the
     container's platform (Linux, CPython 3.12, its CPU), so it works from a
     Mac too. Building an sdist would run its `setup.py` on your machine, so a
     package with no wheel can't be scanned (INCOMPLETE, with pip's error).
   - npm: `npm install --ignore-scripts` in a scratch folder fills an npm
     cache with the package and its dependencies (needs `npm` on your machine).

   **Package hash** (#21): every downloaded file's sha256 goes in the report,
   and the package's own file is checked against the value its registry
   publishes: for PyPI, the wheel's sha256 vs `digests.sha256` in
   `https://pypi.org/pypi/<name>/<version>/json`; for npm, the tarball's
   `sha512-…` integrity vs `dist.integrity` in
   `https://registry.npmjs.org/<name>/<version>` (or `dist.shasum` for old
   packages). A mismatch, or a registry that can't be reached, stops the scan
   **before the install**: INCOMPLETE, with both values in the reason.
2. **Install, inside the sandbox, under strace** (#16), in a separate
   container: same hardening (`--network none`, read-only, non-root, no
   capabilities), offline from the downloaded files, into a fresh Docker volume
   at `/package`. That volume and `/tmp` are the only writable places. The
   install never gets network access. This is where npm runs a package's
   `preinstall`/`postinstall` scripts, so misbehaviour at install time shows up
   here. strace writes the install trace to the container's stderr (saved as
   `install-trace.txt` next to the server's trace); the traced shell's first
   act is `exec 2>&1`, so pip, npm and every install script write to the
   install log (`install-log.txt`) and never hold the trace stream. strace
   runs with `-y` here, so pip's and npm's folder-relative calls get full paths.

   The install is judged against the policy plus an **install baseline**
   (`sandglass/baselines/install.yaml`): what pip and npm themselves read (the
   image's Python and Node.js files, `/download`, `/package`, `/tmp`, a few
   `/etc` and `/proc` files), writes only under `/package` and `/tmp`, the
   programs they run (`sh`, `cp`, `env`, `node`, `npm`, Python, `uname`: npm
   runs every install script through `sh` and `node`), and netlink sockets
   (Node.js listing network interfaces; they can't reach another host).
   Anything else is judged like the server's behaviour: reading
   `~/.aws/credentials`, running another program or any network attempt is a
   violation in the **install** phase. A new symlink or hard link counts as a
   read of where it points, so a link in `/tmp` to a secret is caught. A
   failed or timed-out install is INCOMPLETE (with the end of its log) and the
   server isn't run; its trace is still judged.
3. **Run** the package's server from that volume, mounted **read-only**, under
   strace, with the same hardening and trace protection as a fixture. That
   volume is the container's **only** mount (#20): the Sandglass project is
   not mounted, so the package can't read Sandglass's code, policies or
   reports (`/project/...` gives `ENOENT`). The working directory is
   `/package`. The server is the package's console script (PyPI) or `bin`
   (npm); `--entry NAME` picks one if there are several.
   Reads inside `/package` (the package and its dependencies) are allowed
   automatically, like `{venv}` for fixtures; writes there are not. Use
   absolute paths in a scan's policy: relative ones point into `/project`,
   which a scan doesn't have.
4. **Report**, with a "Package" section: the spec, where it came from, the
   files downloaded (with sha256), the hash check, the install and the entry
   point. If a step fails (download, hash, install, no entry point), the
   report is still written, INCOMPLETE, with the reason.

The volume and the temporary folder are deleted afterwards.

**Our own test packages.** `--registry-dir test_packages/dist` uses a local
folder instead of PyPI/npm, with no network at all. `check_fixtures.py`
builds it (`scripts/build_test_packages.py`) and scans:

| Package | Verdict |
|---|---|
| `pypi:sandglass-test-notes@1.0.0` | CLEAN |
| `npm:sandglass-test-notes@1.0.0` | CLEAN |
| `pypi:sandglass-test-peek@1.0.0` | CLEAN; its reads of `/project/guard` and `/project/CLAUDE.md` are listed as attempted (`ENOENT`): the project isn't mounted |
| `npm:sandglass-test-postinstall@1.0.0` | VIOLATIONS: 1, its `postinstall` script reads `/home/sandglass/.aws/credentials` (the decoy), in the **install** phase; the server itself is clean |
| `pypi:sandglass-test-tampered@1.0.0` | INCOMPLETE: `package hash mismatch` (its test registry publishes a wrong sha256); never installed or run |

The local test registry also holds registry-style metadata
(`test_packages/dist/<pypi|npm>-meta/<name>/<version>.json`) with the
published hashes, so the hash check runs offline too.

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

The sink and the stdin relay run as the same user as the server, so an event
in a helper's process isn't proof the helper's own code did it. Only an exact
list of each helper's known events is skipped (its own launch, its markers,
and for the sink its proxy socket and the isolation check). Anything else
from those processes is judged like the server's (#99).

At startup the sink also tries to `connect()` to `1.1.1.1:443` (the
**isolation check**). The sink itself decides the outcome once the connect
has finished, and reports it in the trace by `stat()`ing
`/sandglass-isolation/<isolated|not-isolated>/<outcome>` before it marks itself
ready (#100). The connect's first errno can't be trusted: with a timeout it's
`EINPROGRESS` even when the connect then succeeds. Only `ENETUNREACH` (no route
at all, which is what `--network none` gives) counts as isolated. If the sink
reports anything else (connected, a timeout, a refusal...), reports nothing, or
never starts, the verdict is INCOMPLETE.

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

**`read_deny`** (optional, #121) lists paths that may never be read or
listed, even if `read_allow`, `runtime_allow` or the baseline would allow
them: **deny wins**. Same path rules as `read_allow` (prefix match; relative
paths from the project root). The "read anywhere" templates use it to keep
home folders out:

```yaml
filesystem:
  read_allow: [/]              # anywhere...
  read_deny: [/home, /root]    # ...except home folders
  write_allow: [/tmp]
```

A probe (`stat`) under `read_deny` is always listed under "probes".

## Policy templates

Instead of writing a policy from scratch, copy one of the standard templates
in `policies/templates/` (#112) and edit the lines marked `EDIT`:

| Template | Files | Network | Programs |
|---|---|---|---|
| `policies/templates/read_only_folder.v1.yaml` | read only inside one folder (`/data`, EDIT); no writes | none | none |
| `policies/templates/no_network.v1.yaml` | read anywhere except `/home` and `/root`; write only `/tmp` | none, not even through the sink | none |
| `policies/templates/listed_domains_only.v1.yaml` | read anywhere except `/home` and `/root`; write only `/tmp` | only the listed domains (`api.example.com`, EDIT), through the local sink | none |

All three have the same `runtime_allow` as `notes_readonly.yaml`, so they work
for `.py` and `.js` servers without other changes. "Read anywhere" stops at
home folders (`read_deny: [/home, /root]`, #121), so reading the decoy home's
fake credentials is a violation. Everything else is readable: if it matters
which files a server reads, start from `read_only_folder`.

**Versions.** The version is in the file name and in `name` (`no_network_v1`),
so every report says exactly which template it was judged against. A
template is never edited in place: a change becomes a new file
(`no_network.v2.yaml`) and the old one stays, so old reports stay
reproducible. Give your edited copy its own name.

```bash
cp policies/templates/read_only_folder.v1.yaml policies/my_notes_server.yaml   # then edit it
```

## How behaviour is judged

| Event | Outside the allow-lists... |
|---|---|
| File read / listing / write that **succeeded** | VIOLATION |
| File open that failed with `EACCES`/`EPERM` (exists, access blocked) | VIOLATION |
| File open that failed otherwise (e.g. `ENOENT`) | listed under "attempted", verdict unchanged |
| `memfd_create` (a file that lives only in memory; code in it can run without touching disk) | recorded as a write to `memfd:<name>`, so the same rules as a file write: VIOLATION if it succeeded |
| `io_uring_setup`/`enter`/`register` that **failed** (e.g. `EPERM` from Docker's seccomp profile; Node's libuv tries this at every startup) | listed under "attempted", verdict unchanged |
| `io_uring_*` that **succeeded** | **INCOMPLETE**: the kernel does io_uring's file opens and reads itself, so strace can't see them and the trace may be missing file access |
| A file or stat call whose path strace **couldn't read** (shown as an address) | **INCOMPLETE**, from any process: it can't be judged, so it's never dropped |
| `stat` / `access` / `readlink` (looking, not reading) | listed under "probes", grouped by path with a count per syscall; informational |
| Any network attempt, even a failed one | VIOLATION |
| A successful connect to the local network sink | not counted itself; the sink records the domain |
| A domain asked of the sink that isn't in `network.allow_domains` | VIOLATION naming the domain |
| Any exec besides the server's own launch | VIOLATION (same failure rules as files) |

**Phases.** Every reported event has a phase, and the Markdown report
groups violations under three headings:

- **Install**: `sandglass scan` only: the package's install, from its own
  trace (#16, see "Scanning a published package"). Fixture runs install
  nothing, and their report says so.
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

The verdict is **INCOMPLETE**, and never clean, if the server didn't start or
exited during startup (e.g. it needs an API key or a real account: the report
gives its exit status and, for Python servers, the error message the launcher
recorded in the trace, since the server's stderr is discarded), the MCP
session failed, no tool was exercised, the trace is missing or has no
`+++ exited` line for the server (a truncated trace), the network sink didn't
start, the sink didn't report the isolation check as isolated, or the stdin relay didn't
start or ended before the client closed stdin (killed, crashed, or no exit
record: the server may have tampered with it), an io_uring call succeeded
(Docker 25+ blocks io_uring by default; see #84 for a seccomp profile that
blocks it whatever the Docker version), or strace couldn't read the path of
a file or stat call (it then prints a memory address instead; such an event
is never dropped, because we can't tell what was touched).

**Programs run and attempts** (#120). The report's "Programs run" section
lists every program that was started successfully (pid, time, full argv),
per phase, whether it was allowed or not; it shows what ran and never
changes the verdict. The Markdown "Attempted" list is grouped: one entry
per (category, path, errno, phase) with a count, the first time and the
first evidence line (the JSON keeps every event). A run of failed execs
from one pid with the same argv and the same program name (`npm` trying
each folder in `PATH`) is shown as one entry, "looked for npm in PATH
(N places)", plus where it was found.

**Coverage** (#23). The report lists every tool the server offered, with
totals:

- **ran**: the call returned a normal result;
- **failed**: the call returned an MCP error (e.g. "not logged in"), raised,
  took longer than 30 s, or got no answer before the session ended;
- **skipped**: no valid input could be built from its schema, or the session
  ended before the tool was reached.

A failing call doesn't stop the run: the next tool is still called.
Coverage is reported, not judged; it doesn't change the verdict. A CLEAN
verdict only covers what ran, so check this table: a tool that failed or was
skipped did nothing we could observe.

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

- **A server can tell it's being traced** (#82). Under strace, a process's
  `/proc/self/status` shows a non-zero `TracerPid`, so a server (or an install
  script) can notice it's being watched and behave well only then. Sandglass
  doesn't hide strace and doesn't try to: hiding it reliably would take tricks
  a determined package could still detect. So a **CLEAN verdict means
  "nothing outside the policy was seen while traced"**, not "this package
  never does anything else". Every report says so in one line (`tracing_note`
  in the JSON). A read of `/proc/self/status` isn't flagged by itself: many
  runtimes read it for ordinary reasons, and the policy decides, like for any
  other file.

- **The server's own stderr is discarded in `--sandbox` mode, to protect the
  trace** (#47). strace writes the trace to the container's stderr, so the
  launcher points the server's stderr at `/dev/null` before any server code
  runs; otherwise the server could write fake lines into its own trace. To see
  a server's tracebacks, run it without `--sandbox`.

- **PyPI scans are wheels only**: a package published only as an sdist gives
  INCOMPLETE, because building an sdist would run the package's own code on
  the host, outside the sandbox.

- **Fixture runs mount the whole project read-only**, so a fixture server
  can read `sandglass/`, `policies/` and the other fixtures. That is acceptable for
  our own fixtures. `sandglass scan` mounts **only the installed package**
  (#20): the project isn't in its container at all.
- **Trace size** (#83). The trace is read one line at a time and at most
  256 MiB of it (`MAX_TRACE_BYTES` in `sandglass/trace_parser.py`); a bigger
  trace makes the run INCOMPLETE, since the unread part could hold anything.
  The parsed events are still kept in memory (bounded by that limit), and the
  trace file on disk isn't capped: Docker writes it straight to the file.
- **Symlinks and links** (#122). A successful open is judged by both the
  path the server asked for and the file it really opened (strace `-y`
  prints it after the returned fd): a violation if either one isn't
  allowed, and the report shows both ("requested X, opened Y"). Making a
  symlink or hard link, in any phase, counts as a read of where it points.
  So reading `~/.aws/credentials` through a link in `/tmp` is caught
  (`test_servers/symlink_escape_server.py`). Opening `/proc/self/...` is
  the exception: strace shows it as `/proc/<pid>/...`, the process's own
  folder, so that path is judged as asked for. Failed opens and probes
  (`stat`) are still judged by the requested path only: strace can't show
  where they would have led.
- **Baselines are specific to the image.** `python312_slim` covers
  `python:3.12-slim-trixie`; `node_debian` covers Debian's `nodejs` package in the same
  image (`.js` servers get both, since the launcher is Python). Another base image
  or runtime needs its own baseline. The Dockerfile pins the Debian release
  (13, "trixie": strace 6.13, Node.js 20), so a rebuild can't silently switch
  release; moving to a new one means re-checking the baselines and the trace parser.
- **Only one call per tool, with one example input.** The input is built
  from the tool's JSON schema (`sandglass/inputs.py`, #22): the schema's own
  `const`/`enum`/`default`/`examples` first, otherwise a simple value per type
  (`"hello"` for strings, `1` for numbers, inside any min/max), nested objects
  and arrays filled in, local `$ref`s followed. A tool whose schema we can't
  satisfy (e.g. a string `pattern`) is skipped, not guessed. Behaviour behind
  other inputs isn't exercised.

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
