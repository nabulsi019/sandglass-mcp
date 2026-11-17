# Policies

A policy says what a server may read, write, contact and run. This page
covers the policy format, the standard templates, and how Sandglass judges
what it recorded against a policy (verdicts, phases, coverage, durations).

- [Policy format](#policy-format)
- [Policy templates](#policy-templates)
- [How behaviour is judged](#how-behaviour-is-judged)

## Policy format

```yaml
name: notes_readonly
description: Notes server may only read .txt files from its notes folder.
filesystem:
  read_allow: [test_servers/allowed_notes]   # any other file read = violation
  write_allow: []                            # no writes
network:
  allow: false                               # no connections (attempts count)
  allow_domains: [api.example.com, "*.example.org"]   # optional; see "Network" in how-it-works.md
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
are used as-is. (A scan needs absolute paths: see
[usage.md](usage.md#scanning-a-published-package).)

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

**Normal runtime behaviour** (#142). Real servers' libraries do a few things
that are harmless, and these are not violations:

- **Opening `/dev/null` read-write** (`write_exact` in the baseline): output
  thrown away. That exact file only: `/dev/zero`, `/dev/mem` or anything else
  under `/dev` still counts.
- **Reading `/proc/sys/vm/overcommit_memory`**: glibc does this the first time
  it shrinks a thread's heap. Reading it only: writing anywhere in `/proc/sys`
  still counts, and other `/proc/sys` reads are up to the policy.
- **`bind()` to `127.0.0.1` or `::1` with port 0, on a socket that never
  listens or accepts**: urllib3 checking whether IPv6 works. A real port,
  another address, a `listen()` (even on that socket), and anything the
  socket connects to or sends still count. This rule is in `compare.py`
  (`_is_ipv6_probe_bind`), not the baseline file.
- **Running `/usr/bin/uname -p`** (`exec_exact` in the baseline): Python's
  `platform.processor()`. Only that path with exactly that argv; it is still
  listed under "Programs run", with the note "Python's platform module
  (baseline: python312_slim)", and everything it does is traced and judged.
  So "no other programs" in a policy means no programs besides the server
  and this one baseline run, which the report always shows. `uname -a`, or
  `uname` through a shell, is a violation.

`test_servers/runtime_noise_server.py` does all four (CLEAN) and
`runtime_neighbours_server.py` does the next step of each (VIOLATIONS).

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

v1 templates were corrected before release: read_deny [/home, /root] was added to no_network.v1 and listed_domains_only.v1 before v0.4 was tagged.

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
| `io_uring_setup`/`enter`/`register` that **failed** (`EPERM` from Sandglass's syscall filter; Node's libuv tries this at every startup) | listed under "attempted", verdict unchanged |
| `io_uring_*` that **succeeded** | **INCOMPLETE**: the kernel does io_uring's file opens and reads itself, so strace can't see them and the trace may be missing file access |
| `clone`/`clone3` with `CLONE_UNTRACED`, `ptrace`, `process_vm_readv`/`writev` (#84) | VIOLATION "tried to evade tracing", under any policy, even when refused; if it **succeeded**, also **INCOMPLETE** |
| The syscall filter's self-test missing, or not refused | **INCOMPLETE** |
| A file or stat call whose path strace **couldn't read** (shown as an address) | **INCOMPLETE**, from any process: it can't be judged, so it's never dropped |
| `stat` / `access` / `readlink` (looking, not reading) | listed under "probes", grouped by path with a count per syscall; informational |
| Any network attempt, even a failed one | VIOLATION |
| A successful connect to the local network sink | not counted itself; the sink records the domain |
| A domain asked of the sink that isn't in `network.allow_domains` | VIOLATION naming the domain |
| A connection to the sink with no readable domain (#136) | VIOLATION if no domain is allowed; **INCOMPLETE** if some are |
| Connections to the sink in the trace ≠ the sink's records (#136) | **INCOMPLETE** |
| Any exec besides the server's own launch | VIOLATION (same failure rules as files) |

The sink, the DNS recorder and the syscall filter are described in
[how-it-works.md](how-it-works.md).

**Phases.** Every reported event has a phase, and the Markdown report
groups violations under three headings:

- **Install**: `sandglass scan` only: the package's install, from its own
  trace (#16, see [Scanning a published package](usage.md#scanning-a-published-package)).
  Fixture runs install nothing, and their report says so.
- **Startup**: before the first tool call reached the server (imports, the
  server setting itself up).
- **Tool calls**: from the first tool call on. A server that only
  misbehaves when a tool is used shows up here, like all our fixtures.

(A deep scan adds a fourth, **observation**: see
[how-it-works.md](how-it-works.md#the-observation-window).)

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
recorded in the trace, since the server's stderr is discarded; and if it
looked for a program in PATH at startup that nothing ever found, "the server
needs a program the sandbox doesn't have: <name>", #148), the MCP
session failed, no tool was exercised, the trace is missing or has no
`+++ exited` line for the server (a truncated trace), the network sink didn't
start, the sink didn't report the isolation check as isolated, or the stdin relay didn't
start or ended before the client closed stdin (killed, crashed, or no exit
record: the server may have tampered with it), Sandglass's syscall filter
failed its self-test, an io_uring call or an attempt to evade tracing
succeeded (#84), the sink's records don't match the connections made to it
or one can't be attributed to a domain (#136), or strace couldn't read the path of
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
- **returned an error** (#143): the server answered with an error: a result
  with `isError` set (e.g. "not logged in"), or a JSON-RPC error response.
  Only these two MCP signals count; a result's text is never read, since a
  tool that worked can return text that mentions an error;
- **failed**: the call raised (e.g. the connection closed), got an
  unexpected result, or got no answer before the session ended;
- **timed out** (#140): no answer within 30 s; the server is then pinged, and
  if it still answers (anything, even an error), the next tool is called;
- **not called** (#140): the calls had stopped before this tool: the time
  budget (120 s for all calls; with `--deep`, 30 s per tool, #170) was used up, or the server didn't answer the
  ping after a timeout;
- **skipped**: no valid input could be built from its schema, or the session
  ended before the tool was reached.

A failing or timed-out call doesn't stop the run: the next tool is still
called. Coverage is reported, not judged; it doesn't change the verdict,
except that a run where no call completed (every call timed out or got no
answer) is INCOMPLETE. A CLEAN verdict only covers what ran, so check this
table: a tool that returned an error, failed, timed out, or was not called
or skipped may not have done what it would normally do.

So the verdict line says it too (#143), in the terminal, at the top of the
Markdown report and as `coverage_summary` in the JSON: any tool that didn't
run normally is counted next to the verdict, e.g. `CLEAN (but 6 of 9 tools
returned errors)` or `VIOLATIONS (and 1 of 4 tools timed out, 1 not
called)`. The verdict word and the exit code don't change.

**Durations** (#156). Every report records wall-clock time, measured on the
host: the total, and each phase: **download** (scans: download, archive and
hash checks), **install** (scans), **run** (the server's startup and tool
calls) and **analysis** (reading the traces, comparing, building the
report; writing the report itself isn't counted). A phase that didn't happen
is `null` in `report["durations"]`, never 0: a fixture run has no download or
install, and a scan stopped at the hash check has only a download. The
Markdown header and the terminal summary show one line, with the download's
size next to its time because that time depends on the network (#167), e.g.
`Duration: 21.4 s (download 3.1 s (9.5 MB), install 6.0, run 10.8, analysis 1.5)`
(whole MB from 10 MB, one decimal from 0.1 MB, KB below that, e.g. `(3 KB)`, #174), and the
Coverage table shows each call's time next to its status. Durations vary
from run to run and never affect the verdict or the exit code.

If the server is still running 1 s after the client closed its stdin (e.g.
a tool stuck in a thread), the stdin relay stops it, so the trace still ends
with the server's exit. The report then says so.
