# How Sandglass works

How a run is isolated and recorded: the sandbox, the launcher, the syscall
filter, the network sink and the DNS recorder, the observation window, the
server's environment, and where everything lives in the repository. How to
run it is in [usage.md](usage.md); how what it records is judged is in
[policies.md](policies.md).

- [Layout](#layout)
- [What the sandbox does](#what-the-sandbox-does)
- [Sandglass's syscall filter](#sandglasss-syscall-filter)
- [The server's environment](#the-servers-environment)
- [Network: a local sink, no route out](#network-a-local-sink-no-route-out)
- [The observation window](#the-observation-window)
- [Node.js servers](#nodejs-servers)
- [Related work](#related-work)

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
  inputs.py          Builds one valid tool input from a tool's JSON schema and descriptions
  scan.py            `sandglass scan`: package spec, download on the host, install in the sandbox
  baselines/
    python312_slim.yaml   System files python:3.12-slim-trixie reads at startup (reads only)
    node_debian.yaml      Extra startup reads of Debian's Node.js, for .js servers (reads only)
    install.yaml          What pip and npm themselves do during a scan's install phase
policies/
  notes_readonly.yaml
  templates/         Standard, versioned policy templates to copy (see docs/policies.md)
scripts/
  check_fixtures.py  Runs all fixtures in the sandbox and checks the expected verdicts
  build_test_packages.py  Builds test_packages/ into a local test registry (test_packages/dist/)
test_packages/       Packages written for testing `sandglass scan`. Never published.
  pypi/sandglass-test-notes/  Notes server as a Python wheel (console script)
  pypi/sandglass-test-peek/   Same, but also tries to read /project/guard and /project/CLAUDE.md
  npm/sandglass-test-notes/   Notes server as an npm tarball (bin)
  npm/sandglass-test-postinstall/  Clean server whose postinstall script reads ~/.aws/credentials
  pypi/sandglass-test-tampered/    Clean server whose (test) registry publishes a wrong hash
  (generated, no source folder)    Hostile archives (#133): sandglass-test-traversal (npm, "../" and
                                   absolute members), sandglass-test-symlink (wheel, symlink out of its
                                   folder), sandglass-test-bomb (wheel, 520 MB of zeros once unpacked)
test_servers/        Fixture servers written for testing Sandglass. Not real targets.
  good_notes_server.py       read_note(name): reads only from allowed_notes/
  overreach_notes_server.py  Same tool, but also reads decoy_home/.fake_credentials
  listing_notes_server.py    Same tool, but also reads /etc/passwd and lists decoy_home/
  tamper_trace_server.py     Same tool, but also tries to read, overwrite and delete its trace
  aws_credentials_server.py  Same tool, but also reads ~/.aws/credentials (the sandbox's decoy)
  symlink_escape_server.py   Same tool, but reads ~/.aws/credentials through a symlink it makes in /tmp
  proc_self_escape_server.py Same tool, but reads ~/.aws/credentials through /proc/self/root and /proc/self/fd
  untraced_clone_server.py   Same tool, but a clone(CLONE_UNTRACED) child (invisible to strace) reads ~/.aws/credentials
  ptrace_server.py           Same tool, but tries ptrace and process_vm_readv/writev on its parent
  iouring_node_server.js     Node twin that reads ~/.aws/credentials with io_uring enabled in libuv
  stall_sink_server.py       Same tool, but stalls one request to the sink to hide a second one behind it
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
docs/                These documents
Dockerfile           The sandbox image
```

## What the sandbox does

The client runs:

```
docker run -i --rm --network none --read-only --tmpfs /tmp --user 10001:10001 \
  -e HOME=/home/sandglass -v <project>:/project:ro --mount type=tmpfs,destination=/project/reports,tmpfs-mode=0555 \
  -w /project sandglass-sandbox \
  sh -c 'mkdir -m 0700 /tmp/work && cd /tmp/work &&
         unset OLDPWD GPG_KEY PYTHON_VERSION PYTHON_SHA256 &&
         exec strace -f -tt -y -e trace=file,process,network,memfd_create,io_uring_setup,io_uring_enter,io_uring_register,ptrace,process_vm_readv,process_vm_writev,pidfd_getfd,unshare,setns,userfaultfd \
         --kill-on-exit -o /proc/self/fd/2 \
         /opt/venv/bin/python -S /usr/local/lib/mcp-runtime/run.py "$@" 3>/dev/null' \
  launch <server> <python|node> "<site dir or empty>" [--server-arg values...]
```

(`--env` adds `-e NAME` for each name, without the value; see
[Server setup](usage.md#server-setup).)

The launcher (`sandglass/launcher.py`), the network sink (`netsink.py`) and
the stdin relay (`stdin_relay.py`) are copied into the image as
`/usr/local/lib/mcp-runtime/run.py`, `sink.py` and `relay.py` (#159) and
started by path, so no process's command line (which the server can read
in `/proc/<pid>/cmdline`) carries their source or the name Sandglass.
**Rebuild the image after changing them**: before every run the client
compares the image's copies with your checkout (sha256) and refuses a
stale image.

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

## Sandglass's syscall filter

(#84) strace sees every syscall a process makes, but a few syscalls let a
process act where strace can't see. Sandglass refuses those itself, with a
seccomp filter, instead of relying on whatever Docker version is installed:

| Syscall | Why it hides things | The filter returns |
|---|---|---|
| `io_uring_setup` / `enter` / `register` | the kernel opens and reads files for the process; no `openat` in the trace | `EPERM` |
| `clone` with `CLONE_UNTRACED` | a child strace can't follow: none of its actions are traced | `EPERM` |
| `clone3` | its flags are in memory the filter can't read (could hold `CLONE_UNTRACED`) | `ENOSYS`: glibc, Python and Node then use `clone` |
| `ptrace` | tracing another process (and making it act), or stopping strace | `EPERM` |
| `process_vm_readv` / `process_vm_writev` | reading or writing another process's memory, e.g. a Sandglass helper's | `EPERM` |
| `pidfd_getfd` (#155) | copying an open fd out of another process (e.g. strace's) | `EPERM` |
| `unshare` / `setns` (#155) | new namespaces (a user namespace gives root-like powers inside it), or joining another one | `EPERM` |
| `userfaultfd` (#155) | stalling the kernel mid-syscall: races against strace reading the arguments | `EPERM` |

Any syscall from another ABI (32-bit `int 0x80` on x86_64, x32) gets `EPERM`
too, since the numbers above wouldn't match there.

How: the launcher (`sandglass/launcher.py`), right after hiding the trace
stream and before the sink, the relay or any server code, installs the
filter on itself (`prctl(PR_SET_NO_NEW_PRIVS)`, then
`SECCOMP_MODE_FILTER`, a 24-instruction BPF program written in Python with
`ctypes`, for x86_64 and aarch64). A filter is inherited by every child and
survives `exec`, so it covers the server and everything it starts, but not
strace, the launcher's parent. Then it runs a **self-test**: it tries
`io_uring_setup` and a `CLONE_UNTRACED` clone itself. Both must fail with
`EPERM` in the trace, before the sink is ready; if either is missing or
went through, the run is **INCOMPLETE** ("Sandglass's syscall filter is not
active"), never CLEAN. On another CPU architecture the filter isn't
installed, so the self-test makes every run INCOMPLETE.

So Node.js servers work on any Docker version: libuv's io_uring attempts at
startup are refused and listed as attempted, never INCOMPLETE. Any attempt
to evade tracing (a `CLONE_UNTRACED` clone, `ptrace`, `process_vm_*`) by the
server is a **violation**, "tried to evade tracing", even when refused; one
that got through (no filter) also makes the run INCOMPLETE.
`check_fixtures.py` also runs three fixtures with Docker's own seccomp
profile turned off (`--security-opt seccomp=unconfined`, in the test script
only, never in `sandglass/`), the review's Docker 20.10 case: same verdicts.

**The install phase and the npm download container (#155)** get the same
filter. The launcher has a second mode, `--filter-then-exec PROGRAM ARG...`:
it installs the filter on itself, runs the same self-test, then execs the
program (an argument list, never a shell string). In the install container
it is the first program strace runs, and it execs the installer's shell, so
pip, npm and every install script are filtered (strace isn't). The install's
self-test must show both calls refused before the shell starts, otherwise
the scan is INCOMPLETE ("syscall filter not active during install"). During
the install a refused io_uring call is listed as attempted, and a refused
evasion is a violation ("install tried to evade tracing"). In the download
container (not traced) npm runs through it too. `check_fixtures.py` scans
npm:sandglass-test-notes (also through the download container) and
npm:sandglass-test-postinstall with Docker's seccomp profile off for every
container of the scan: CLEAN, VIOLATIONS (the postinstall's read of the
decoy credentials) and CLEAN, never INCOMPLETE because of npm's io_uring.

## The server's environment

(#146) A server sees exactly these environment variables (plus any `--env`
names you give, #144):

| Variable | Value | Where from |
|---|---|---|
| `PATH` | `/opt/venv/bin:/usr/local/bin:…` | the image |
| `LANG` | `C.UTF-8` | the base image (`python:3.12-slim`) |
| `PYTHONDONTWRITEBYTECODE` | `1` | the image (no `.pyc` writes in traces) |
| `HOSTNAME` | the container id | Docker |
| `HOME` | `/home/sandglass` | `docker run -e`: the decoy home |
| `PWD` | `/tmp/work` | `sh`, the work folder |
| `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` | `http://127.0.0.1:18080` | the launcher: the network sink (below) |

No variable name contains "Sandglass". The launcher's runtime and the
scanned package's site folder are passed to it as arguments, not variables:
for a Python server the launcher and the server are one process, and
`/proc/self/environ` would keep a variable even after it was deleted. uv's
build settings (`UV_*`) exist only while the image is built, and `sh`
unsets the base image's build metadata (`GPG_KEY`, `PYTHON_VERSION`,
`PYTHON_SHA256`) and `OLDPWD` before tracing starts.

What still shows (on purpose, or not worth hiding): `HOME=/home/sandglass`
(the decoy home is protected; renaming it is #159), and **a server can tell
an HTTP proxy is configured on localhost**: it can read the variables,
connect to the proxy or see its listener in `/proc/net/tcp`. Any port would
be as visible, so it stays 18080. Other ways to notice the sandbox are in
[limitations.md](limitations.md).

## Network: a local sink, no route out

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

**Every connection is accounted for** (#136). The sink reads all its
connections side by side, each with a 2-second deadline from the moment it
was accepted (trickling a byte at a time doesn't extend it), so one
unfinished request can't keep the next waiting. When the server exits, the
sink drains: every connection still open or still queued is read and
recorded before it stops. Each connection gets exactly one record; one whose
request names no readable domain is an **unidentified connection to the
sink**: a violation if the policy allows no network at all, INCOMPLETE ("a
request could not be attributed to a domain") if it allows some domains
(it might have been one of them, or not). And compare.py counts the
successful `connect()`s to the sink in the trace: if that number differs
from the sink's records, a request may be missing, so the run is INCOMPLETE.

The sink and the stdin relay run as the same user as the server, so an event
in a helper's process isn't proof the helper's own code did it. Only an exact
list of each helper's known events is skipped (its own launch, its markers,
and for the sink its proxy socket, the isolation check and its read of
/etc/resolv.conf before "ready"). Anything else
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

Also before it marks itself ready, the sink reads the container's
`/etc/resolv.conf` and records each nameserver the same way
(`/sandglass-resolver/nameserver/<address>`, then `/sandglass-resolver/done`;
`/sandglass-resolver/unreadable` if it can't read the file) (#141). Only the
sink's own read and markers before "ready" count; the report's Network
section lists the nameservers, or says they are unknown.

**Names looked up: the DNS recorder (#147).** A server that ignores the
proxy variables (Node's `fetch`, for one) looks names up itself. So the
container gets `--dns 127.0.0.1 --dns-search .` (still `--network none`:
127.0.0.1 is its own loopback), and before the sink the launcher starts
`sandglass/dnssink.py` (in the image as `/usr/local/lib/mcp-runtime/dns.py`,
by path, empty environment) on 127.0.0.1:53, UDP and TCP. It records every
query's type and name (`/sandglass-dns/<type>/<name>`, stat()ed like the
sink's markers, names lower-cased, anything outside `[a-z0-9._-]` escaped)
and **answers NXDOMAIN, never an address**. Only the first process to stat
`/sandglass-dns/ready` is trusted. The report lists the names in its Network
section, e.g. "`hidden-node.example` (tool-call): looked up (DNS: A, AAAA),
not contacted (answered NXDOMAIN)", and in the JSON as `dns_names`. A name
not in `network.allow_domains` is a violation, in the same entry as the
sink's requests for that domain. With some domains allowed, the lookup
steps to 127.0.0.1:53 aren't violations (the name is judged instead), like
a connect to the sink. **Fail closed:** the recorder never started (e.g. a
Docker that doesn't let a non-root user bind port 53 in the container: the
sandbox adds no `--sysctl` or capability for it), stopped before the server,
or recorded no name although lookups reached it: INCOMPLETE. The install
phase keeps Docker's resolver, so names looked up while installing are not
recorded.

**Network violations are grouped** (#141). One server request can take
dozens of steps (glibc asks the nscd socket, then each nameserver on port
53, again for every retry), so the summary and the Markdown show one entry
per:

- **domain** asked of the sink, with its count;
- **name lookups**: connects or sends to the nscd socket, or to port 53 at a
  nameserver from the container's resolv.conf (the DNS recorder). These steps
  don't contain the name, and lookups run side by side, so they're never
  matched one by one (#147): if the recorder recorded exactly one name in
  that phase, they join that domain's entry (e.g. `domain
  hidden-node.example ×5 (nscd socket (ENOENT) ×2, port 53 at 127.0.0.1 ×1,
  DNS lookup A ×1, DNS lookup AAAA ×1)`); with several names, one entry
  "name lookups for a.example, b.example"; with none, "name lookups: no name
  recorded";
- **direct DNS to `<address>:53`** for port 53 anywhere else: that bypasses
  the system resolver. If the nameservers are unknown, every port-53 address
  is its own entry, never merged into the lookups;
- any other network event per (syscall, family, address, port).

Files, programs and everything else stay one entry per event. The JSON
keeps every raw event in `violations` (and every request in `domains`);
`violation_groups` lists the entries, each with the indexes of its events.
**"violations: N" counts raw events**, as before, and the summary adds the
number of entries, e.g. `violations: 143 in 2 entries` for wikipedia-mcp
(13 requests for `en.wikipedia.org` and 130 lookup steps). The verdict and
the exit code don't depend on the grouping.

## The observation window

(#175, deep only.) A quick scan closes the session right after the last
call, so anything a server does a few seconds later (a background thread, a
timer) is never traced. After its last call, a deep scan sends one ordinary
MCP notification, `notifications/roots/list_changed` (servers ignore it; it
carries no Sandglass name), then keeps the session open and idle for
**60 s**, in both runs, sending nothing. If the server exits, the window
ends early. The stdin relay marks the trace just before passing that
notification on, and events after the marker are in the **observation**
phase, with their own sections in the Markdown; they are judged by exactly
the same rules, the label only says when it happened. Only the relay's own
marker counts: if a deep trace lacks it, those events are "unknown", never
guessed. The report gets `observation` (`seconds`, `ended_early`, `events`)
and an "Observation" line. This narrows the blind spot; it doesn't close it:
anything delayed past the window, or triggered by a date or an event, stays
unseen, and a hostile server can notice the notification and stay quiet.
(The MCP SDK now marks roots as deprecated, SEP-2577; the notification is
still valid.) A deep scan takes about 2 minutes longer. The rest of the deep
scan is in [usage.md](usage.md#deep-scan).

## Node.js servers

A `.js` server runs with Debian's `node` (installed in the image, no npm).
The launcher still runs first (trace hidden, syscall filter installed, sink started), then `exec`s
`/usr/bin/node <server.js>` in the same process. That one exec counts as part
of the launch for `.js` servers only; any other exec is still a violation.

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
