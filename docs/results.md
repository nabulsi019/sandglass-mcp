# Results

Last updated: 2026-11-17, version v0.4.2

Every number Sandglass's documents quote, with where it comes from and when
it was measured. v0.4.2 is not tagged yet: the numbers below are from `main`
at `c68c748` (2026-11-12; this page's PR changes documents only), and from
the two real-scan documents it links to. Anything not measured is marked
"not measured yet".

**How to read these numbers:**
- **VIOLATIONS** means the server read, contacted or ran something the
  policy doesn't allow, during that run. It doesn't say why, or whether it
  was harmful.
- **CLEAN never means safe.** It means nothing outside the policy was seen
  while the server was traced, with the inputs it got. See
  [limitations.md](limitations.md).
- Real-server times were measured on one machine, the owner's Mac (Apple
  chip, Docker 29.8.2). Download times depend on the network that day.

## Tests and fixtures

| Number | Value | Source | Date |
|---|---|---|---|
| Unit tests | 905 passed, 2 skipped | `uv run pytest` at `c68c748` on the owner's Mac (`905 passed, 2 skipped, 9 warnings in 74.89s`) | 2026-11-17 |
| Fixture runs | 58, all match | `uv run python scripts/check_fixtures.py` at `c68c748`: `all 58 fixtures match expectations`, on the owner's Mac (3 min 57 s) and in CI ([Sandbox run 43332843892](https://github.com/nabulsi019/sandglass-mcp/actions/runs/43332843892), the merge of PR #185) | 2026-11-17 (Mac), 2026-11-12 (CI) |

The unit tests check the parser, the policy rules and the report on
hand-written traces, without Docker. The 58 fixture runs are servers and
packages we wrote, each run through the real sandbox and tracer, and each
must give an exact verdict and exact violations:

- 8 first fixtures (clean, file reads, listing, a program run, an
  undeclared domain, Node.js, trace tampering) and 1 that exits at startup;
- 8 scans of our own test packages (clean, an install-time read, a wrong
  hash, three hostile archives), 2 more through the npm download container;
- 7 escape attempts (`/proc/self`, untraced clone, io_uring, ptrace, a
  stalled sink connection) and 2 policy-template runs (`read_deny`,
  symlinks);
- 6 runs with Docker's own seccomp profile off (3 servers, 3 npm scans), to
  show Sandglass's filter doesn't depend on Docker's;
- 24 runs for single features: time-outs, runtime noise, coverage summary,
  server setup, input modes, environment, process names, DNS, a missing
  program, deep-scan budgets, sample files, repeated calls, stability, and
  the observation window.

The full list, with every expected verdict, is in [fixtures.md](fixtures.md).

## Real-server scans

Sandglass was run on 13 real open-source MCP servers (PyPI and npm), on the
owner's own machine, under `policies/templates/no_network.v1.yaml`. The full
tables, with every package, version, time and reason, are in
[real-scans-v0.4.1.md](real-scans-v0.4.1.md) and
[real-scans-deep.md](real-scans-deep.md). The summary:

| Pass | Servers | CLEAN | VIOLATIONS | INCOMPLETE | Meaningful | Source | Date |
|---|---|---|---|---|---|---|---|
| First pass (#25), quick | 13 | 3 | 6 | 4 | about 4 of 13 | [real-scans-v0.4.1.md](real-scans-v0.4.1.md), "Totals" | 2026-10-19 to 2026-10-27 |
| v0.4.1 rescan, quick | the same 13 | 5 | 7 | 1 | 7 of 13 (plus 1 partly) | [real-scans-v0.4.1.md](real-scans-v0.4.1.md), PR #166 | 2026-10-31 |
| Deep rescan of the 5 shallow ones | 5 | 1 | 4 | 0 | 3 of 5 (before: 1, partly) | [real-scans-deep.md](real-scans-deep.md), PR #185 | 2026-11-12 |

"Meaningful" is the judgement written in those documents: the verdict
reflects the server's tools doing their normal work, not mostly rejecting
their inputs. Between the first pass and v0.4.1, false positives (for
example `/dev/null`, a loopback IPv6 bind) were removed and servers that
couldn't start got the setup they need, so fewer results were INCOMPLETE
and more meant something. Five quick results were still shallow, because
most tools rejected inputs like `hello`. The deep scan (sample files, up to
5 calls per tool, a second run, a 60 s observation window) made 3 of those
5 meaningful: markitdown-mcp, mcp-server-git (8 of 12 tools ran) and
wikipedia-mcp (22 of 22 tools called). excel-mcp-server and
arxiv-mcp-server are still shallow; the deep document says why.

Every VIOLATIONS verdict in these passes is a server contacting a domain or
running a program that `no_network.v1` doesn't allow, mostly the service
the server exists to use. No server read the decoy credentials.

### Deep scan caught what quick missed: markitdown-mcp

| Scan | Verdict | Source | Date |
|---|---|---|---|
| Quick (v0.4.1) | CLEAN (0), "but 1 of 1 tool returned errors" | [real-scans-v0.4.1.md](real-scans-v0.4.1.md), row 6 | 2026-10-31 |
| Deep | VIOLATIONS 4 in 1 entry (1), stable in both runs | [real-scans-deep.md](real-scans-deep.md), row 1 | 2026-11-12 |

In the deep scan, a dependency of markitdown-mcp@0.0.1a8 (onnxruntime
1.31.1, through magika) contacted `mobile.events.data.microsoft.com` about
9 s after the last tool call, from a background thread, in both runs. No
tool call triggered it. This is ONNX Runtime's documented telemetry (on by
default since 1.29; opt-out `ORT_DISABLE_TELEMETRY=1`; public reports in
[immich#30729](https://github.com/immich-app/immich/issues/30729) and
[LibreTranslate#1035](https://github.com/LibreTranslate/LibreTranslate/issues/1035)).
The quick scan reported CLEAN because it stops watching right after the
last call; the deep scan's 60 s observation window saw the request. The
sink refused it, so nothing was sent. This is a documented behaviour of a
dependency, not a hidden one; it shows why a quick CLEAN is only a first
look.

## Scan time and compute cost

Wall-clock time of the whole command (download, install, run, analysis),
measured with `time` on the owner's Mac:

| Scan | Servers | With download: range (median) | Without download: range (median) | Source | Date |
|---|---|---|---|---|---|
| Quick | 13 real servers | 6 to 243 s (43 s) | 3.5 to 146.2 s (13.4 s) | [real-scans-v0.4.1.md](real-scans-v0.4.1.md), "v0.4.1 time" and "without download" | 2026-10-31 |
| Deep | 5 real servers | 140 to 1231 s (152 s) | 134.6 to 1220.9 s (142.0 s) | [real-scans-deep.md](real-scans-deep.md), "Time" (total minus its download part) | 2026-11-12 |
| All 58 fixtures | our own | 3 min 57 s | n/a (local test registry) | `check_fixtures.py`, owner's Mac | 2026-11-17 |
| All 58 fixtures, CI | our own | 4 min 57 s (plus 58 s image build; job 6 min 2 s) | n/a | [Sandbox run 43332843892](https://github.com/nabulsi019/sandglass-mcp/actions/runs/43332843892) | 2026-11-12 |

The same five servers, quick against deep, without download:

| Server | Quick | Deep |
|---|---|---|
| markitdown-mcp | 40.7 s | 165.7 s |
| excel-mcp-server | 13.3 s | 138.3 s |
| mcp-server-git | 10.2 s | 134.6 s |
| wikipedia-mcp | 146.2 s | 1220.9 s |
| arxiv-mcp-server | 15.1 s | 142.0 s |

A quick scan of most servers takes about 10 to 40 s once the package is
downloaded; a server with many slow tools can use its whole 120 s call
budget (wikipedia-mcp, 22 tools). A deep scan takes about 2 to 3 minutes
for most servers, because it runs the server twice and waits 60 s after
each run, and up to about 20 minutes for a server with many tools
(wikipedia-mcp: a 600 s call budget, twice). Downloads add anything from
seconds to minutes: markitdown-mcp's 114 MB took 201 s on 2026-10-31 and
about 18 s on 2026-10-26.

**Approximate compute cost per scan.** Sandglass runs on your own machine,
so a scan costs no money there; its electricity use is not measured yet.
To give a price, take a GitHub-hosted Linux 2-core (x64) runner: $0.006 per
minute, and "GitHub rounds the minutes and partial minutes each job uses up
to the nearest whole minute"
([GitHub's runner pricing](https://docs.github.com/en/billing/reference/actions-runner-pricing),
read 2026-11-17). One scan per job, using the Mac times above:

| Scan | Time | Billed minutes | Cost |
|---|---|---|---|
| Quick, median (with download) | 43 s | 1 | 1 × $0.006 = $0.006 |
| Quick, slowest (markitdown-mcp, slow download) | 243 s | 5 | 5 × $0.006 = $0.030 |
| Deep, median (with download) | 152 s | 3 | 3 × $0.006 = $0.018 |
| Deep, slowest (wikipedia-mcp) | 1231 s | 21 | 21 × $0.006 = $0.126 |
| All 58 fixtures in CI (measured on a runner) | 6 min 2 s | 7 | 7 × $0.006 = $0.042 |

A job on a fresh runner also builds the image first (58 s in CI), which
adds about 1 billed minute ($0.006) per job. These are estimates: the scan
times were measured on an Apple-chip Mac, not on a runner. Real-server
scan times on a hosted runner: not measured yet.

## The outside review: escape probes

An external reviewer looked at Sandglass three times: `d48a04c`
(2026-10-20; issues #75 to #83, filed 2026-10-22), `b528494` (2026-10-23;
findings R1 to R4: R1 and R2 extended #84, R3 and R4 became #136 and #133
on 2026-10-26)
and a fourth round on 2026-10-29 (issue #155). Each escape the reviewer
described became a fixture that tries it for real, in the sandbox, with fake
credentials only:

| Finding | What a server could do | Probe | Before the fix | Now |
|---|---|---|---|---|
| R1 (#75, #84): io_uring | read files with no `openat` in the trace (Docker before 25) | `iouring_node_server.js`, also with Docker's seccomp profile off | INCOMPLETE with Docker's seccomp profile off (PR #135) | VIOLATIONS: 1 read of the decoy credentials; io_uring refused, the read seen; the same with Docker's profile off |
| R2 (#84): `clone(CLONE_UNTRACED)` | a child strace doesn't follow reads the credentials | `untraced_clone_server.py`, also with Docker's profile off | **CLEAN** (a prototype server, PR #135) | VIOLATIONS: 2, the refused clone ("tried to evade tracing") and the read by the fallback child |
| #84: `ptrace`, `process_vm_readv`/`writev` | act through, or read and write, another process | `ptrace_server.py` | not measured yet (the probe was written with the fix) | VIOLATIONS: 3, all refused |
| R3 (#136): stalled sink connection | hide a domain behind a stalled request | `stall_sink_server.py` under `listed_domains_only.v1` | **CLEAN**, only `api.example.com` recorded (PR #137) | VIOLATIONS: 1, `hidden.example` |
| R4 (#133): hostile archives | write outside the temp folder on the host while unpacking | `sandglass-test-traversal` (npm), `-symlink` and `-bomb` (wheels) | not measured yet (no hostile archive had been tried) | INCOMPLETE, `unsafe archive`; never unpacked on the host, nothing written outside the temp folder |
| Round 4 (#155): install not filtered | npm scans INCOMPLETE on old Docker; install scripts not filtered | npm scans with Docker's seccomp profile off | INCOMPLETE on Docker 20.10 (as reported in #155) | npm:sandglass-test-notes CLEAN, npm:sandglass-test-postinstall VIOLATIONS (its install-time read), through the download container CLEAN |

"Now" is from `check_fixtures.py` on 2026-11-17 (owner's Mac) and
2026-11-12 (CI). "Before the fix" is what the fix's PR reported when it
reproduced the finding on the code before the fix. The two **CLEAN**s are
the important ones: before those fixes, a server could read the decoy
credentials or contact a domain and still get CLEAN.

Our own probes in the same spirit (not from the review), all VIOLATIONS
now: `tamper_trace_server.py` (3, its attempts on its own trace, all
blocked), `symlink_escape_server.py` (2, under `no_network.v1`),
`proc_self_escape_server.py` (3, under both policies).

The review's other findings, all closed:

| Issue | Finding | Outcome |
|---|---|---|
| #76 | `sendmmsg` wasn't recorded | fixed, with a unit test (2026-10-22) |
| #77 | `memfd_create` wasn't traced | fixed: recorded as a write to `memfd:<name>` (2026-10-23) |
| #78 | non-ASCII paths decoded wrongly | fixed, with unit tests (2026-10-22) |
| #79 | a leading `//` could get past a deny rule | fixed, with unit tests (2026-10-22) |
| #80 | hostnames with `_` recorded as invalid | fixed, with unit tests (2026-10-23) |
| #81 | the base image could change Debian release | fixed: pinned to trixie (2026-10-23) |
| #82 | a server can see it is traced (`TracerPid`) | not fixable; documented in every report and in [limitations.md](limitations.md) (2026-10-23) |
| #83 | the whole trace was loaded into memory | fixed: read line by line, capped at 256 MiB (2026-10-23) |

## Not measured yet

- How often Sandglass misses a real misbehaving server (no known-malicious
  MCP server has been scanned; only our own fixtures).
- Real-server scan times on a hosted runner or on x86_64.
- Electricity or hardware cost of a scan on your own machine.
- Deep scans of the other 8 real servers (only the 5 shallow ones were
  rescanned deep).
- How many real servers check for the sandbox or for tracing.
