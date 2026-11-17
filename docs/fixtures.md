# Fixtures and tests

Sandglass is tested two ways: unit tests on hand-written traces (no Docker),
and **fixtures**: servers and packages we wrote, each with a known
misbehaviour (or none), run through the real sandbox and tracer, with the
verdict and the exact violations each one must give. The fixture servers are
in `test_servers/`, the test packages in `test_packages/` (see the
[layout](how-it-works.md#layout)). They are not real targets.

## Running them

```bash
uv run pytest                                # unit tests, no Docker needed
docker build -t sandglass-sandbox .
uv run python scripts/check_fixtures.py      # must print "all ... fixtures match expectations"
```

`check_fixtures.py` is also what CI runs (the `fixtures` check). The
expected results live in its `EXPECTED_*` dicts, and every one of them is
protected in `CLAUDE.md`. How many there are, and when they last passed, is
in [results.md](results.md#tests-and-fixtures).

Every run must also show the sink reporting the isolation check as isolated
(no route to the internet).

## Expected verdicts

```bash
uv run sandglass test_servers/good_notes_server.py      --policy policies/notes_readonly.yaml --sandbox
uv run sandglass test_servers/overreach_notes_server.py --policy policies/notes_readonly.yaml --sandbox
uv run sandglass test_servers/listing_notes_server.py   --policy policies/notes_readonly.yaml --sandbox
```

Under `policies/notes_readonly.yaml` unless another policy is named:

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
| process_list_server under `policies/templates/no_network.v1.yaml` | CLEAN | 0; sees at least the launcher, sink and relay (and the DNS recorder), and no "sandglass" in any process's command line (#159) |
| dns_fetch_server.js under `policies/templates/no_network.v1.yaml` | VIOLATIONS | one entry, `domain hidden-node.example`: the DNS recorder's A and AAAA lookups plus glibc's lookup steps, all in the tool-call phase; the tool gets ENOTFOUND (#147) |
| missing_program_server | INCOMPLETE | 0; reasons: exited during startup, and "the server needs a program the sandbox doesn't have: sandglass-missing-program" (#148) |
| aws_credentials_server under `policies/templates/no_network.v1.yaml` | VIOLATIONS | 1: read of `/home/sandglass/.aws/credentials` (`read_deny: /home`, #121) |
| symlink_escape_server under `policies/templates/no_network.v1.yaml` | VIOLATIONS | 2, both on `/home/sandglass/.aws/credentials`: the symlink to it made in `/tmp` (a link counts as a read of its target), and the read through that link (judged by the file really opened, #122) |
| proc_self_escape_server under `policies/templates/no_network.v1.yaml` | VIOLATIONS | 3, all reads of `/home/sandglass/.aws/credentials`: through `/proc/self/root/...`, directly, and again through `/proc/self/fd/100` (each judged by the file really opened, #131) |
| proc_self_escape_server under `policies/notes_readonly.yaml` | VIOLATIONS | 3 reads, named by the paths asked for: `/proc/self/root/home/sandglass/.aws/credentials`, `/home/sandglass/.aws/credentials`, `/proc/self/fd/100` |
| untraced_clone_server | VIOLATIONS | 2: the refused `clone CLONE_UNTRACED` ("tried to evade tracing", #84), and the read of `/home/sandglass/.aws/credentials` by the ordinary child it falls back to |
| iouring_node_server.js (run with `UV_USE_IO_URING=1`) | VIOLATIONS | 1: read of `/home/sandglass/.aws/credentials`; io_uring is refused, so libuv reads through its thread pool, visibly |
| ptrace_server | VIOLATIONS | 3: `ptrace PTRACE_ATTACH`, `process_vm_readv`, `process_vm_writev` (all refused, #84) |
| stall_sink_server under `policies/templates/listed_domains_only.v1.yaml` | VIOLATIONS | 1: domain `hidden.example`, the request queued behind a stalled one to the allowed `api.example.com` (#136; CLEAN with the old sink) |
| stall_sink_server | VIOLATIONS | 2: domains `api.example.com` and `hidden.example` |
| good_notes_node_server.js, untraced_clone_server, iouring_node_server.js with Docker's own seccomp profile **off** (old-Docker simulation, test code only) | CLEAN / VIOLATIONS / VIOLATIONS | the same as above: Sandglass's filter doesn't rely on Docker's |

The test packages `sandglass scan` is checked with, and their verdicts, are
in [usage.md](usage.md#scanning-a-published-package) ("Our own test
packages").

## What all the fixture runs cover

Every entry below is one run of `check_fixtures.py`, named by the dict it
comes from. The exact expectations are in the script.

| Dict in `check_fixtures.py` | Runs | What they check |
|---|---|---|
| `EXPECTED` (with `EXPECTED_DOMAINS`) | 8 | the first fixtures: clean, file reads, listing, a program run, an undeclared domain, Node.js, trace tampering |
| `EXPECTED_V04` | 1 | a server that exits at startup (missing API key): INCOMPLETE with the reason |
| `EXPECTED_SCANS` | 8 | `sandglass scan` of our test packages: clean, install-time read, wrong hash, three hostile archives |
| `EXPECTED_POLICY_RUNS` | 2 | `read_deny` and symlinks under `no_network.v1` |
| `EXPECTED_HOSTILE` | 7 | escape attempts: `/proc/self` escapes, untraced clone, io_uring, ptrace, a stalled sink connection |
| `EXPECTED_OLD_DOCKER` | 3 | the same filter with Docker's seccomp profile off |
| `EXPECTED_OLD_DOCKER_SCANS`, `EXPECTED_OLD_DOCKER_NPM_REGISTRY_SCANS` | 3 | npm scans (install and download container) with Docker's seccomp profile off |
| `EXPECTED_NPM_REGISTRY_SCANS` | 2 | the npm download container, from a local registry |
| `EXPECTED_TIMEOUTS` | 1 | a tool that hangs: timed out, the next tool still runs |
| `EXPECTED_RUNTIME` | 2 | harmless runtime noise (CLEAN) and the step past each (VIOLATIONS) |
| `EXPECTED_COVERAGE_SUMMARY` | 1 | a tool that returns an error, shown next to the verdict |
| `EXPECTED_SERVER_SETUP` | 3 | `--server-arg`, `--env` and the work folder |
| `EXPECTED_INPUT_MODES` | 2 | `--inputs described` and `--inputs minimal` |
| `EXPECTED_ENVIRONMENT` | 2 | the exact environment a Python and a Node server see |
| `EXPECTED_PROCESS_FINGERPRINTS` | 1 | no "sandglass" on any process's command line |
| `EXPECTED_DNS` | 1 | the DNS recorder names a lookup Node's `fetch` makes |
| `EXPECTED_MISSING_PROGRAM` | 1 | a server that needs a program the image doesn't have |
| `EXPECTED_DEEP_BUDGET` | 2 | quick and deep budgets with many tools |
| `EXPECTED_SAMPLE_FILES` | 3 | deep scan sample files, and the sample-read rule |
| `EXPECTED_REPEATED_CALLS` | 2 | a read only a second input variant triggers (quick misses it, deep finds it) |
| `EXPECTED_STABILITY` | 1 | a server that behaves differently in run 2: "unstable" |
| `EXPECTED_OBSERVATION` | 2 | a read after the last call (quick misses it, deep finds it) |
| **Total** | **58** | |

`EXPECTED_SCAN_PHASES`, `EXPECTED_SCAN_STOPPED`, `EXPECTED_SCAN_ATTEMPTS`,
`EXPECTED_HOSTILE_DOMAINS` and `EXPECTED_EXIT_CODES` add checks to the runs
above (phases, stop reasons, attempts, sink requests, exit codes); they are
not runs of their own.
