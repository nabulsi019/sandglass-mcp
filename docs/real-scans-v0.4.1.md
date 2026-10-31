# Real-server scans, v0.4.1 (#149)

The 13 real packages from the first real-server pass (#25) were scanned again,
same versions, after the v0.4.1 fixes. The goal: check that the fixes make
these results mean something.

**How:**
- Sandglass at `84f39b4` (main before this doc), on 2026-10-31, on the owner's Mac (Apple chip, `aarch64-linux-gnu` in the image), Docker 29.8.2.
- Every package ran under `policies/templates/no_network.v1.yaml` with the README's command, `uv run sandglass scan <spec> --policy policies/templates/no_network.v1.yaml`.
- Times are wall-clock `real` from `time`, for the whole command (download, install, run, analysis). Downloads come from PyPI or npm, so they depend on the network.
- Server setup (#144):
  - excel-mcp-server: `--server-arg stdio`
  - server-memory: `--env MEMORY_FILE_PATH=/tmp/work/memory.jsonl` (the variable its `dist/index.js` reads; the path must be absolute)
  - every other package as-is, including mcp-server-sqlite (expected to fail, #157)
- Real packages were scanned only because the owner ran them on his own machine. The only credentials in the sandbox are the decoy home's fake ones. The JSON and Markdown reports stay in `reports/` and are not committed.

**How to read a verdict:**
- **VIOLATIONS** means the server read, contacted or ran something this policy doesn't allow, during this run. With `no_network.v1`, any network attempt counts, including the domain a tool exists to contact.
- **CLEAN never means safe.** It means nothing outside the policy was seen while the server was traced, with the inputs it got, for one call per tool. The "but N of M tools returned errors" part says how much really ran.

## Results

| # | Package | #25 verdict (exit) | v0.4.1 verdict (exit) | #25 time | v0.4.1 time | What it really means now |
|---|---|---|---|---|---|---|
| 1 | pypi mcp-server-time@2026.10.19 | CLEAN (0) | CLEAN (0), "but 1 of 2 tools returned errors" | 17 s | 36 s | Half meaningful. `get_current_time` ran with `America/New_York`, taken from its parameter description (#145). `convert_time` got the time `hello` and rejected it (not HH:MM). Nothing outside the policy was seen in those two calls. |
| 2 | pypi mcp-server-fetch@2026.10.24 | VIOLATIONS 5 (1) | VIOLATIONS 6 in 1 entry (1) | 19 s | 53 s | Correct, and now one entry: `domain example.com` (a CONNECT to :443 through the sink, plus its name lookups, now named by the DNS recorder, #147). That's the tool doing its job, contacting the URL it was given; `no_network.v1` forbids it. |
| 3 | pypi mcp-server-git@2026.10.19 | INCOMPLETE (3) | VIOLATIONS 2 (1) | 16 s | 38 s | Starts now (git is in the image, #148). The 2 violations are the server running `/usr/bin/git version` twice at startup; the template allows no programs, so a git policy would list `/usr/bin/git`. The `/dev/null` false positive is gone (#142). Shallow: all 12 tools returned errors, because `repo_path` was `/tmp/work/hello`, which isn't a repository. |
| 4 | pypi mcp-server-sqlite@2025.4.25 | INCOMPLETE (3) | INCOMPLETE (3) | 19 s | 43 s | Still not meaningful (#157). It now gets past the database path, then exits at startup: `AttributeError: 'Server' object has no attribute 'list_resources'`. Its `mcp[cli]>=1.6.0` has no upper bound, so the install picked mcp 2.3.0, whose API it doesn't support. |
| 5 | pypi arxiv-mcp-server@0.8.2 | VIOLATIONS 1 (1) | VIOLATIONS 1 (1), "and 19 of 19 tools returned errors" | 21 s | 69 s | The violation is now real: a request to `export.arxiv.org` through the sink, the service the server wraps. The `bind ::1 port 0` false positive is gone (#142). Shallow: every tool returned an error (invalid IDs from the inputs; storage under the read-only HOME because no `--storage-path` was given; "Pro" dependencies not installed). |
| 6 | pypi markitdown-mcp@0.0.1a8 | VIOLATIONS 3 (1) | CLEAN (0), "but 1 of 1 tool returned errors" | 60 s | 243 s | All three false positives are gone: the IPv6 probe, `/dev/null` and `uname` (#142). But the CLEAN is shallow: its one tool got `hello`, not a URI, and rejected it, so no conversion ran. 201 s of the time was downloading its dependencies. |
| 7 | pypi awslabs.aws-documentation-mcp-server@1.2.3 | VIOLATIONS 2 (1) | VIOLATIONS 5 in 3 entries (1), "and 3 of 5 tools returned errors" | 23 s | 83 s | Correct, and more complete: besides `proxy.search.docs.aws.com` and `api.contentrecs.docs.aws.com`, it now contacts `docs.aws.amazon.com` (3 CONNECTs), because the inputs from descriptions get further (#145). These are the AWS documentation services the server is for. |
| 8 | pypi duckduckgo-mcp-server@0.7.0 | VIOLATIONS 1 (1) | VIOLATIONS 1 (1) | 22 s | 46 s | Correct, unchanged: a request to `html.duckduckgo.com`, its search backend. |
| 9 | pypi wikipedia-mcp@2.0.1 | INCOMPLETE (3), 144 violations | VIOLATIONS 206 in 1 entry (1), "and 1 of 22 tools timed out, 1 not called" | 158 s | 183 s | The session no longer dies (#140): 20 tools answered. The 120 s budget ran out at `get_coordinates` (recorded as timed out), and the last tool was not called. Every network event is one entry, `domain en.wikipedia.org` (#141, #147): 12 CONNECTs through the sink plus its retried name lookups, all now named. |
| 10 | pypi excel-mcp-server@2.2.2 | INCOMPLETE (3) | CLEAN (0), "but 44 of 46 tools returned errors, 2 skipped" | 20 s | 38 s | Starts now with `--server-arg stdio` (#144). The CLEAN is shallow: 44 tools rejected the path `hello` (not an Excel file), and 2 had no valid input. Nothing outside the policy was seen. |
| 11 | npm @modelcontextprotocol/server-everything@2.0.1 | VIOLATIONS 4 (1) | VIOLATIONS 5 in 1 entry (1), "and 1 of 16 tools returned errors" | 19 s | 19 s | The domain is now named: `domain raw.githubusercontent.com`, the default URL its gzip tool fetches with Node's `fetch`, which ignores the proxy (#147). Its `get-env` tool no longer shows `SANDGLASS_RUNTIME` or any Sandglass name (#146). |
| 12 | npm @modelcontextprotocol/server-memory@2.0.0 | CLEAN (0) | CLEAN (0) | 5 s | 6 s | Now a real CLEAN for this run: with `MEMORY_FILE_PATH=/tmp/work/memory.jsonl` all 9 tools ran without errors. Its writes go to the work folder, which `no_network.v1` allows (`/tmp`). Before, the same verdict hid 6 tools failing with EROFS. |
| 13 | npm @modelcontextprotocol/server-sequential-thinking@2.0.0 | CLEAN (0) | CLEAN (0) | 6 s | 6 s | Real CLEAN, unchanged. |

**Totals:**
- **#25:** 3 CLEAN, 6 VIOLATIONS, 4 INCOMPLETE.
- **v0.4.1:** 5 CLEAN, 7 VIOLATIONS, 1 INCOMPLETE.

**Meaningful results:** about 4 of 13 before, 7 of 13 now (rows 2, 7, 8, 9, 11, 12 and 13), plus row 1 partly.

**Also checked in this rescan:**
- **No `SANDGLASS_` anywhere:** none of the 14 reports from this rescan (the 13 above plus the test package below) contains it.
- **No false positives:** no report has a violation for `/dev/null`, a loopback IPv6 bind or `/proc/sys/vm/overcommit_memory`.
- **No decoy credentials touched:** no server read the decoy credentials (`.aws/credentials`, `.ssh/id_rsa`, `.env`).
- **Decoy-HOME lookups are of files that don't exist:** they're ordinary lookups that fail with ENOENT and are listed as attempted. These are pip's config (install), Node's module folders, git's config, `.netrc` (requests), arxiv's default storage and onnxruntime's cache.
- **npm test package:** `npm:sandglass-test-notes@1.0.0` from `--registry-dir test_packages/dist` is CLEAN (0) in 3 s, with no io_uring INCOMPLETE.

## Still not meaningful, and why

- **mcp-server-sqlite (4):** it doesn't start. Its dependency range allows an mcp version it can't run with (#157); this needs a way to pin dependencies for a scan.
- **excel-mcp-server (10), markitdown-mcp (6), mcp-server-git (3), arxiv-mcp-server (5):** they start, but almost every tool rejected its input. The inputs don't point at files, URIs or repositories that exist in the sandbox (a workbook, a URI, a git repository, a real arXiv ID). One call per tool with schema-built values can't reach those code paths. The deep-scan work (repeated calls, prepared inputs) is what would.
- **mcp-server-time (1):** one of its two tools rejected the time `hello`.
- **wikipedia-mcp (9):** one tool wasn't called, because the time budget ran out. The budget doesn't grow with the number of tools (22 here); planned for the deep scan. The timed-out tool's reason reads "no answer within 0 s", because it started with almost no budget left; that wording could be clearer.
- **Every row:** one call per tool, NXDOMAIN for every lookup and 403 for every HTTPS CONNECT. So a tool that needs a real network answer stops at its first request, and whatever it would do next isn't seen.
