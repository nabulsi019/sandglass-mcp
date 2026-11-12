# Real-server scans, deep (#182)

The five real packages whose quick results in
[real-scans-v0.4.1.md](real-scans-v0.4.1.md) were shallow were scanned again,
same versions, with `--deep` (#170 to #175). The goal: check which of those
results mean something now, and which are still shallow, and why.

**How:**
- Sandglass at `b9617e8` (main before this doc), on 2026-11-12, on the owner's Mac (Apple chip, `aarch64-linux-gnu` in the image), Docker 29.8.2.
- Every package ran under `policies/templates/no_network.v1.yaml` with `uv run sandglass scan <spec> --policy policies/templates/no_network.v1.yaml --deep`.
- Server setup (#144): excel-mcp-server with `--server-arg stdio`; the others as-is.
- Times are wall-clock `real` from `time`, for the whole command. The split (download, install, run, analysis) is the report's own "Duration" line. Downloads come from PyPI, so they depend on the network.
- What a deep scan adds: a time budget of 30 s per tool (#170), sample files in the work dir (#171), up to 5 calls per tool with different inputs (variants: `described`, `minimal`, `schema`, `sample-file`, `edge-empty`, `edge-long`, `edge-unicode`) and a second run that replays the first run's calls (#172), and a 60 s idle observation window after the last call (#175).
- Real packages were scanned only because the owner ran them on his own machine. The only credentials in the sandbox are the decoy home's fake ones. The JSON and Markdown reports stay in `reports/` and are not committed.

**How to read a verdict:**
- **VIOLATIONS** means the server read, contacted or ran something this policy doesn't allow, during this run. With `no_network.v1`, any network attempt counts, including the domain a tool exists to contact, and any program run.
- **CLEAN never means safe.** It means nothing outside the policy was seen while the server was traced, with the inputs it got. A tool "ran" if at least one of its calls (its best variant) returned without an error.
- **Unstable between runs** means the two runs didn't produce the same violation entries; the verdict is the worse of the two.

## Results

| # | Package | Quick verdict (v0.4.1) | Deep verdict (exit) | Tools ran (best variant) | Time (download / install / run / analysis) | What it really means now |
|---|---|---|---|---|---|---|
| 1 | pypi markitdown-mcp@0.0.1a8 | CLEAN (0), "but 1 of 1 tool returned errors" | VIOLATIONS 4 in 1 entry (1), stable | 1 of 1 (`sample-file`) | 190 s (24.3 / 32.1 / 128.1 / 4.6) | Meaningful now. `convert_to_markdown` converted `file:///tmp/work/samples/notes.md`; `described` (`hello`) and the three edge variants were rejected (unsupported URI scheme). A dependency (onnxruntime 1.31.1, via magika) contacts `mobile.events.data.microsoft.com` about 9 s after the last call, from a background thread, in both runs; no tool call triggers it. This is ONNX Runtime's documented telemetry (on by default since 1.29; opt-out `ORT_DISABLE_TELEMETRY=1`; see [immich#30729](https://github.com/immich-app/immich/issues/30729) and [LibreTranslate#1035](https://github.com/LibreTranslate/LibreTranslate/issues/1035)). The quick scan (v0.4.1) reported CLEAN because it doesn't watch after the last call; the deep scan's observation window caught it. The sink refused every request, so nothing was sent. |
| 2 | pypi excel-mcp-server@2.2.2 | CLEAN (0), "but 44 of 46 tools returned errors, 2 skipped" | CLEAN (0), "but 43 of 46 tools returned errors", stable | 3 of 46 (`sample-file`) | 145 s (6.7 / 8.8 / 126.9 / 1.4) | Still shallow. `describe_workbook`, `set_workbook_settings` and `export_workbook` ran on `/tmp/work/samples/book.xlsx`; 43 tools still returned errors on every variant (228 calls). They need more than a workbook path: real sheet names, ranges, chart or table names. Nothing outside the policy was seen in those calls, including no write outside `/tmp`. |
| 3 | pypi mcp-server-git@2026.10.19 | VIOLATIONS 2 (1), "all 12 tools returned errors" | VIOLATIONS 33 in 22 entries (1), "and 4 of 12 tools returned errors, unstable between runs" | 8 of 12 (`sample-file`) | 140 s (5.4 / 6.4 / 125.5 / 1.1) | Meaningful now. With the sample repository at `/tmp/work/samples/repo`, `git_status`, `git_diff_unstaged`, `git_diff_staged`, `git_reset`, `git_log`, `git_create_branch`, `git_checkout` and `git_show` ran. `git_add`, `git_commit`, `git_diff` and `git_branch` got `hello` as a path, ref or branch type and rejected it. 19 of the 22 entries are runs of `/usr/bin/git` (the template allows no programs; a git policy would list it). The other 3 are name lookups. "Unstable between runs" comes from Docker's random per-container hostname: `git checkout` writes the reflog, so git builds a committer identity and looks up the hostname, `bafce0d080c6` in run 1 and `0ac9231f9d11` in run 2. The server behaved the same in both runs; only the container's name differed. |
| 4 | pypi wikipedia-mcp@2.0.1 | VIOLATIONS 206 in 1 entry (1), "and 1 of 22 tools timed out, 1 not called" | VIOLATIONS 920 in 1 entry (1), stable | 22 of 22 (`described`) | 1231 s, about 20 min (10.1 / 20.6 / 1196.1 / 3.5) | Meaningful now, for coverage: every tool was called and answered, none timed out (92 calls). Every network event is still one entry, `domain en.wikipedia.org` (52 CONNECTs through the sink and its retried name lookups), the service the server wraps. The run took 20 min: the call budget is 600 s (30 s per tool, capped), the second run replays the first run's calls, and each run ends with the 60 s observation window. Most calls spend their time on refused requests and lookups. |
| 5 | pypi arxiv-mcp-server@0.8.2 | VIOLATIONS 1 (1), "and 19 of 19 tools returned errors" | VIOLATIONS 2 in 1 entry (1), "and 19 of 19 tools returned errors", stable | 0 of 19 | 152 s (10.0 / 9.1 / 130.7 / 1.4) | Still shallow. The one entry is `domain export.arxiv.org` (2 CONNECTs through the sink), the service it wraps. Every variant of every tool returned an error (81 calls): storage under the read-only HOME (no `--storage-path`), invalid arXiv IDs, "Pro" dependencies not installed, and out-of-range numbers from the edge variants. |

**Totals:**
- **Quick (v0.4.1), these 5:** 2 CLEAN, 3 VIOLATIONS; meaningful: 1 (wikipedia-mcp, partly).
- **Deep:** 1 CLEAN, 4 VIOLATIONS; meaningful: 3 (markitdown-mcp, mcp-server-git 8 of 12, wikipedia-mcp 22 of 22).

**Also checked in this rescan:**
- **Sample files read:** no report has a "sample files read" entry; the policy allows reads under `/tmp`, so none needed to be listed apart.
- **Observation window:** only markitdown-mcp had events judged as violations in it (row 1). The other four had none.
- **Unstable between runs:** only mcp-server-git (row 3), from the container's hostname.
- **No decoy credentials touched:** no server read the decoy credentials (`.aws/credentials`, `.ssh/id_rsa`, `.env`).
- **Installs:** all five installed offline with exit 0 and 0 install violations.

## Still shallow, and why

- **excel-mcp-server (2):** a sample workbook isn't enough. Most tools need a sheet name, a range or the name of an existing chart, table or pivot table, which inputs built from the schema don't know. Calls that chain (create a sheet, then write to it) would reach them.
- **arxiv-mcp-server (5):** it needs real network answers: a search or download that returns an arXiv paper (#173, canned network responses from the sink), real arXiv IDs, and a writable storage path (`--storage-path` under `/tmp/work`).
- **Every row:** NXDOMAIN for every lookup and 403 for every HTTPS CONNECT, so a tool that needs a real network answer stops at its first request (#173).

## Follow-ups

- #183: a fixed, neutral container hostname, so git's hostname lookup isn't flagged as unstable between runs.
- #184: the observation window uses the deprecated `roots/list_changed` (SEP-2577); switch to a message that isn't deprecated, such as `ping`.
