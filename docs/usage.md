# Using Sandglass

How to run Sandglass: setup, scanning a published package, giving a server
the setup it needs, choosing tool inputs, the deep scan, and exit codes.
How it works inside is in [how-it-works.md](how-it-works.md); how a run is
judged is in [policies.md](policies.md).

**Only scan servers you wrote or may test**, with fake credentials only
(see the [Safety rules](../README.md#safety-rules)).

- [Setup](#setup)
- [Running a server in the sandbox](#running-a-server-in-the-sandbox)
- [Exit codes](#exit-codes)
- [Scanning a published package](#scanning-a-published-package)
- [Server setup](#server-setup)
- [Tool inputs](#tool-inputs)
- [Deep scan](#deep-scan)
- [Without `--sandbox`](#without---sandbox)

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

The expected verdict of every fixture, and how to check them all at once,
is in [fixtures.md](fixtures.md).

## Exit codes

With `--sandbox`, and for `sandglass scan`, the exit code is the verdict:

| Exit code | Meaning |
|---|---|
| `0` | CLEAN |
| `1` | VIOLATIONS |
| `2` | usage error (a wrong argument, a missing file; argparse's own code) |
| `3` | INCOMPLETE (including "the sandbox couldn't start") |

So a script can tell "called wrong" from "the run can't be trusted" (#124).

## Scanning a published package

```bash
uv run sandglass scan pypi:<package>@<exact-version> --policy <policy.yaml>
uv run sandglass scan npm:<package>@<exact-version>  --policy <policy.yaml>
```

**Only scan packages you may test** (see
[Safety rules](../README.md#safety-rules)). The version must be
exact: `latest`, ranges (`^1.2.3`, `~1.2`, `>=1`, `1.*`, `1.x`) and local
versions are refused with a usage error, so a report always names exactly
what was scanned. Exit code: `0` CLEAN, `1` VIOLATIONS, `2` usage error,
`3` INCOMPLETE.

The policy's `read_allow`, `write_allow` and `read_deny` paths must be
absolute (or placeholders like `{venv}`) for a scan (#123): a relative path
means "inside the project", and a scan doesn't mount the project. A relative
path stops the scan before anything is downloaded, with exit code `2` and
`policy path '<path>' is relative; scans have no project folder, use an
absolute path`. Normal runs still accept relative paths.

What happens (`sandglass/scan.py`):

1. **Download** into a temporary folder on your machine. No package code
   runs here:
   - PyPI: `pip download`, **wheels only** (`--only-binary=:all:`), for the
     container's platform (Linux, CPython 3.12, its CPU), so it works from a
     Mac too. Building an sdist would run its `setup.py` on your machine, so a
     package with no wheel can't be scanned (INCOMPLETE, with pip's error).
   - npm (#138): **not on your machine**. A separate, short-lived **download
     container** (same `sandglass-sandbox` image, deleted when it exits) runs
     `npm install --ignore-scripts --no-audit --no-fund`, which fills an npm
     cache with the package and its dependencies. npm unpacks only inside
     that container's in-memory `/tmp`; the unpacked `node_modules` never
     reaches your machine. What comes back into the scan's temp folder is
     only the npm cache (the tarballs, still packed, and npm's index),
     `package.json` and `package-lock.json`. `npm` doesn't need to be
     installed on your machine. A lockfile entry that points at a local path
     (`file:`, `link`) stops the scan, and so does a lockfile or cache file
     that is a symlink or leads outside the temp folder.

     What the download container may do:

     | | |
     |---|---|
     | Network | **Yes, for this step only** (Docker's default bridge), to reach the npm registry. The analysis sandbox below stays `--network none`. |
     | User | `--user 10001:10001` (non-root), plus your temp folder's group (`--group-add`) so it can write there |
     | Filesystem | `--read-only` root; writable only: the scan's temp folder (at `/out`) and a `/tmp` tmpfs (`noexec,nosuid`) |
     | Privileges | `--cap-drop ALL`, `--security-opt no-new-privileges`; never `--privileged` or `--cap-add` |
     | Mounts | the temp folder only: no project, no home folder; `HOME` is an empty `/tmp/home` |
     | Code | npm only, with `--ignore-scripts` and `npm_config_ignore_scripts=true`: no package code runs. Sandglass refuses to start it without `--ignore-scripts`. |

     What it can't stop: npm itself downloads and unpacks the tarballs
     (inside the container), and a package's registry could see the request.
     The container doesn't see the decoy credentials or your files.

   **Archive check** (#133): every downloaded file (the package and each
   dependency: wheels, npm tarballs, the npm cache's tarballs) is checked
   member by member, reading only the headers, before anything else reads
   it. Nothing is ever unpacked on your machine, by Sandglass or by npm. The scan stops,
   INCOMPLETE (`unsafe archive <file>: member '<name>' is ...; not
   installed`), if a member is an absolute path or has a `..` component, is
   a symlink or hard link leading outside the archive, or is a device or
   fifo, or if the archive has more than 20,000 files or more than 500 MB
   once unpacked (`MAX_ARCHIVE_FILES` / `MAX_ARCHIVE_BYTES` in
   `sandglass/scan.py`). Sandglass's own reads from an archive
   (`entry_points.txt`, `package.json`) are plain files only, at most 1 MB.

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
   `install-trace.txt` next to the server's trace). The first traced program
   is Sandglass's syscall filter (#155, see
   [how-it-works.md](how-it-works.md#sandglasss-syscall-filter)), which execs the installer's shell;
   the shell's first act is `exec 2>&1`, so pip, npm and every install script write to the
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
   reports (`/project/...` gives `ENOENT`). The server's working directory
   is the empty `/tmp/work` (#144, see [Server setup](#server-setup)). The server is the package's console script (PyPI) or `bin`
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
| `npm:sandglass-test-traversal@1.0.0` | INCOMPLETE: `unsafe archive`, its member `../../sandglass-escaped-traversal.txt` has a `..` component; never unpacked, installed or run |
| `pypi:sandglass-test-symlink@1.0.0` | INCOMPLETE: `unsafe archive`, a symlink leading outside the archive (to `~/.aws/credentials`) |
| `pypi:sandglass-test-bomb@1.0.0` | INCOMPLETE: `unsafe archive`, more than 500 MB uncompressed (a 0.5 MB wheel) |

The local test registry also holds registry-style metadata
(`test_packages/dist/<pypi|npm>-meta/<name>/<version>.json`) with the
published hashes, so the hash check runs offline too.

With `--registry-dir`, an npm test package's tarball is copied straight from
that folder: no npm and no download container (the fast path the fixtures
above use). To test the download container itself (#138),
`check_fixtures.py` also serves `test_packages/dist` as an npm registry, from
a container on a private Docker network (never the real registry), and scans
through it (`EXPECTED_NPM_REGISTRY_SCANS`):

| Package (download container) | Verdict |
|---|---|
| `npm:sandglass-test-notes@1.0.0` | CLEAN; the hash matches the registry's `dist.integrity` |
| `npm:sandglass-test-traversal@1.0.0` | INCOMPLETE: `unsafe archive`, member `../../sandglass-escaped-traversal.txt`; npm unpacked it only inside the download container, nothing escaped on the host |

It also checks that the download left only `npm-cache/`, `project/package.json`
and `project/package-lock.json` in the temp folder.

## Server setup

Arguments, environment and a work folder (#144). Some servers need setup
before they start or work. Both `sandglass scan` and
`sandglass <server> --sandbox` take:

- `--server-arg ARG` (repeatable, in order): an argument for the server. One
  that starts with `-` must be written `--server-arg=--db-path`. Arguments
  are passed as a list (never through a shell) and **recorded in the report
  as given**, so put nothing secret there.
- `--env KEY=VALUE` (repeatable): an environment variable for the server.
  **Fake values only** (see [Safety rules](../README.md#safety-rules)). The
  report records the name, never the value; the value reaches Docker through
  its own environment (`-e NAME`), so it isn't on any command line.

Every run also has a **work folder**: `/tmp/work`, created empty (owned by
the sandbox user) before tracing starts, inside the scratch `/tmp` that is
already there; it is the server's working directory. There is no new mount,
and `$HOME` stays the read-only decoy. Writes there are judged by the policy
like any other: `no_network.v1` allows them (it allows `/tmp`),
`read_only_folder.v1` reports them as violations.

The report header shows the setup and a command that reproduces the run,
e.g. `- Server setup: arguments ["stdio"], environment MEMORY_FILE_PATH
(values not recorded), work dir /tmp/work`.

### Refused `--env` names

`--env` refuses these names (exit code `2`), compared upper-cased, because
the variables reach the whole container (the shell and strace too), not
only the server:

| Names | Why refused |
|---|---|
| `PATH`, `HOME` | set by Sandglass (`HOME` is the decoy home) |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | set or removed by the launcher for the network sink |
| `SANDGLASS_*` | read by Sandglass's launcher |
| `LD_*`, `PYTHON*` | read before the launcher hides the trace stream |
| `NODE_OPTIONS` | changes how Sandglass starts Node |
| `DOCKER_*` | read by the docker command on the host, which passes the values on |
| `GCONV_PATH`, `LOCPATH`, `GLIBC_TUNABLES`, `MALLOC_*`, `IFS`, `ENV`, `BASH_ENV` | read by glibc or the shell before tracing starts |

Examples (servers from #25):

```bash
uv run sandglass scan pypi:excel-mcp-server@2.2.2 --policy policies/templates/no_network.v1.yaml \
    --server-arg stdio --server-arg=--allow-dir --server-arg /tmp/work
uv run sandglass scan pypi:mcp-server-sqlite@2025.4.25 --policy policies/templates/no_network.v1.yaml \
    --server-arg=--db-path --server-arg /tmp/work/test.db
uv run sandglass scan npm:@modelcontextprotocol/server-memory@2.0.0 --policy policies/templates/no_network.v1.yaml \
    --env MEMORY_FILE_PATH=/tmp/work/memory.jsonl   # must be absolute: relative is the package folder
uv run sandglass scan pypi:arxiv-mcp-server@0.8.2 --policy policies/templates/no_network.v1.yaml \
    --server-arg=--storage-path --server-arg /tmp/work/papers
```

## Tool inputs

`--inputs minimal|schema|described` (#145). Each tool is called once, with
one input built from its JSON schema and its descriptions
(`sandglass/inputs.py`). Both `sandglass scan` and
`sandglass <server> --sandbox` take `--inputs`:

| Mode | Input |
|---|---|
| `minimal` | required arguments only, a plain value per type: `"hello"`, `0`, `false`, `[]`, `{}`. The naive baseline, for comparing modes. |
| `schema` | the schema alone (#22): `const`/`enum`/`default`/`examples`, a value per format, numbers inside their bounds, nested objects filled in. A `pattern` skips the tool. |
| `described` (default) | per argument, the first of: `const` > `enum` (first value) > `default` > `examples` > an example in the argument's description > a URL in the tool's description > a format hint > a string matching the `pattern` > the number bounds > the `schema` mode's value. |

An example in a description is the first quoted token (`'...'`, `"..."` or
`` `...` ``) after "e.g.", "eg.", "for example", "example:" or "such as", in
the same sentence: `IANA timezone name (e.g., 'America/New_York')` gives
`America/New_York`; for an array, `(e.g. ['cs.LG', 'cs.AI'])` gives
`["cs.LG"]`. A token that is empty, has a newline or is over 200 characters
is ignored, and so is one that isn't the argument's type (`'ten'` for an
integer). A URL from the tool's description is only used for arguments
named like `url`/`uri`/`link` or with format `uri`. Format hints: `date`
2024-01-15, `date-time` 2024-01-15T12:00:00Z, `uri` https://example.com/,
`email` user@example.com, `uuid` a fixed valid UUID, `time` 12:00. All of
it is deterministic: no LLM, no network.

The report records the mode in its header and in the reproduce command,
and every argument's value with its source (`const`, `enum`, `default`,
`examples`, `param-description`, `tool-description`, `format`, `pattern`,
`bounds`, `fallback`) in the JSON's `inputs` and the "Tools exercised"
table.

**Safety:** description examples are the server's own text, so a hostile
server can choose its own inputs. That is acceptable: Sandglass judges what
the server *does*, not what it was asked. The values are only sent to the
tool, never interpreted by Sandglass (no path is created, nothing is run),
and are capped at 200 characters.

## Deep scan

`--deep` (#170). The quick scan (the default) gives all the tool calls one
budget of 120 s, whatever the tool count, so a server with many tools can
run out of it (wikipedia-mcp, 22 tools). `--deep`, on `sandglass scan` and on
`sandglass <server> --sandbox` (a usage error without `--sandbox`), gives the
calls a budget that grows with the tool count instead:

    budget = min(max(120, 30 × tools), 600) seconds

30 s is the call timeout, so every tool can use one full timeout: 2 tools
get 120 s, 13 tools 390 s, 22 tools 600 s (the cap). The budget starts once
the tools are listed, and in deep no call starts with under 5 s left: that
tool is "not called (time budget)". Download and install time come on top.

The report records which scan ran: `depth` (`quick` or `deep`) in the JSON,
and for deep its `budget` (`seconds`, `per_tool`, `tools`) and a "Time
budget" line in the Markdown header; the reproduce command has `--deep`.
Everything else is the quick scan's: the same call timeout (30 s), the same
ping rule after a timeout, the same verdict rules and exit codes. Without
`--deep`, a scan behaves exactly as before (`tests/test_quick_unchanged.py`
freezes its docker arguments, messages and budget).

```bash
uv run sandglass scan pypi:wikipedia-mcp@2.0.1 --policy policies/templates/no_network.v1.yaml --deep
```

How long each kind of scan takes, measured, is in
[results.md](results.md#scan-time-and-compute-cost).

**Sample files** (#171, deep only). Many tools need a real file to do
anything: "hello" isn't a path, so a quick scan sees only their input
errors. The image holds a few small, harmless sample files, built by
`scripts/build_samples.py` (`notes.txt`, `notes.md`, `table.csv`,
`data.json`, `book.xlsx`, `doc.pdf`, `image.png`) and a git repository
`repo/` with 2 commits (fixed author and dates). A deep run copies them to
`/tmp/work/samples` before tracing starts (owned by the server's user,
fresh for each run); a quick run's `/tmp/work` stays empty.

A string argument named with *path*, *file*, *dir*, *folder*, *repo*,
*document*, *uri* or *url* (or with `format: uri`) gets a sample instead of
its normal value, source `sample-file`. Which one comes from the words in the
argument's name and description, then the tool's: excel/xlsx/spreadsheet →
`book.xlsx`, pdf → `doc.pdf`, csv → `table.csv`, json → `data.json`,
markdown/md → `notes.md`, image/png → `image.png`, git/repo → `repo`,
dir/folder → the samples folder, otherwise `notes.txt`. A URI is
`file:///tmp/work/samples/...`; a URL argument keeps its http(s) URL unless
the text names `file:`. The server's text only chooses among these fixed
paths: it can never put a path of its own into an input.

**Reads of the samples.** Reading a sample Sandglass passed in is not the
server overreaching, so in deep scans those reads are listed under "Sample
files read" instead of as violations, only for **the exact sample paths
passed in any call of that run** (`sample_paths` in the JSON), and for files
under a passed directory (e.g. `repo/.git/HEAD` when `repo` was passed).
Everything else is judged normally: a sample that wasn't passed, any write
(a tool saving next to a sample under a read-only policy is a violation),
and any program run (mcp-server-git running `git` stays a violation unless
`exec_allow` lists it). A server can notice `/tmp/work/samples` and tell it's
a deep scan, and a tool may change a sample that later tools then see; calls
keep a fixed order, so it's the same every run.

**Repeated calls** (#172, deep only). One call per tool can miss what a
tool does with another kind of input. A deep scan calls each tool with up to
5 input variants, in this order, dropping any whose arguments repeat an
earlier one: the chosen `--inputs` mode (`described` by default), then
`described`, `sample-file` (#171), `schema`, `minimal`, then harmless edge
cases: an empty string, `0` and `[]`; a 1,000-character string and `-1`;
the non-ASCII string `héllo 🙂`. No path traversal, no shell characters, no
injection strings. The calls go **round robin**: every tool's first variant,
then every tool's second, and so on, so running out of budget can't starve a
tool of its first call. A tool that timed out gets no more variants, and the
ping rule after a timeout still applies. Coverage shows one row per tool
with its best call (`ran` if any variant ran), and the Markdown lists every
call with its variant; the coverage summary still counts tools, not calls.

**The repeatability check** (#172, deep only). A deep scan runs the server
twice, each time in a fresh container, from the same installed package
(nothing is downloaded or installed again): run 2 makes exactly run 1's
calls, in the same order, under run 1's budget. Its trace is `trace-2.txt`.
The two runs are compared by their violation entries (the label and the
phase, not the counts, since lookup retries vary). The verdict is the worse
of the two (INCOMPLETE, then VIOLATIONS, then CLEAN); there is no new verdict
word or exit code. If the runs differ, the verdict line says `unstable between
runs`, and a "Stability" line (terminal and Markdown) names the entries only
in run 1 or only in run 2. Every violation is tagged with its run (`"run": 1`
or `2`): all of run 1's, and run 2's that run 1 doesn't have, so a difference
can't hide and a stable run lists each finding once. A server with honest
randomness (a random CDN host) reads as unstable; that's accurate. Deep scans
take about twice as long.

**The observation window** (#175, deep only). After its last call, a deep
scan keeps the session open and idle for 60 s, in both runs, and events in
that time are in the **observation** phase, judged by the same rules. How it
works and what it can't see:
[how-it-works.md](how-it-works.md#the-observation-window). A deep scan
takes about 2 minutes longer.

**The depth label** (#174). Every report, scans and fixture runs alike,
says which scan ran, in the terminal summary (just before the Duration
line) and in the Markdown header:

| Depth | Label |
|---|---|
| quick | `Depth: quick scan: a first look` |
| deep | `Depth: deep scan: recommended before approving a server` |

The label describes the scan, never the server: a deep scan that reports
CLEAN still only covers what ran, and a person makes the decision. The
verdict and the exit code never depend on the label.

## Without `--sandbox`

```bash
uv run sandglass test_servers/good_notes_server.py --policy policies/notes_readonly.yaml
```

Runs the server directly on your machine with no tracing and no report. Useful
for checking a server works at all. (The server path on the command line is
relative to your current directory, like any CLI argument.)
