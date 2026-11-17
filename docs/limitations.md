# Known limitations

What Sandglass can't see, can't stop, or doesn't try to. Read this before
trusting a CLEAN verdict: **CLEAN never means safe.** It means nothing
outside the policy was seen while the server was traced, with the inputs it
got.

## What a run can miss

- **Delayed behaviour** (#175). A deep scan watches for 60 s after the last
  call; a quick scan not at all. Anything a server does later, on a date, or
  only after an event Sandglass never causes, is not seen, and a server can
  notice the deep scan (its sample folder, its notification) and wait it out.
- **Behaviour delayed past the 60 s observation window isn't seen.** The
  window ([how-it-works.md](how-it-works.md#the-observation-window)) ends
  60 s after the last call, and then the session is closed. A timer that
  fires after 61 s, a job scheduled for the next hour or the next day, or
  work started only on the server's tenth session is never traced. The
  markitdown-mcp telemetry in [results.md](results.md) fired about 9 s
  after the last call, inside the window; the same request after 70 s would
  have been missed, and a quick scan would have missed it at 9 s.
- **Behaviour that depends on the environment is only seen for the
  sandbox's own setup.** A server runs with exactly the variables listed in
  [how-it-works.md](how-it-works.md#the-servers-environment): `LANG` is
  `C.UTF-8`, there is no `CI`, `GITHUB_ACTIONS`, `TERM`, `USER` or cloud
  variable, the hostname is a random container id, and the clock, timezone,
  CPU and files are the image's. Code that only acts under another locale or
  timezone, only outside CI, only on a given hostname, user or date, or only
  when a real cloud credential or account is present, isn't exercised. Any
  `--env` you add is still only one more setup.
- **Probes of credential files that don't exist in the decoy home are only
  "attempted".** The decoy home has three fake files: `.aws/credentials`,
  `.ssh/id_rsa` and `.env`. A server that looks for another one (for
  example `~/.config/gcloud/...`, `~/.kube/config`, `~/.npmrc`,
  `~/.netrc` or a browser profile) gets `ENOENT`. A failed open is listed
  under "attempted" and doesn't change the verdict
  ([policies.md](policies.md#how-behaviour-is-judged)), so such a probe
  doesn't make the run VIOLATIONS, and what the server would have done with
  the file's contents is never seen. Read the "Attempted" list of every
  report for paths under `/home/sandglass`.
- **Only one call per tool, with one example input** (quick scan). The input is built
  from the tool's JSON schema and, in the default `described` mode, the
  examples its descriptions give (`sandglass/inputs.py`, #22, #145; see
  [Tool inputs](usage.md#tool-inputs)): the schema's own `const`/`enum`/`default`/`examples`
  first, then description examples and hints, otherwise a simple value per
  type (`"hello"` for strings, `1` for numbers, inside any min/max), nested
  objects and arrays filled in, local `$ref`s followed. A tool whose schema
  we can't satisfy (a string `pattern` none of a few fixed strings match) is
  skipped, not guessed. An argument with no example (e.g. mcp-server-time's
  `time`, "in 24-hour format (HH:MM)") still gets `"hello"`. Behaviour behind
  other inputs isn't exercised. (A [deep scan](usage.md#deep-scan) makes up
  to 5 calls per tool, with sample files, and that still isn't every input.)

## Detecting the sandbox

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
- **A server can tell it's in the sandbox** in other cheap ways too (#159).
  Removed so far: Sandglass's name in the environment (#146) and on every
  command line (the launcher, sink and relay are files in the image at
  `/usr/local/lib/mcp-runtime/`, the shells' `$0` are neutral, the venv has
  no project prompt, a scan's volume and npm `package.json` have neutral
  names). Still there: `/etc/passwd` has a `sandglass` user and `HOME` is
  `/home/sandglass` (the protected decoy home); `TracerPid` in
  `/proc/self/status` (#82); the proxy on 127.0.0.1:18080 and the proxy
  variables pointing at it; the helper files themselves (readable, and
  their comments mention Sandglass); the launcher's own command line (a
  Python server's `/proc/self/cmdline` is `python -S .../run.py <server>`,
  not `python <server>`); and fixture runs mount the project at `/project`.
  Fully hiding a tracer isn't possible; the aim is removing cheap tells,
  and "the server detects the sandbox" stays a limitation of any dynamic
  analysis.

## The syscall filter and the trace

- **The syscall filter covers the install too (#155), from its first
  program on.** The few lines of the untraced outer `sh` that start strace
  run before it, like in the server's run. The npm download container is
  filtered but not traced: it only downloads, with `--ignore-scripts`.
- **`/proc/<pid>/mem` is out of the filter's reach.** seccomp can't look at
  the path an `open` is given, so opening another process's memory file
  isn't refused by Sandglass. It is still an ordinary file open in the
  trace, judged by the policy like any read or write (and strace's own
  memory is protected by its non-readable binary, see
  [What the sandbox does](how-it-works.md#what-the-sandbox-does)).

- **The server's own stderr is discarded in `--sandbox` mode, to protect the
  trace** (#47). strace writes the trace to the container's stderr, so the
  launcher points the server's stderr at `/dev/null` before any server code
  runs; otherwise the server could write fake lines into its own trace. To see
  a server's tracebacks, run it without `--sandbox`.
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
  folder, so that path is judged as asked for. Only then: `/proc/self/root/...`
  or `/proc/self/fd/N` that lead outside `/proc` are judged by the file they
  opened (`test_servers/proc_self_escape_server.py`, #131). Failed opens and probes
  (`stat`) are still judged by the requested path only: strace can't show
  where they would have led.

## Packages and downloads

- **PyPI scans are wheels only**: a package published only as an sdist gives
  INCOMPLETE, because building an sdist would run the package's own code on
  the host, outside the sandbox.
- **npm downloads with network access** (#138). The npm download container
  is the one Sandglass container with network, for the download only, and
  npm unpacks the tarballs inside it (never on your machine) before
  Sandglass's archive checks run on the host. A package (or dependency)
  bigger than 500 MB unpacked, or with more than 20,000 files, can't be
  scanned.

- **Fixture runs mount the whole project read-only**, so a fixture server
  can read `sandglass/`, `policies/` and the other fixtures. That is acceptable for
  our own fixtures. `sandglass scan` mounts **only the installed package**
  (#20): the project isn't in its container at all.

## Network

- **What the DNS recorder can't see** (#147). DNS over HTTPS (through the
  proxy the sink records the DoH server's domain, not the name; direct to
  an IP it's just a connect to that address); DNS over TLS (port 853) and
  DNS to a hard-coded nameserver (shown as `direct DNS to X:53`, an address,
  never the name); hard-coded IP addresses (no lookup at all). After the
  NXDOMAIN answer, what a server would have done next (port, path, data) is
  never seen: we get the name, not the request. Names looked up during the
  install phase aren't recorded (Docker's resolver there). A flood of
  queries only adds markers; the trace size cap (#83) makes an oversized
  trace INCOMPLETE. The recorder runs as the server's user, like the sink:
  a server that kills it makes the run INCOMPLETE.

## The image

- **Programs in the image** (#148). Besides Python, the image has strace,
  `node`/`npm`/`npx` (Debian's), `sh`/`bash`, `uv` and `git` (added for
  servers like mcp-server-git; it brings perl, about 101 MB). Running any
  of them is still the server's own action: a violation unless the
  policy's `exec_allow` lists it, so mcp-server-git gets VIOLATIONS under
  every template for running `/usr/bin/git`. A server that needs another
  program and exits at startup gets the INCOMPLETE reason "the server
  needs a program the sandbox doesn't have: <name>", but only if it
  looked for it with exec (a PATH search, 2+ places, never found by any
  process, the last such search before its exit). A program looked up
  with `stat` only (e.g. `shutil.which`) isn't named, and a server that
  probes for an optional program, carries on, and then exits for another
  reason gets a misleading hint (its own error message comes first).
- **Baselines are specific to the image.** `python312_slim` covers
  `python:3.12-slim-trixie`; `node_debian` covers Debian's `nodejs` package in the same
  image (`.js` servers get both, since the launcher is Python). Another base image
  or runtime needs its own baseline. The Dockerfile pins the Debian release
  (13, "trixie": strace 6.13, Node.js 20), so a rebuild can't silently switch
  release; moving to a new one means re-checking the baselines and the trace parser.
