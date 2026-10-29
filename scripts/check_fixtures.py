"""Run every fixture in the sandbox and check its verdict and exact violations.

Also builds our own test packages (test_packages/ -> test_packages/dist/) and
scans them with `sandglass scan` from that local folder (#19), no network;
then scans two npm ones again through the npm download container (#138),
from that folder served as a local npm registry (never the real one).

Used before opening a PR and by the CI sandbox job. Exits 0 only if every
fixture matches its expectation exactly.

    docker build -t sandglass-sandbox .
    uv run python scripts/check_fixtures.py
"""

import contextlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from sandglass import PROJECT_ROOT, client, sandbox, scan
from sandglass.client import EXIT_CODES, run_sandboxed, run_scan
from sandglass.scan import npm_tarball_name, parse_spec

POLICY = PROJECT_ROOT / "policies" / "notes_readonly.yaml"

# Requests the network sink must have recorded, per fixture (others: none).
EXPECTED_DOMAINS = {
    "undeclared_domain_server.py": [("GET", "undeclared.example", 80)],
}

# fixture -> (expected verdict, expected set of (mode, path) violations)
# (mode is None for an exec, "domain" for a domain asked of the network sink)
EXPECTED = {
    "good_notes_server.py": ("CLEAN", set()),
    "overreach_notes_server.py": ("VIOLATIONS", {
        ("read", "/project/test_servers/decoy_home/.fake_credentials"),
    }),
    "listing_notes_server.py": ("VIOLATIONS", {
        ("read", "/etc/passwd"),
        ("list", "/project/test_servers/decoy_home"),
    }),
    # Reads the decoy ~/.aws/credentials baked into the image.
    "aws_credentials_server.py": ("VIOLATIONS", {
        ("read", "/home/sandglass/.aws/credentials"),
    }),
    # Starts /bin/sh. Exec violations have no mode, hence None.
    "shell_command_server.py": ("VIOLATIONS", {
        (None, "/bin/sh"),
    }),
    # Sends a GET to undeclared.example; the local sink records it.
    "undeclared_domain_server.py": ("VIOLATIONS", {
        ("domain", "undeclared.example"),
    }),
    # The Node.js twin of good_notes_server, with its own baseline (node_debian).
    "good_notes_node_server.js": ("CLEAN", set()),
    # Tries to read, overwrite and delete its trace. Only the /proc attempts on
    # strace's fds get as far as EACCES (= violation); the rest fail with ENOENT.
    "tamper_trace_server.py": ("VIOLATIONS", {
        ("list", "/proc/1/fd"),
        ("read", "/proc/1/fd/2"),
        ("write", "/proc/1/fd/2"),
    }),
}


# Fixtures added in v0.4 (#24 onwards). Not in CLAUDE.md's protected items
# (yet): the owner decides whether to protect them like EXPECTED.
# fixture -> (expected verdict, expected violations, text that must appear
# in the INCOMPLETE reasons)
EXPECTED_V04 = {
    # Exits at startup because its (fake) API key isn't set (#24).
    "missing_api_key_server.py": ("INCOMPLETE", set(), [
        "the server exited during startup (exited with 1) before any tool call",
        "RuntimeError: NOTES_API_KEY is not set",
    ]),
}


# Fixtures run under another policy than notes_readonly (#121 onwards).
# fixture -> (policy file, expected verdict, expected violations)
EXPECTED_POLICY_RUNS = {
    # "Read anywhere" stops at home folders (read_deny: /home, /root).
    "aws_credentials_server.py": (PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml",
                                  "VIOLATIONS", {
                                      ("read", "/home/sandglass/.aws/credentials"),
                                  }),
    # Reads the credentials through a symlink it makes in /tmp (#122). Two
    # violations: making the link counts as a read of its target (the
    # syscall is a write, hence "write"), and the open is judged by the file
    # it really opened (strace -y).
    "symlink_escape_server.py": (PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml",
                                 "VIOLATIONS", {
                                     ("write", "/home/sandglass/.aws/credentials"),
                                     ("read", "/home/sandglass/.aws/credentials"),
                                 }),
}


# Hostile fixtures (#131 onwards): servers that actively try to hide what they
# do from the tracer, each run through the real sandbox. One fixture can run
# under several policies, so the key is (fixture, policy name in POLICIES).
# -> (expected verdict, expected violations as a LIST: the same file can be
# caught more than once, text that must appear in the INCOMPLETE reasons)
POLICIES = {
    "notes_readonly": POLICY,
    "no_network.v1": PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml",
    "listed_domains_only.v1": PROJECT_ROOT / "policies" / "templates" / "listed_domains_only.v1.yaml",
}
CREDS = "/home/sandglass/.aws/credentials"
EXPECTED_HOSTILE = {
    # Reads the credentials through /proc/self/root and /proc/self/fd (#131).
    # Read anywhere but /home: each read is judged by the file really opened.
    ("proc_self_escape_server.py", "no_network.v1"): ("VIOLATIONS", [
        ("read", CREDS), ("read", CREDS), ("read", CREDS),
    ], []),
    # Notes only: the paths asked for are already outside the policy.
    ("proc_self_escape_server.py", "notes_readonly"): ("VIOLATIONS", [
        ("read", f"/proc/self/root{CREDS}"), ("read", CREDS), ("read", "/proc/self/fd/100"),
    ], []),
    # (#84) Sandglass's syscall filter. A clone(CLONE_UNTRACED) child would
    # read the credentials unseen; the clone is refused (a violation) and the
    # fallback child's read is seen.
    ("untraced_clone_server.py", "notes_readonly"): ("VIOLATIONS", [
        ("evade", "clone CLONE_UNTRACED"), ("read", CREDS),
    ], []),
    # Reads the credentials with io_uring enabled in libuv (UV_USE_IO_URING=1,
    # see FIXTURE_DOCKER_OPTIONS): io_uring is refused, so the read is seen.
    ("iouring_node_server.js", "notes_readonly"): ("VIOLATIONS", [("read", CREDS)], []),
    # ptrace and process_vm_readv/writev on its parent: all refused, all violations.
    ("ptrace_server.py", "notes_readonly"): ("VIOLATIONS", [
        ("evade", "ptrace PTRACE_ATTACH"), ("evade", "process_vm_readv"), ("evade", "process_vm_writev"),
    ], []),
    # (#136) Stalls a request to an allowed domain, queues one to hidden.example
    # behind it. The sink reads both side by side (and drains on exit), so
    # hidden.example is recorded; with the old sink this run was CLEAN.
    ("stall_sink_server.py", "listed_domains_only.v1"): ("VIOLATIONS", [("domain", "hidden.example")], []),
    ("stall_sink_server.py", "notes_readonly"): ("VIOLATIONS", [
        ("domain", "api.example.com"), ("domain", "hidden.example"),
    ], []),
}

# The requests the sink must record for a hostile fixture, in any order
# (others: none). (fixture, policy name) -> [(method, host, port)]
EXPECTED_HOSTILE_DOMAINS = {
    ("stall_sink_server.py", "listed_domains_only.v1"): [
        ("GET", "api.example.com", 80), ("CONNECT", "hidden.example", 443)],
    ("stall_sink_server.py", "notes_readonly"): [
        ("GET", "api.example.com", 80), ("CONNECT", "hidden.example", 443)],
}

# Extra `docker run` options for one fixture, in every run of it (test only).
FIXTURE_DOCKER_OPTIONS = {
    # Lets libuv use io_uring for file reads (off by default in recent libuv).
    "iouring_node_server.js": ["-e", "UV_USE_IO_URING=1"],
}

# (#84) The review's Docker 20.10 case, simulated: Docker's own seccomp
# profile turned OFF, so only Sandglass's filter stands between the server
# and io_uring / CLONE_UNTRACED. TEST CODE ONLY: this option must never
# appear in sandglass/ (tests/test_syscall_filter.py checks that).
# fixture -> (expected verdict, expected violations), under notes_readonly.
OLD_DOCKER_OPTIONS = ["--security-opt", "seccomp=unconfined"]
EXPECTED_OLD_DOCKER = {
    # Node's libuv uses io_uring at startup: refused, so CLEAN, not INCOMPLETE.
    "good_notes_node_server.js": ("CLEAN", []),
    "untraced_clone_server.py": ("VIOLATIONS", [("evade", "clone CLONE_UNTRACED"), ("read", CREDS)]),
    "iouring_node_server.js": ("VIOLATIONS", [("read", CREDS)]),
}


# (#140) A tool that hangs: it times out, the next tool is still called, and
# the stdin relay stops the server, which doesn't exit after eof (a stuck
# thread). Under notes_readonly, with the call timeout shortened to
# FIXTURE_CALL_TIMEOUT_SECONDS (test only; the product default stays 30 s).
# fixture -> (expected verdict, expected violations, coverage status of each
# tool, whether the report says Sandglass stopped the server)
FIXTURE_CALL_TIMEOUT_SECONDS = 3
EXPECTED_TIMEOUTS = {
    "hanging_tool_server.py": ("CLEAN", set(), {"hang": "timed out", "read_note": "ran"}, True),
}

# (#142) Normal runtime behaviour the python312_slim baseline covers, and its
# dangerous neighbours, through the real tracer. Under notes_readonly.
# fixture -> (expected verdict, expected violations, programs (argv, note)
# that "Programs run" must list). A listen()'s target is its fd and backlog,
# e.g. "8, 128"; the fd varies, so it's written "<fd>, 128" (see normalized).
UNAME_NOTE = "Python's platform module (platform.processor()) (baseline: python312_slim)"
# (#143) A tool that returned an error is shown next to the verdict, which
# itself doesn't change. Under notes_readonly.
# fixture -> (expected verdict, expected violations, expected coverage summary)
EXPECTED_COVERAGE_SUMMARY = {
    "tool_error_server.py": ("CLEAN", set(), "1 of 2 tools returned errors"),
}

# (#144) A server that needs an argument and an environment variable to start,
# and writes a file into its working directory (/tmp/work). The write is
# judged by the policy like any other. The env value is fake.
SETUP_ARGS = ["--note-name", "setup_note"]
SETUP_ENV = {"SETUP_TEST_TOKEN": "fake-token-for-tests"}
SETUP_POLICIES = {
    "no_network.v1": PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml",
    "read_only_folder.v1": PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml",
}
# (fixture, policy name, given the setup?) -> (expected verdict, expected
# violations, texts the INCOMPLETE reasons must mention)
EXPECTED_SERVER_SETUP = {
    ("setup_required_server.py", "no_network.v1", True): ("CLEAN", set(), []),
    ("setup_required_server.py", "read_only_folder.v1", True): (
        "VIOLATIONS", {("write", "/tmp/work/setup_note.txt")}, []),
    ("setup_required_server.py", "no_network.v1", False): (
        "INCOMPLETE", set(), ["needs the arguments --note-name setup_note"]),
}

# (#145) The input modes: a tool that only works with the example in its
# argument's description. Under notes_readonly.
# (fixture, --inputs mode) -> (expected verdict, expected violations, expected
# coverage summary (None: every tool ran), the timezone input and its source)
EXPECTED_INPUT_MODES = {
    ("described_input_server.py", "described"): (
        "CLEAN", set(), None, {"value": "America/New_York", "source": "param-description"}),
    ("described_input_server.py", "minimal"): (
        "CLEAN", set(), "1 of 1 tool returned errors", {"value": "hello", "source": "fallback"}),
}

EXPECTED_RUNTIME = {
    # /dev/null O_RDWR, the overcommit_memory read, bind ::1 port 0, uname -p.
    "runtime_noise_server.py": ("CLEAN", set(), [(["uname", "-p"], UNAME_NOTE)]),
    # A real port with listen(), `uname -a`, a write to /dev/zero: 4 violations.
    "runtime_neighbours_server.py": ("VIOLATIONS", {
        (None, '{sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}'),
        (None, "<fd>, 128"),
        (None, "/usr/bin/uname"),
        ("write", "/dev/zero"),
    }, [(["uname", "-a"], None)]),
}


def normalized(report: dict) -> dict:
    """The report with each listen()'s fd number replaced by <fd> (#142)."""
    violations = [{**v, "target": re.sub(r"^\d+, ", "<fd>, ", v["target"])}
                  if v.get("syscall") == "listen" else v for v in report["violations"]]
    return {**report, "violations": violations}


@contextlib.contextmanager
def call_timeout(seconds: float):
    """Shorten the per-tool timeout inside the `with` block. Test only."""
    original = client.CALL_TIMEOUT_SECONDS
    client.CALL_TIMEOUT_SECONDS = seconds
    try:
        yield
    finally:
        client.CALL_TIMEOUT_SECONDS = original


@contextlib.contextmanager
def docker_options(options: list[str]):
    """Add `docker run` options (before the image name) to every sandboxed
    run inside the `with` block. Test only: the product command is unchanged."""
    original = sandbox._traced_run_args

    def with_options(*args, **kwargs):
        run_args = original(*args, **kwargs)
        image = run_args.index(sandbox.IMAGE)
        return run_args[:image] + options + run_args[image:]

    sandbox._traced_run_args = with_options
    try:
        yield
    finally:
        sandbox._traced_run_args = original


# `sandglass scan` of our own test packages (#19), from the local test
# registry that scripts/build_test_packages.py builds (no network). Also v0.4,
# not protected yet. package spec -> (expected verdict, expected violations)
SCAN_POLICY = PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml"
TEST_REGISTRY = PROJECT_ROOT / "test_packages" / "dist"
EXPECTED_SCANS = {
    "pypi:sandglass-test-notes@1.0.0": ("CLEAN", set()),
    "npm:sandglass-test-notes@1.0.0": ("CLEAN", set()),
    # Tries to read Sandglass's project files; a scan doesn't mount them (#20).
    "pypi:sandglass-test-peek@1.0.0": ("CLEAN", set()),
    # A clean server whose npm postinstall script reads the decoy
    # ~/.aws/credentials: caught in the install phase (#16).
    "npm:sandglass-test-postinstall@1.0.0": ("VIOLATIONS", {
        ("read", "/home/sandglass/.aws/credentials"),
    }),
    # Its file doesn't match the hash its registry publishes (#21).
    "pypi:sandglass-test-tampered@1.0.0": ("INCOMPLETE", set()),
    # Hostile archives (#133), generated by build_test_packages.py: refused
    # on the host, member by member, before anything is unpacked or installed.
    "npm:sandglass-test-traversal@1.0.0": ("INCOMPLETE", set()),
    "pypi:sandglass-test-symlink@1.0.0": ("INCOMPLETE", set()),
    "pypi:sandglass-test-bomb@1.0.0": ("INCOMPLETE", set()),
}
# The phase a scan's violations must be in, if not "tool-call".
EXPECTED_SCAN_PHASES = {
    "npm:sandglass-test-postinstall@1.0.0": "install",
}
# Scans that must stop before anything is installed or run, and text their
# INCOMPLETE reasons must contain.
EXPECTED_SCAN_STOPPED = {
    # Its local registry publishes a wrong sha256 (#21).
    "pypi:sandglass-test-tampered@1.0.0": ["package hash mismatch", "not installed"],
    # Unsafe archives (#133): the member and why, then "not installed".
    "npm:sandglass-test-traversal@1.0.0": [
        "unsafe archive sandglass-test-traversal-1.0.0.tgz: member '../../sandglass-escaped-traversal.txt'"
        " is a path with a \"..\" component", "not installed"],
    "pypi:sandglass-test-symlink@1.0.0": [
        "member 'sandglass_test_symlink/notes.txt' is a symlink leading outside the archive", "not installed"],
    "pypi:sandglass-test-bomb@1.0.0": [
        "unsafe archive sandglass_test_bomb-1.0.0-py3-none-any.whl: more than 500 MB uncompressed",
        "not installed"],
}
# Failed attempts a scan must show: package spec -> set of (mode, path, errno).
EXPECTED_SCAN_ATTEMPTS = {
    "pypi:sandglass-test-peek@1.0.0": {
        ("read", "/project/guard", "ENOENT"),
        ("read", "/project/CLAUDE.md", "ENOENT"),
    },
}

# npm scans through the download container (#138): npm runs in a throwaway
# container, never on the host. Served from a LOCAL npm registry that this
# script starts itself in a private Docker network (local_npm_registry), never
# the real one. Added in #138. package spec -> (verdict, violations, INCOMPLETE
# reason texts; a scan with reasons must stop before anything is installed)
EXPECTED_NPM_REGISTRY_SCANS = {
    "npm:sandglass-test-notes@1.0.0": ("CLEAN", set(), []),
    # Unpacked by npm only inside the download container's /tmp; its cached
    # tarball is refused on the host, member by member (#133).
    "npm:sandglass-test-traversal@1.0.0": ("INCOMPLETE", set(), [
        "unsafe archive", "member '../../sandglass-escaped-traversal.txt' is a path with a \"..\" component",
        "not installed"]),
}
# What the download container may leave in the scan's temp folder: npm's
# cache, package.json and the lockfile. Never node_modules (npm's unpacked files).
NPM_DOWNLOAD_OUTPUT = ("npm-cache/", "project/package.json", "project/package-lock.json")


# The exit code of `sandglass ... --sandbox` and `sandglass scan` per verdict
# (#124). 2 is not a verdict: it's argparse's usage error.
EXPECTED_EXIT_CODES = {"CLEAN": 0, "VIOLATIONS": 1, "INCOMPLETE": 3}


def build_test_packages() -> None:
    """Build test_packages/dist/ (scripts/build_test_packages.py) before the scans."""
    path = Path(__file__).with_name("build_test_packages.py")
    spec = importlib.util.spec_from_file_location("build_test_packages", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build_all()


@contextlib.contextmanager
def local_npm_registry():
    """Serve test_packages/dist as an npm registry, for the download container (#138).

    A static HTTP server (Python's http.server, in the sandbox image, read-only,
    non-root) on a private Docker network. The download container joins that
    network and reaches it by name; the host reaches it on a 127.0.0.1 port
    for the hash check (#21). Yields what the download step saw: a list of
    (package, files the container left in the temp folder). Test code only:
    the product's defaults (the real registry, Docker's bridge) are restored after.
    """
    tag = f"{os.getpid()}"
    network, server = f"sandglass-test-npm-{tag}", f"sandglass-test-registry-{tag}"
    docker = shutil.which("docker") or "docker"
    root = Path(tempfile.mkdtemp(prefix="sandglass-test-registry-"))
    root.chmod(0o755)  # readable by the server's user (uid 10001)
    # The registry's layout: GET /<name> is the package's document (index.html
    # of a folder), /<name>/<version> one version's, /-/<file>.tgz the tarballs.
    (root / "-").mkdir()
    for meta in sorted((TEST_REGISTRY / "npm-meta").glob("*/*.json")):
        version_doc = json.loads(meta.read_text(encoding="utf-8"))
        name, version = version_doc["name"], version_doc["version"]
        tarball = npm_tarball_name(name, version)
        shutil.copy(TEST_REGISTRY / "npm" / tarball, root / "-" / tarball)
        version_doc["dist"]["tarball"] = f"http://{server}:8000/-/{tarball}"
        (root / name).mkdir()
        (root / name / version).write_text(json.dumps(version_doc), encoding="utf-8")
        (root / name / "index.html").write_text(json.dumps(
            {"name": name, "dist-tags": {"latest": version}, "versions": {version: version_doc}}),
            encoding="utf-8")
    for path in root.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)

    seen = []
    original = (scan.NPM_DOWNLOAD_REGISTRY, scan.NPM_DOWNLOAD_NETWORK, scan.NPM_VERSION_URL, scan.download)

    def watched_download(spec, folder, multiarch, registry_dir=None):
        try:
            return original[3](spec, folder, multiarch, registry_dir)
        finally:  # what reached the host, even if the scan stops here
            seen.append((str(spec), sorted(p.relative_to(folder).as_posix()
                                           for p in folder.rglob("*") if not p.is_dir())))

    try:
        subprocess.run([docker, "network", "create", network], check=True, capture_output=True)
        subprocess.run([docker, "run", "-d", "--rm", "--name", server, "--network", network,
                        "--read-only", "--user", sandbox.CONTAINER_USER, "--cap-drop", "ALL",
                        "-p", "127.0.0.1::8000", "-v", f"{root}:/srv:ro", sandbox.IMAGE,
                        "python", "-m", "http.server", "8000", "-d", "/srv"],
                       check=True, capture_output=True)
        port = subprocess.run([docker, "port", server, "8000/tcp"], check=True, capture_output=True,
                              text=True).stdout.split()[0].rsplit(":", 1)[1]
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):  # wait for the server to answer
            try:
                urllib.request.urlopen(f"{base}/-/", timeout=2).close()
                break
            except OSError:
                time.sleep(0.2)
        scan.NPM_DOWNLOAD_REGISTRY = f"http://{server}:8000/"
        scan.NPM_DOWNLOAD_NETWORK = network
        scan.NPM_VERSION_URL = base + "/{name}/{version}"
        scan.download = watched_download
        yield seen
    finally:
        (scan.NPM_DOWNLOAD_REGISTRY, scan.NPM_DOWNLOAD_NETWORK, scan.NPM_VERSION_URL,
         scan.download) = original
        subprocess.run([docker, "rm", "-f", server], capture_output=True)
        subprocess.run([docker, "network", "rm", network], capture_output=True)
        shutil.rmtree(root, ignore_errors=True)


def escaped_traversal_files() -> list[str]:
    """Where sandglass-test-traversal's "../../" member would land if anything
    on the host unpacked it: the temp folders and the project."""
    name = "sandglass-escaped-traversal.txt"
    places = [Path(tempfile.gettempdir()), PROJECT_ROOT, PROJECT_ROOT.parent, Path.cwd()]
    places += [p for p in Path(tempfile.gettempdir()).glob("sandglass-download-*") if p.is_dir()]
    return sorted({str(p / name) for p in places if (p / name).exists()})


def in_order(violations) -> list:
    """(mode, target) pairs in a fixed order. An exec's mode is None, which
    Python can't compare with a string mode, so it sorts as "" (#101)."""
    return sorted(violations, key=lambda v: (v[0] or "", v[1]))


def check(fixture: str, report: dict, want_verdict: str, want_violations: set,
          want_phase: str = "tool-call", server_ran: bool = True,
          want_domains: list | None = None) -> list[str]:
    """Every check that applies to every fixture; returns the failures."""
    failures = []
    print(f"{fixture}: {report['verdict']}, exit code {EXIT_CODES.get(report['verdict'])}")
    got = [(v["mode"], v["target"]) for v in report["violations"]]
    # Compare as a list too, so a duplicate violation (same read twice) fails.
    ok = report["verdict"] == want_verdict and in_order(got) == in_order(want_violations)
    if not ok:
        failures.append(f"{fixture}: expected {want_verdict} {in_order(want_violations)}, "
                        f"got {report['verdict']} {in_order(got)}")

    # Every fixture misbehaves only inside read_note, so every violation
    # must be in the tool-call phase (#18), e.g. overreach's decoy read.
    # (Except a package that misbehaves while it's installed: "install", #16.)
    wrong_phase = [(v["mode"], v["target"], v["phase"]) for v in report["violations"]
                   if v["phase"] != want_phase]
    if wrong_phase:
        failures.append(f"{fixture}: violations outside the {want_phase} phase: {wrong_phase}")

    # Every run: the sandbox must have no route out (the sink reported "isolated")...
    # (A scan stopped before its server ran, #21, must show it never ran.)
    isolation = report["network_isolation"]
    if not server_ran:
        if report.get("trace_file") is not None:
            failures.append(f"{fixture}: expected the server not to run, but it has a trace")
    elif not isolation or not isolation["isolated"]:
        failures.append(f"{fixture}: network isolation check did not report isolated: {isolation}")
    # ...and the sink logged exactly the requests we expect.
    domains = [(d["method"], d["host"], d["port"]) for d in report["domains"]]
    if want_domains is not None:
        # Hostile fixtures (#136): requests made side by side may be recorded in any order.
        if sorted(domains) != sorted(want_domains):
            failures.append(f"{fixture}: expected sink requests {sorted(want_domains)}, got {sorted(domains)}")
    elif domains != EXPECTED_DOMAINS.get(fixture, []):
        failures.append(f"{fixture}: expected sink requests {EXPECTED_DOMAINS.get(fixture, [])}, "
                        f"got {domains}")
    return failures


def main() -> int:
    failures = []
    # The exit code each verdict gives (#124); 2 stays argparse's usage error.
    if EXIT_CODES != EXPECTED_EXIT_CODES:
        failures.append(f"exit codes: expected {EXPECTED_EXIT_CODES}, got {EXIT_CODES}")
    for fixture, (want_verdict, want_violations) in EXPECTED.items():
        print(f"\n===== {fixture} =====")
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY)
        failures += check(fixture, report, want_verdict, want_violations)

    for fixture, (want_verdict, want_violations, want_reasons) in EXPECTED_V04.items():
        print(f"\n===== {fixture} =====")
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY)
        failures += check(fixture, report, want_verdict, want_violations)
        reasons = " | ".join(report.get("incomplete_reasons", []))
        failures += [f"{fixture}: INCOMPLETE reasons don't mention {text!r}: {reasons}"
                     for text in want_reasons if text not in reasons]

    for fixture, (policy, want_verdict, want_violations) in EXPECTED_POLICY_RUNS.items():
        print(f"\n===== {fixture} under {policy.name} =====")
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, policy)
        failures += check(f"{fixture} under {policy.name}", report, want_verdict, want_violations)

    for (fixture, policy_name), (want_verdict, want_violations, want_reasons) in EXPECTED_HOSTILE.items():
        label = f"{fixture} under {policy_name}"
        print(f"\n===== {label} =====")
        with docker_options(FIXTURE_DOCKER_OPTIONS.get(fixture, [])):
            report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICIES[policy_name])
        failures += check(label, report, want_verdict, want_violations,
                          want_domains=EXPECTED_HOSTILE_DOMAINS.get((fixture, policy_name), []))
        reasons = " | ".join(report.get("incomplete_reasons", []))
        failures += [f"{label}: INCOMPLETE reasons don't mention {text!r}: {reasons}"
                     for text in want_reasons if text not in reasons]

    for fixture, (want_verdict, want_violations) in EXPECTED_OLD_DOCKER.items():
        label = f"{fixture} with Docker's seccomp profile off (old-Docker simulation)"
        print(f"\n===== {label} =====")
        with docker_options(OLD_DOCKER_OPTIONS + FIXTURE_DOCKER_OPTIONS.get(fixture, [])):
            report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY)
        failures += check(label, report, want_verdict, want_violations)

    for fixture, (want_verdict, want_violations, want_programs) in EXPECTED_RUNTIME.items():
        print(f"\n===== {fixture} =====")
        report = normalized(run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY))
        failures += check(fixture, report, want_verdict, want_violations)
        programs = [(p["argv"], p["note"]) for p in report.get("programs", [])]
        failures += [f"{fixture}: expected the program run {argv} with note {note!r}, got {programs}"
                     for argv, note in want_programs if (argv, note) not in programs]

    for fixture, (want_verdict, want_violations, want_coverage, want_stopped) in EXPECTED_TIMEOUTS.items():
        print(f"\n===== {fixture} (call timeout {FIXTURE_CALL_TIMEOUT_SECONDS} s) =====")
        with call_timeout(FIXTURE_CALL_TIMEOUT_SECONDS):
            report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY)
        failures += check(fixture, report, want_verdict, want_violations)
        got_coverage = {row["tool"]: row["status"]
                        for row in (report.get("coverage") or {}).get("tools", [])}
        if got_coverage != want_coverage:
            failures.append(f"{fixture}: expected coverage {want_coverage}, got {got_coverage}")
        if bool(report.get("server_stopped_note")) != want_stopped:
            failures.append(f"{fixture}: expected server stopped by Sandglass: {want_stopped}, "
                            f"got note {report.get('server_stopped_note')!r}")

    for fixture, (want_verdict, want_violations, want_summary) in EXPECTED_COVERAGE_SUMMARY.items():
        print(f"\n===== {fixture} =====")
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY)
        failures += check(fixture, report, want_verdict, want_violations)
        if report.get("coverage_summary") != want_summary:
            failures.append(f"{fixture}: expected coverage summary {want_summary!r}, "
                            f"got {report.get('coverage_summary')!r}")

    for (fixture, mode), (want_verdict, want_violations, want_summary, want_input) \
            in EXPECTED_INPUT_MODES.items():
        label = f"{fixture} with --inputs {mode}"
        print(f"\n===== {label} =====")
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY, [], {}, mode)
        failures += check(label, report, want_verdict, want_violations)
        if report.get("coverage_summary") != want_summary:
            failures.append(f"{label}: expected coverage summary {want_summary!r}, "
                            f"got {report.get('coverage_summary')!r}")
        got_input = (report.get("inputs") or {}).get("timezone_offset", {}).get("timezone")
        if report.get("input_mode") != mode or got_input != want_input:
            failures.append(f"{label}: expected mode {mode} and input {want_input}, "
                            f"got {report.get('input_mode')} {got_input}")

    for (fixture, policy_name, with_setup), (want_verdict, want_violations, want_reasons) \
            in EXPECTED_SERVER_SETUP.items():
        label = f"{fixture} under {policy_name}, {'with' if with_setup else 'without'} its setup"
        print(f"\n===== {label} =====")
        args, env = (SETUP_ARGS, SETUP_ENV) if with_setup else ([], {})
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, SETUP_POLICIES[policy_name], args, env)
        failures += check(label, report, want_verdict, want_violations)
        reasons = " | ".join(report.get("incomplete_reasons", []))
        failures += [f"{label}: INCOMPLETE reasons don't mention {text!r}: {reasons}"
                     for text in want_reasons if text not in reasons]
        # The report names the env variables but never records a value.
        setup = report.get("server_setup") or {}
        if setup.get("args") != args or setup.get("env") != list(env):
            failures.append(f"{label}: expected server setup {args} {list(env)}, got {setup}")
        if any(value in json.dumps(report) for value in env.values()):
            failures.append(f"{label}: an --env value appears in the report")

    build_test_packages()
    for package, (want_verdict, want_violations) in EXPECTED_SCANS.items():
        print(f"\n===== scan {package} =====")
        report = run_scan(parse_spec(package), SCAN_POLICY, TEST_REGISTRY)
        stopped = EXPECTED_SCAN_STOPPED.get(package)
        failures += check(package, report, want_verdict, want_violations,
                          EXPECTED_SCAN_PHASES.get(package, "tool-call"), server_ran=stopped is None)
        reasons = " | ".join(report.get("incomplete_reasons", []))
        failures += [f"{package}: INCOMPLETE reasons don't mention {text!r}: {reasons}"
                     for text in stopped or [] if text not in reasons]
        attempts = {(a["mode"], a["target"], a["error"]) for a in report.get("attempted", [])}
        missing = EXPECTED_SCAN_ATTEMPTS.get(package, set()) - attempts
        if missing:
            failures.append(f"{package}: expected failed attempts {sorted(missing)} are missing")

    # npm through the download container (#138), from a local registry.
    with local_npm_registry() as downloads:
        for package, (want_verdict, want_violations, want_reasons) in EXPECTED_NPM_REGISTRY_SCANS.items():
            label = f"{package} (download container, local npm registry)"
            print(f"\n===== scan {label} =====")
            report = run_scan(parse_spec(package), SCAN_POLICY, None)
            failures += check(label, report, want_verdict, want_violations, server_ran=not want_reasons)
            reasons = " | ".join(report.get("incomplete_reasons", []))
            failures += [f"{label}: INCOMPLETE reasons don't mention {text!r}: {reasons}"
                         for text in want_reasons if text not in reasons]
            if not want_reasons and not (report.get("package", {}).get("hash") or {}).get("match"):
                failures.append(f"{label}: the hash check did not match: {report.get('package', {}).get('hash')}")
    for package, files in downloads:
        unexpected = [f for f in files if not f.startswith(NPM_DOWNLOAD_OUTPUT)]
        if unexpected or "project/package-lock.json" not in files:
            failures.append(f"{package}: the download container left {unexpected or 'no lockfile'} on the host")
    if len(downloads) != len(EXPECTED_NPM_REGISTRY_SCANS):
        failures.append(f"expected {len(EXPECTED_NPM_REGISTRY_SCANS)} npm downloads, saw {len(downloads)}")
    escaped = escaped_traversal_files()
    if escaped:
        failures.append(f"sandglass-test-traversal wrote outside its folder on the host: {escaped}")

    print("\n===== summary =====")
    for line in failures:
        print("FAIL", line)
    if not failures:
        total = (len(EXPECTED) + len(EXPECTED_V04) + len(EXPECTED_POLICY_RUNS) + len(EXPECTED_HOSTILE)
                 + len(EXPECTED_OLD_DOCKER) + len(EXPECTED_TIMEOUTS) + len(EXPECTED_RUNTIME)
                 + len(EXPECTED_COVERAGE_SUMMARY) + len(EXPECTED_SERVER_SETUP) + len(EXPECTED_INPUT_MODES)
                 + len(EXPECTED_SCANS) + len(EXPECTED_NPM_REGISTRY_SCANS))
        print(f"all {total} fixtures match expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
