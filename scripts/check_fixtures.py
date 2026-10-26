"""Run every fixture in the sandbox and check its verdict and exact violations.

Also builds our own test packages (test_packages/ -> test_packages/dist/) and
scans them with `sandglass scan` from that local folder (#19), no network.

Used before opening a PR and by the CI sandbox job. Exits 0 only if every
fixture matches its expectation exactly.

    docker build -t sandglass-sandbox .
    uv run python scripts/check_fixtures.py
"""

import importlib.util
import sys
from pathlib import Path

from sandglass import PROJECT_ROOT
from sandglass.client import EXIT_CODES, run_sandboxed, run_scan
from sandglass.scan import parse_spec

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
}


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
}
# Failed attempts a scan must show: package spec -> set of (mode, path, errno).
EXPECTED_SCAN_ATTEMPTS = {
    "pypi:sandglass-test-peek@1.0.0": {
        ("read", "/project/guard", "ENOENT"),
        ("read", "/project/CLAUDE.md", "ENOENT"),
    },
}


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


def in_order(violations) -> list:
    """(mode, target) pairs in a fixed order. An exec's mode is None, which
    Python can't compare with a string mode, so it sorts as "" (#101)."""
    return sorted(violations, key=lambda v: (v[0] or "", v[1]))


def check(fixture: str, report: dict, want_verdict: str, want_violations: set,
          want_phase: str = "tool-call", server_ran: bool = True) -> list[str]:
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
    if domains != EXPECTED_DOMAINS.get(fixture, []):
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
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICIES[policy_name])
        failures += check(label, report, want_verdict, want_violations)
        reasons = " | ".join(report.get("incomplete_reasons", []))
        failures += [f"{label}: INCOMPLETE reasons don't mention {text!r}: {reasons}"
                     for text in want_reasons if text not in reasons]

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

    print("\n===== summary =====")
    for line in failures:
        print("FAIL", line)
    if not failures:
        total = (len(EXPECTED) + len(EXPECTED_V04) + len(EXPECTED_POLICY_RUNS) + len(EXPECTED_HOSTILE)
                 + len(EXPECTED_SCANS))
        print(f"all {total} fixtures match expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
