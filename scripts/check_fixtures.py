"""Run every fixture in the sandbox and check its verdict and exact violations.

Used before opening a PR and by the CI sandbox job. Exits 0 only if every
fixture matches its expectation exactly.

    docker build -t sandglass-sandbox .
    uv run python scripts/check_fixtures.py
"""

import sys

from sandglass import PROJECT_ROOT
from sandglass.client import run_sandboxed

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


def in_order(violations) -> list:
    """(mode, target) pairs in a fixed order. An exec's mode is None, which
    Python can't compare with a string mode, so it sorts as "" (#101)."""
    return sorted(violations, key=lambda v: (v[0] or "", v[1]))


def main() -> int:
    failures = []
    for fixture, (want_verdict, want_violations) in EXPECTED.items():
        print(f"\n===== {fixture} =====")
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY)
        got = [(v["mode"], v["target"]) for v in report["violations"]]
        # Compare as a list too, so a duplicate violation (same read twice) fails.
        ok = report["verdict"] == want_verdict and in_order(got) == in_order(want_violations)
        if not ok:
            failures.append(f"{fixture}: expected {want_verdict} {in_order(want_violations)}, "
                            f"got {report['verdict']} {in_order(got)}")

        # Every fixture misbehaves only inside read_note, so every violation
        # must be in the tool-call phase (#18), e.g. overreach's decoy read.
        wrong_phase = [(v["mode"], v["target"], v["phase"]) for v in report["violations"]
                       if v["phase"] != "tool-call"]
        if wrong_phase:
            failures.append(f"{fixture}: violations outside the tool-call phase: {wrong_phase}")

        # Every run: the sandbox must have no route out (the sink reported "isolated")...
        isolation = report["network_isolation"]
        if not isolation or not isolation["isolated"]:
            failures.append(f"{fixture}: network isolation check did not report isolated: {isolation}")
        # ...and the sink logged exactly the requests we expect.
        domains = [(d["method"], d["host"], d["port"]) for d in report["domains"]]
        if domains != EXPECTED_DOMAINS.get(fixture, []):
            failures.append(f"{fixture}: expected sink requests {EXPECTED_DOMAINS.get(fixture, [])}, "
                            f"got {domains}")

    print("\n===== summary =====")
    for line in failures:
        print("FAIL", line)
    if not failures:
        print(f"all {len(EXPECTED)} fixtures match expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
