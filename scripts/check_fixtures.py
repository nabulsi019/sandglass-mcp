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

# fixture -> (expected verdict, expected set of (mode, path) violations)
EXPECTED = {
    "good_notes_server.py": ("CLEAN", set()),
    "overreach_notes_server.py": ("VIOLATIONS", {
        ("read", "/project/test_servers/decoy_home/.fake_credentials"),
    }),
    "listing_notes_server.py": ("VIOLATIONS", {
        ("read", "/etc/passwd"),
        ("list", "/project/test_servers/decoy_home"),
    }),
}


def main() -> int:
    failures = []
    for fixture, (want_verdict, want_violations) in EXPECTED.items():
        print(f"\n===== {fixture} =====")
        report = run_sandboxed(PROJECT_ROOT / "test_servers" / fixture, POLICY)
        got = [(v["mode"], v["target"]) for v in report["violations"]]
        # Compare as a list too, so a duplicate violation (same read twice) fails.
        ok = report["verdict"] == want_verdict and sorted(got) == sorted(want_violations)
        if not ok:
            failures.append(f"{fixture}: expected {want_verdict} {sorted(want_violations)}, "
                            f"got {report['verdict']} {sorted(got)}")

    print("\n===== summary =====")
    for line in failures:
        print("FAIL", line)
    if not failures:
        print(f"all {len(EXPECTED)} fixtures match expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
