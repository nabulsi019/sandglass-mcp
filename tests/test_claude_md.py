"""CLAUDE.md's protected items (#102): complete, and still true of the code.

Claude may merge PRs that change none of the protected items, so the list
must name every safeguard, and each one must still exist where it says.
"""

import importlib.util

from sandglass import PROJECT_ROOT, sandbox

CLAUDE_MD = (PROJECT_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
# The merge rule, up to "After every merge" (where the protected list ends).
PROTECTED = CLAUDE_MD[CLAUDE_MD.index("**Merging**"):CLAUDE_MD.index("After every merge")]

spec = importlib.util.spec_from_file_location("check_fixtures", PROJECT_ROOT / "scripts" / "check_fixtures.py")
check_fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_fixtures)


def test_every_fixture_expectation_is_protected():
    assert "`EXPECTED`" in PROTECTED and "`EXPECTED_DOMAINS`" in PROTECTED
    for fixture in list(check_fixtures.EXPECTED) + list(check_fixtures.EXPECTED_DOMAINS):
        name = fixture.removesuffix(".py")
        assert name in PROTECTED, f"{fixture} is not in CLAUDE.md's protected items"


def test_every_v04_expectation_is_protected():
    # The v0.4 dicts (#119): every one named, and every entry in them.
    dicts = ("EXPECTED_V04", "EXPECTED_SCANS", "EXPECTED_SCAN_PHASES",
             "EXPECTED_SCAN_STOPPED", "EXPECTED_SCAN_ATTEMPTS")
    for name in dicts:
        assert f"`{name}`" in PROTECTED, f"{name} is not in CLAUDE.md's protected items"
        for fixture in getattr(check_fixtures, name):
            # "pypi:sandglass-test-notes@1.0.0" is named without its version.
            short = fixture.removesuffix(".py").split("@")[0]
            assert short in PROTECTED, f"{name} entry {fixture} is not in CLAUDE.md's protected items"


def test_every_expectation_dict_is_protected():
    # A new EXPECTED_* dict must be added to the protected list too.
    for name in dir(check_fixtures):
        if name.startswith("EXPECTED"):
            assert f"`{name}`" in PROTECTED, f"{name} is not in CLAUDE.md's protected items"


def test_trace_integrity_hardening_is_protected():
    for item in ("--network none", "--read-only", "non-root", "--cap-add",
                 "chmod 0711 /usr/bin/strace", "read-only tmpfs over `reports/`",
                 "os.dup2(3, 2)", "os.close(3)", "HOME=/home/sandglass", "sandbox/decoy_home/",
                 "required checks", "ruleset"):
        assert item in PROTECTED, f"{item!r} is not in CLAUDE.md's protected items"


def test_the_protected_hardening_still_exists_in_the_code():
    # If one of these moves, CLAUDE.md must be updated with it.
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "chmod 0711 /usr/bin/strace" in dockerfile
    assert "COPY --chown=10001:10001 sandbox/decoy_home/ /home/sandglass/" in dockerfile
    args = " ".join(sandbox.docker_command(sandbox.PROJECT_ROOT / "test_servers" / "good_notes_server.py")[1])
    assert "type=tmpfs,destination=/project/reports,tmpfs-mode=0555" in args
    assert "-e HOME=/home/sandglass" in args
    assert "os.dup2(3, 2)" in sandbox.LAUNCHER and "os.close(3)" in sandbox.LAUNCHER
