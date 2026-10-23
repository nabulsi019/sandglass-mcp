"""read_deny (#121): a read under it is a violation whatever allows it. Deny wins.

Hand-written traces, no Docker. The policy is notes_readonly with a
read_deny added, so every allow-list (read_allow, runtime_allow, the
baseline) can be tested against it.
"""

import pytest

from sandglass.compare import compare_install
from sandglass.policy import PolicyError, load_install_baseline, load_policy
from sandglass.trace_parser import parse_trace
from tests.test_install import DONE, START
from tests.test_policy import real_policy, write
from tests.test_sandbox_pipeline import EXITED, LAUNCH, SERVER, run


def policy_with_deny(tmp_path, deny):
    data = real_policy()
    data["filesystem"]["read_deny"] = deny
    return load_policy(write(tmp_path, data), server_script=SERVER, in_sandbox=True,
                       multiarch="x86_64-linux-gnu")


def read(path, flags="O_RDONLY|O_CLOEXEC"):
    return f'8 10:00:00.2 openat(AT_FDCWD, "{path}", {flags}) = 3'


def found(result):
    return [(v["mode"], v["target"], v["reason"]) for v in result["violations"]]


@pytest.mark.parametrize("deny, path, allowed_by", [
    (["test_servers/allowed_notes/secret.txt"], "/project/test_servers/allowed_notes/secret.txt", "read_allow"),
    (["/opt/venv/lib"], "/opt/venv/lib/python3.12/site-packages/x.py", "runtime_allow {venv}"),
    (["/etc/ld.so.cache"], "/etc/ld.so.cache", "the baseline"),
])
def test_deny_wins_over_every_allow_list(tmp_path, deny, path, allowed_by):
    # Allowed without read_deny...
    assert run([LAUNCH, read(path), EXITED], policy=policy_with_deny(tmp_path, []))["verdict"] == "CLEAN"
    # ...a violation with it, saying why.
    result = run([LAUNCH, read(path), EXITED], policy=policy_with_deny(tmp_path, deny))
    assert found(result) == [("read", path, "read matches read_deny")], allowed_by


def test_deny_covers_listings_and_shows_probes(tmp_path):
    policy = policy_with_deny(tmp_path, ["/opt/venv"])
    listing = read("/opt/venv/lib", "O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY")
    probe = '8 10:00:00.3 newfstatat(AT_FDCWD, "/opt/venv/lib/x.py", {st_mode=S_IFREG|0644, st_size=1, ...}, 0) = 0'
    result = run([LAUNCH, listing, probe, EXITED], policy=policy)
    assert found(result) == [("list", "/opt/venv/lib", "list matches read_deny")]
    assert [p["path"] for p in result["probes"]] == ["/opt/venv/lib/x.py"]


def test_a_failed_read_under_deny_is_still_only_attempted(tmp_path):
    # Same failure rules as any other file: ENOENT -> attempted.
    missing = '8 10:00:00.2 openat(AT_FDCWD, "/opt/venv/x", O_RDONLY) = -1 ENOENT (No such file or directory)'
    result = run([LAUNCH, missing, EXITED], policy=policy_with_deny(tmp_path, ["/opt/venv"]))
    assert result["verdict"] == "CLEAN" and [a["target"] for a in result["attempted"]] == ["/opt/venv/x"]


def test_relative_deny_paths_resolve_like_read_allow(tmp_path):
    policy = policy_with_deny(tmp_path, ["test_servers/decoy_home"])
    assert [str(p) for p in policy.read_deny] == ["/project/test_servers/decoy_home"]


def test_read_deny_is_optional_and_must_be_a_list_of_strings(tmp_path):
    assert policy_with_deny(tmp_path, []).read_deny == []
    data = real_policy()
    data["filesystem"]["read_deny"] = "/home"
    with pytest.raises(PolicyError, match="filesystem.read_deny"):
        load_policy(write(tmp_path, data), server_script=SERVER)
    del data["filesystem"]["read_deny"]
    assert load_policy(write(tmp_path, data), server_script=SERVER).read_deny == []


def test_deny_applies_to_the_install_phase_too(tmp_path):
    # The install baseline allows reading npm's own files; denied, they count.
    data = real_policy()
    data["filesystem"]["read_deny"] = ["/usr/share/nodejs/npm"]
    policy = load_policy(write(tmp_path, data), in_sandbox=True, multiarch="x86_64-linux-gnu",
                         container_script="/package/x/server.js", package_dir="/package")
    line = ('9     10:00:00.4 openat(AT_FDCWD</package>, "/usr/share/nodejs/npm/lib/cli.js", '
            'O_RDONLY|O_CLOEXEC) = 17</usr/share/nodejs/npm/lib/cli.js>')
    events = parse_trace("\n".join([START, line, DONE]), cwd="/package")
    result = compare_install(events, policy, load_install_baseline("x86_64-linux-gnu"), 0)
    assert found(result) == [("read", "/usr/share/nodejs/npm/lib/cli.js", "install read matches read_deny")]
