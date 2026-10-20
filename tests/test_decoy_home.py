"""The decoy $HOME baked into the sandbox image (sandbox/decoy_home/).

It must hold the files a credential-stealing server looks for, with only
obviously fake values, and the host's real home must never be mounted.
"""

from pathlib import Path

from sandglass import PROJECT_ROOT, sandbox

DECOY_HOME = PROJECT_ROOT / "sandbox" / "decoy_home"
DECOY_FILES = [".aws/credentials", ".ssh/id_rsa", ".env"]
SERVER = PROJECT_ROOT / "test_servers" / "good_notes_server.py"


def values(path: Path) -> list[str]:
    """Every non-comment, non-section line, reduced to its value part."""
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        # "key = value", "KEY=value", or a bare value (the fake id_rsa)
        out.append(line.split("=", 1)[-1].strip())
    return out


def test_decoy_files_exist():
    for name in DECOY_FILES:
        assert (DECOY_HOME / name).is_file(), name


def test_decoy_files_hold_only_fake_values():
    for name in DECOY_FILES:
        found = values(DECOY_HOME / name)
        assert found, f"{name} has no values"
        assert all(v.startswith("FAKE_") for v in found), (name, found)
        # Says so in plain words, for anyone who opens it.
        assert "DECOY FILE" in (DECOY_HOME / name).read_text()


def test_no_private_key_block():
    # A real-looking PEM block could trip secret scanners or be mistaken for a key.
    assert "BEGIN" not in (DECOY_HOME / ".ssh" / "id_rsa").read_text()


def test_docker_command_sets_decoy_home_and_never_mounts_host_home():
    _, args = sandbox.docker_command(SERVER)
    assert "HOME=/home/sandglass" in [args[i + 1] for i, a in enumerate(args) if a == "-e"]
    # The only bind mount is the project, read-only. (On a Mac the project
    # itself usually lives under the home folder; nothing else from it does.)
    volumes = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
    assert volumes == [f"{PROJECT_ROOT}:/project:ro"]
    home = str(Path.home())
    for arg in args:
        if home in arg:
            assert arg == f"{PROJECT_ROOT}:/project:ro", arg
    # --mount is only used for the empty reports/ tmpfs.
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "--mount"]
    assert all(m.startswith("type=tmpfs,") for m in mounts)
