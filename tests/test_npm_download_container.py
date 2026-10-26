"""The npm download container (#138): npm never runs or unpacks on the host.

These tests check the `docker run` command line and what the host does with
the container's output, without Docker (subprocess.run is replaced). The
end-to-end check against a local npm registry is in scripts/check_fixtures.py
(EXPECTED_NPM_REGISTRY_SCANS), which needs the sandbox image.
"""

import json
import shutil
from pathlib import Path

import pytest

from sandglass import PROJECT_ROOT, sandbox, scan
from sandglass.scan import ScanError, parse_spec
from tests.test_scan import build_test_packages

NOTES = parse_spec("npm:sandglass-test-notes@1.0.0")


def _args(tmp_path):
    docker, args = scan.npm_download_container_command(NOTES, tmp_path)
    return args


def _value(args, flag):
    """Every value given to a flag ("--user", "-v", ...)."""
    return [args[i + 1] for i, arg in enumerate(args) if arg == flag]


# --- the command line ------------------------------------------------------------

def test_runs_as_the_non_root_sandbox_user(tmp_path):
    args = _args(tmp_path)
    assert _value(args, "--user") == ["10001:10001"]
    # Plus the output folder's own group (the host user's), so it can write
    # there without the folder being writable for every user.
    assert _value(args, "--group-add") == [str(tmp_path.stat().st_gid)]


def test_read_only_root_and_no_extra_privileges(tmp_path):
    args = _args(tmp_path)
    assert "--read-only" in args
    assert "--privileged" not in args and "--cap-add" not in args
    assert _value(args, "--cap-drop") == ["ALL"]
    assert _value(args, "--security-opt") == ["no-new-privileges"]
    assert not any("seccomp=unconfined" in arg for arg in args)


def test_npm_runs_with_ignore_scripts(tmp_path):
    args = _args(tmp_path)
    npm = args[args.index("sandglass-download") + 1:]
    assert npm[:2] == ["npm", "install"] and "--ignore-scripts" in npm
    assert "--no-audit" in npm and "--no-fund" in npm
    assert npm[-1] == "sandglass-test-notes@1.0.0"
    # And install scripts off a second way, in npm's environment.
    assert "npm_config_ignore_scripts=true" in _value(args, "-e")


def test_only_the_output_folder_is_writable(tmp_path):
    args = _args(tmp_path)
    # One mount: the scan's own temp folder at /out. No --mount, no other -v.
    assert _value(args, "-v") == [f"{tmp_path}:/out"]
    assert "--mount" not in args and "--volume" not in args
    # Plus the container's own scratch /tmp, in memory, where nothing can be run.
    assert _value(args, "--tmpfs") == ["/tmp:rw,noexec,nosuid"]


def test_the_project_is_not_mounted_and_home_is_empty(tmp_path):
    args = _args(tmp_path)
    assert not any(str(PROJECT_ROOT) in arg for arg in args)
    assert "/project" not in " ".join(_value(args, "-v"))
    # An empty HOME in /tmp: not the decoy home, never the host's.
    assert "HOME=/tmp/home" in _value(args, "-e")
    assert f"HOME={sandbox.CONTAINER_HOME}" not in _value(args, "-e")


def test_network_only_here_and_the_sandbox_stays_offline(tmp_path):
    assert _value(_args(tmp_path), "--network") == ["bridge"]  # Docker's default network
    # The analysis sandbox is unchanged: the install and the server are offline.
    _, install = sandbox.scan_install_command("vol", tmp_path, "true", [])
    _, run = sandbox.scan_run_command("vol", "/package/x", "node")
    assert _value(install, "--network") == ["none"] and _value(run, "--network") == ["none"]


def test_npm_unpacks_inside_the_container_only():
    # npm runs in the container's /tmp/project; only package.json and the
    # lockfile are copied to /out, never node_modules.
    script = scan.NPM_DOWNLOAD_SCRIPT
    assert "cd /tmp/project" in script
    assert "cp package.json package-lock.json /out/project/" in script
    assert "node_modules" not in script
    # What it writes to /out: no one but its user and the folder's group can change it.
    assert script.startswith("umask 007;") and "o-w" in script


def test_the_output_folder_is_not_writable_for_other_users(registry, monkeypatch, tmp_path):
    monkeypatch.setattr(scan.subprocess, "run", _fake_container(registry, "sandglass-test-notes"))
    scan.download(NOTES, tmp_path, "x86_64-linux-gnu", None)
    mode = tmp_path.stat().st_mode
    assert mode & 0o002 == 0 and mode & 0o020 and mode & 0o2000  # o-w, g+w, setgid


def test_a_test_registry_is_passed_to_npm(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "NPM_DOWNLOAD_REGISTRY", "http://registry.test:8000/")
    monkeypatch.setattr(scan, "NPM_DOWNLOAD_NETWORK", "sandglass-test-net")
    args = _args(tmp_path)
    assert "--registry" in args and args[args.index("--registry") + 1] == "http://registry.test:8000/"
    assert _value(args, "--network") == ["sandglass-test-net"]


# --- what the host does with the output --------------------------------------------

@pytest.fixture(scope="module")
def registry():
    build_test_packages.build_all()
    return build_test_packages.DIST


def _fake_container(registry: Path, name: str, extra=None):
    """A stand-in for `docker run`: writes what the real container leaves in
    /out (lockfile + cache content file), from the local test registry."""
    def run(command, **kwargs):
        out = Path(command[command.index("-v") + 1].split(":")[0])
        (out / "project").mkdir()
        tarball = registry / "npm" / scan.npm_tarball_name(name, "1.0.0")
        integrity = json.loads((registry / "npm-meta" / name / "1.0.0.json").read_text())["dist"]["integrity"]
        lock = {"packages": {"": {"name": "sandglass-scan"},
                             f"node_modules/{name}": {"version": "1.0.0", "integrity": integrity}}}
        (out / "project" / "package-lock.json").write_text(json.dumps(lock))
        content = scan.cache_content_path(out / "npm-cache", integrity)
        content.parent.mkdir(parents=True)
        shutil.copy(tarball, content)
        if extra:
            extra(out)

        class Done:
            returncode, stdout, stderr = 0, "", ""
        return Done()
    return run


def test_every_cached_tarball_is_checked_on_the_host(registry, monkeypatch, tmp_path):
    checked = []
    monkeypatch.setattr(scan.subprocess, "run", _fake_container(registry, "sandglass-test-notes"))
    monkeypatch.setattr(scan, "check_archive", lambda path: checked.append(Path(path)))
    prepared = scan.download(NOTES, tmp_path, "x86_64-linux-gnu", None)
    assert checked == [prepared.artifact] and prepared.files == [prepared.artifact]
    assert prepared.labels[prepared.artifact] == "sandglass-test-notes@1.0.0 (npm cache)"
    assert set(prepared.entries) == {"sandglass-test-notes"}


def test_a_hostile_tarball_from_the_registry_is_refused(registry, monkeypatch, tmp_path):
    traversal = parse_spec("npm:sandglass-test-traversal@1.0.0")
    monkeypatch.setattr(scan.subprocess, "run", _fake_container(registry, "sandglass-test-traversal"))
    with pytest.raises(ScanError, match=r"unsafe archive .*'\.\./\.\./sandglass-escaped-traversal\.txt'"):
        scan.download(traversal, tmp_path, "x86_64-linux-gnu", None)


def test_a_symlinked_lockfile_is_not_followed(registry, monkeypatch, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    folder = tmp_path / "download"
    folder.mkdir()

    def link_lockfile(out):
        (out / "project" / "package-lock.json").unlink()
        (out / "project" / "package-lock.json").symlink_to(outside)
    monkeypatch.setattr(scan.subprocess, "run",
                        _fake_container(registry, "sandglass-test-notes", link_lockfile))
    with pytest.raises(ScanError, match="no package-lock.json"):
        scan.download(NOTES, folder, "x86_64-linux-gnu", None)


def test_a_failed_download_is_a_scan_error(monkeypatch, tmp_path):
    class Failed:
        returncode, stdout, stderr = 1, "", "npm error 404 Not Found"
    monkeypatch.setattr(scan.subprocess, "run", lambda command, **k: Failed())
    with pytest.raises(ScanError, match="download container.*404 Not Found"):
        scan.download(NOTES, tmp_path, "x86_64-linux-gnu", None)


def test_a_download_that_runs_too_long_is_removed(monkeypatch, tmp_path):
    removed = []

    def too_long(command, **kwargs):
        raise scan.subprocess.TimeoutExpired(command, 1)
    monkeypatch.setattr(scan.subprocess, "run", too_long)
    monkeypatch.setattr(sandbox, "remove_container", removed.append)
    with pytest.raises(ScanError, match="longer than"):
        scan.download(NOTES, tmp_path, "x86_64-linux-gnu", None)
    assert len(removed) == 1 and removed[0].endswith("-npm")


def test_the_registry_dir_fast_path_starts_no_container(registry, monkeypatch, tmp_path):
    # Our own test packages (--registry-dir): copied from the local folder, no npm, no Docker.
    monkeypatch.setattr(scan.subprocess, "run", lambda *a, **k: pytest.fail("no container"))
    prepared = scan.download(NOTES, tmp_path, "x86_64-linux-gnu", registry)
    assert prepared.artifact.name == "sandglass-test-notes-1.0.0.tgz"
