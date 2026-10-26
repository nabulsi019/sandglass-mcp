"""Archives on the host (#133): checked member by member, never unpacked.

`sandglass scan` downloads packages on the owner's machine before anything is
sandboxed, so an archive built to escape its folder (a "../" or absolute
member, a symlink out, a device, a zip bomb) must stop the scan there:
INCOMPLETE with the reason, and nothing written outside the scan's temp folder.
No Docker, no network.
"""

import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from sandglass import scan
from sandglass.scan import ScanError, check_archive, parse_spec
from tests.test_scan import build_test_packages


def make_tar(path: Path, members: list[tarfile.TarInfo]) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for info in members:
            data = b"x" * info.size if info.isfile() else None
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def member(name: str, kind=tarfile.REGTYPE, linkname: str = "", size: int = 1) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, linkname
    info.size = size if kind == tarfile.REGTYPE else 0
    return info


def make_zip(path: Path, members: list[tuple[str, int, bytes]]) -> Path:
    """(name, unix mode with file type, content) per member."""
    with zipfile.ZipFile(path, "w") as z:
        for name, mode, data in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            z.writestr(info, data)
    return path


# --- check_archive: what is refused ---------------------------------------------

@pytest.mark.parametrize("bad, why", [
    (member("package/../../evil.txt"), 'a ".." component'),
    (member("/tmp/evil.txt"), "an absolute path"),
    (member("package/link", tarfile.SYMTYPE, "../../home/sandglass/.aws/credentials"), "symlink leading outside"),
    (member("package/link", tarfile.SYMTYPE, "/etc/passwd"), "symlink leading outside"),
    (member("package/hard", tarfile.LNKTYPE, "../outside"), "hardlink leading outside"),
    (member("package/hard", tarfile.LNKTYPE, "/etc/passwd"), "hardlink leading outside"),
    (member("package/dev", tarfile.CHRTYPE), "a device or fifo"),
    (member("package/dev", tarfile.BLKTYPE), "a device or fifo"),
    (member("package/fifo", tarfile.FIFOTYPE), "a device or fifo"),
])
def test_unsafe_tar_members_are_refused(tmp_path, bad, why):
    archive = make_tar(tmp_path / "x.tgz", [member("package/package.json"), bad])
    with pytest.raises(ScanError, match="unsafe archive x.tgz") as exc:
        check_archive(archive)
    assert why in str(exc.value)


def test_links_inside_the_archive_are_fine(tmp_path):
    archive = make_tar(tmp_path / "ok.tgz", [
        member("package/a.txt"),
        member("package/lib/link", tarfile.SYMTYPE, "../a.txt"),     # stays in package/
        member("package/hard", tarfile.LNKTYPE, "package/a.txt"),    # a path inside the archive
    ])
    check_archive(archive)


@pytest.mark.parametrize("name, mode, data, why", [
    ("pkg/../../evil.py", 0o100644, b"", 'a ".." component'),
    ("/abs/evil.py", 0o100644, b"", "an absolute path"),
    ("C:/evil.py", 0o100644, b"", "an absolute path"),
    ("pkg\\..\\..\\evil.py", 0o100644, b"", 'a ".." component'),
    ("pkg/creds", 0o120777, b"../../home/sandglass/.aws/credentials", "symlink leading outside"),
    ("pkg/fifo", 0o010644, b"", "a device, fifo or socket"),
])
def test_unsafe_zip_members_are_refused(tmp_path, name, mode, data, why):
    archive = make_zip(tmp_path / "x.whl", [("pkg/__init__.py", 0o100644, b""), (name, mode, data)])
    with pytest.raises(ScanError, match="unsafe archive x.whl") as exc:
        check_archive(archive)
    assert why in str(exc.value)


def test_too_many_files_or_bytes_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "MAX_ARCHIVE_FILES", 3)
    many = make_tar(tmp_path / "many.tgz", [member(f"package/{i}") for i in range(4)])
    with pytest.raises(ScanError, match="more than 3 files"):
        check_archive(many)
    monkeypatch.setattr(scan, "MAX_ARCHIVE_BYTES", 100)
    big = make_tar(tmp_path / "big.tgz", [member("package/a", size=60), member("package/b", size=60)])
    with pytest.raises(ScanError, match="uncompressed"):
        check_archive(big)
    big_zip = make_zip(tmp_path / "big.whl", [("a", 0o100644, b"0" * 101)])
    with pytest.raises(ScanError, match="uncompressed"):
        check_archive(big_zip)


def test_a_file_that_is_not_an_archive_is_refused(tmp_path):
    junk = tmp_path / "junk.tgz"
    junk.write_bytes(b"not an archive at all")
    with pytest.raises(ScanError, match="can't be read"):
        check_archive(junk)


def test_package_json_must_be_a_plain_file_of_reasonable_size(tmp_path, monkeypatch):
    link = make_tar(tmp_path / "link.tgz", [member("package/x"),
                                            member("package/package.json", tarfile.SYMTYPE, "x")])
    with pytest.raises(ScanError, match="not a plain file"):
        scan._package_json_from_tarball(link)
    monkeypatch.setattr(scan, "MAX_METADATA_BYTES", 10)
    big = make_tar(tmp_path / "big.tgz", [member("package/package.json", size=11)])
    with pytest.raises(ScanError, match="bigger than"):
        scan._package_json_from_tarball(big)


# --- the hostile test packages, scanned from the local registry ------------------

@pytest.fixture(scope="module")
def registry():
    build_test_packages.build_all()
    return build_test_packages.DIST


@pytest.mark.parametrize("package, why", [
    ("npm:sandglass-test-traversal@1.0.0", "member '../../sandglass-escaped-traversal.txt' is a path with a \"..\" component"),
    ("pypi:sandglass-test-symlink@1.0.0", "is a symlink leading outside the archive"),
    ("pypi:sandglass-test-bomb@1.0.0", "more than 500 MB uncompressed"),
])
def test_hostile_packages_stop_on_the_host_and_write_nothing_outside(registry, tmp_path, package, why):
    # The scan's temp folder is tmp_path/"scan"; anything else under tmp_path
    # (or the targets the archives aim at) appearing means something escaped.
    folder = tmp_path / "scan"
    folder.mkdir()
    before = set(tmp_path.rglob("*"))
    with pytest.raises(ScanError, match="unsafe archive") as exc:
        scan.download(parse_spec(package), folder, "x86_64-linux-gnu", registry)
    assert why in str(exc.value) and str(exc.value).endswith("not installed")
    outside = {p for p in tmp_path.rglob("*") if not p.is_relative_to(folder)} - before
    assert outside == set()
    for target in build_test_packages.HOSTILE_ESCAPE_TARGETS:
        assert not (folder / "project" / target).exists() and not Path(target).exists()
    # Inside the temp folder: only the downloaded archive (and npm's project
    # files), never an unpacked member.
    assert not any(p.name in ("notes.txt", "zeros.bin", "server.js") for p in folder.rglob("*"))


def test_the_scan_report_is_incomplete_with_the_reason(registry, monkeypatch):
    from sandglass import client
    monkeypatch.setattr(client.sandbox, "detect_multiarch", lambda: "x86_64-linux-gnu")
    calls = []
    monkeypatch.setattr(client.sandbox, "create_volume", lambda name: calls.append(name))
    report = client.run_scan(parse_spec("pypi:sandglass-test-symlink@1.0.0"),
                             build_test_packages.PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml",
                             registry)
    assert report["verdict"] == "INCOMPLETE" and calls == []  # never installed
    assert "unsafe archive" in " ".join(report["incomplete_reasons"])


# --- npm on the host never runs install scripts ---------------------------------

def test_npm_download_command_ignores_scripts():
    command = scan.npm_download_command("/usr/bin/npm", parse_spec("npm:pkg@1.0.0"), Path("/tmp/c"))
    assert "--ignore-scripts" in command and command[-1] == "pkg@1.0.0"


def test_npm_without_ignore_scripts_fails_closed(monkeypatch, tmp_path):
    ran = []
    monkeypatch.setattr(scan.subprocess, "run", lambda *a, **k: ran.append(a))
    # A future edit that drops the flag: refused before npm starts.
    monkeypatch.setattr(scan, "npm_download_command",
                        lambda npm, spec, cache: [npm, "install", f"{spec.name}@{spec.version}"])
    monkeypatch.setattr(scan.shutil, "which", lambda name: "/usr/bin/npm")
    with pytest.raises(ScanError, match="without --ignore-scripts"):
        scan.download(parse_spec("npm:pkg@1.0.0"), tmp_path, "x86_64-linux-gnu", None)
    assert ran == []


def test_npm_on_the_host_also_gets_ignore_scripts_in_its_environment(monkeypatch):
    seen = {}

    class Done:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(scan.subprocess, "run", lambda command, **k: seen.update(k) or Done())
    scan._run_host(["/usr/bin/npm", "install", "--ignore-scripts", "x@1.0.0"], "npm")
    assert seen["env"]["npm_config_ignore_scripts"] == "true"


def test_a_lockfile_dependency_on_a_local_path_stops_the_scan(tmp_path):
    (tmp_path / "project").mkdir()
    lock = {"packages": {"": {}, "node_modules/pkg": {"version": "1.0.0", "integrity": "sha512-AA=="},
                         "node_modules/evil": {"resolved": "file:../../home/me", "link": True}}}
    (tmp_path / "project" / "package-lock.json").write_text(__import__("json").dumps(lock))
    with pytest.raises(ScanError, match="points at a local path"):
        scan._cache_tarballs(parse_spec("npm:pkg@1.0.0"), tmp_path)


def test_every_downloaded_wheel_is_checked(registry, tmp_path, monkeypatch):
    checked = []
    monkeypatch.setattr(scan, "check_archive", lambda path: checked.append(Path(path).name))
    scan.download(parse_spec("pypi:sandglass-test-notes@1.0.0"), tmp_path, "x86_64-linux-gnu", registry)
    assert checked == ["sandglass_test_notes-1.0.0-py3-none-any.whl"]
    assert os.path.exists(tmp_path / checked[0])
