"""Build the test packages in test_packages/ into a local "registry" folder.

    uv run python scripts/build_test_packages.py

writes (git-ignored):
    test_packages/dist/pypi/<name>-<version>-py3-none-any.whl   one per test_packages/pypi/*/
    test_packages/dist/npm/<name>-<version>.tgz                 one per test_packages/npm/*/
    test_packages/dist/<pypi|npm>-meta/<name>/<version>.json    the "published" hashes (#21)

`sandglass scan ... --registry-dir test_packages/dist` then uses these files
instead of PyPI or npm, so scanning our own test packages needs no network.

The files are written directly with zipfile and tarfile, the way pip and npm
lay them out, so no build tool (or network) is needed, and the same sources
always give byte-identical files (fixed timestamps, sorted entries). Only our
own test packages are built; nothing is downloaded.
"""

import base64
import gzip
import hashlib
import io
import json
import shutil
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

from sandglass import PROJECT_ROOT
from sandglass.scan import npm_tarball_name

SOURCES = PROJECT_ROOT / "test_packages"
DIST = SOURCES / "dist"

FIXED_DATE = (1980, 1, 1, 0, 0, 0)  # the earliest date a zip file can hold


def _files(folder: Path) -> list[Path]:
    """Every file under `folder`, sorted, skipping caches."""
    return sorted(p for p in folder.rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")


def build_wheel(source: Path, out_dir: Path) -> Path:
    """A pure-Python wheel from test_packages/pypi/<pkg>/ (pyproject.toml + module folder)."""
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    name, version = project["name"], project["version"]
    dist_name = name.replace("-", "_")           # wheel file names use "_"
    dist_info = f"{dist_name}-{version}.dist-info"

    entries: dict[str, bytes] = {}
    module = source / dist_name                  # e.g. sandglass_test_notes/
    for path in _files(module):
        entries[path.relative_to(source).as_posix()] = path.read_bytes()

    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    for requirement in project.get("dependencies", []):
        metadata += f"Requires-Dist: {requirement}\n"
    entries[f"{dist_info}/METADATA"] = metadata.encode()
    entries[f"{dist_info}/WHEEL"] = (b"Wheel-Version: 1.0\nGenerator: sandglass-build-test-packages\n"
                                     b"Root-Is-Purelib: true\nTag: py3-none-any\n")
    scripts = project.get("scripts", {})
    if scripts:
        lines = ["[console_scripts]"] + [f"{k} = {v}" for k, v in sorted(scripts.items())]
        entries[f"{dist_info}/entry_points.txt"] = ("\n".join(lines) + "\n").encode()

    # RECORD: every file with its sha256 (urlsafe base64, no padding) and size.
    record = []
    for path, data in entries.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(data)}")
    record.append(f"{dist_info}/RECORD,,")
    entries[f"{dist_info}/RECORD"] = ("\n".join(record) + "\n").encode()

    out = out_dir / f"{dist_name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as whl:
        for path, data in entries.items():
            info = zipfile.ZipInfo(path, FIXED_DATE)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            whl.writestr(info, data)
    return out


def build_npm_tarball(source: Path, out_dir: Path) -> Path:
    """An npm tarball (every file under package/) from test_packages/npm/<pkg>/."""
    manifest = json.loads((source / "package.json").read_text(encoding="utf-8"))
    out = out_dir / npm_tarball_name(manifest["name"], manifest["version"])

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in _files(source):
            data = path.read_bytes()
            info = tarfile.TarInfo("package/" + path.relative_to(source).as_posix())
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    # mtime=0 in the gzip header too, so the same sources give the same bytes.
    out.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
    return out


def write_metadata(ecosystem: str, source: Path, built: Path) -> Path:
    """The registry's metadata for one built file, the way PyPI / npm publish it
    (only the fields `sandglass scan` reads), so its hash check (#21) runs offline.

    A package whose pyproject.toml says [tool.sandglass-test]
    wrong_published_hash = true gets a deliberately WRONG published hash: it
    stands for a file that changed after it was published.
    """
    if ecosystem == "pypi":
        project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
        name, version = project["project"]["name"], project["project"]["version"]
        sha256 = hashlib.sha256(built.read_bytes()).hexdigest()
        if project.get("tool", {}).get("sandglass-test", {}).get("wrong_published_hash"):
            sha256 = hashlib.sha256(b"not the file that was published").hexdigest()
        metadata = {"info": {"name": name, "version": version},
                    "urls": [{"filename": built.name, "digests": {"sha256": sha256}}]}
    else:
        manifest = json.loads((source / "package.json").read_text(encoding="utf-8"))
        name, version = manifest["name"], manifest["version"]
        data = built.read_bytes()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        metadata = {"name": name, "version": version,
                    "dist": {"integrity": integrity, "shasum": hashlib.sha1(data).hexdigest()}}
    path = DIST / f"{ecosystem}-meta" / name / f"{version}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Hostile archives (#133): packages that would be unsafe to unpack. They have
# no source folder: they are generated here, so a "../" member never exists
# as a real file in the repository. `sandglass scan` must refuse each one on
# the host, before the install (INCOMPLETE). Nothing in them is ever unpacked.
# ---------------------------------------------------------------------------

HOSTILE_ESCAPE_TARGETS = ("../../sandglass-escaped-traversal.txt", "/tmp/sandglass-escaped-absolute.txt")
BOMB_BYTES = 520 * 1024 * 1024  # just over scan.MAX_ARCHIVE_BYTES once unpacked


def _wheel_metadata(name: str, version: str) -> dict[str, bytes]:
    """The dist-info files every wheel needs (no RECORD hashes: never installed)."""
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    return {
        f"{dist_info}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist_info}/entry_points.txt": f"[console_scripts]\n{name} = x:main\n".encode(),
        f"{dist_info}/RECORD": b"",
    }


def _zip_info(path: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_DATE)
    info.external_attr = mode << 16  # Unix type and permissions, as zip stores them
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def build_symlink_wheel(out_dir: Path) -> Path:
    """sandglass-test-symlink: a wheel whose module folder holds a symlink to
    ~/.aws/credentials, outside the folder it would be unpacked into."""
    out = out_dir / "sandglass_test_symlink-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(out, "w") as whl:
        whl.writestr(_zip_info("sandglass_test_symlink/__init__.py", 0o100644), b"")
        # A zip symlink: file type 0o120000, the target is the member's content.
        whl.writestr(_zip_info("sandglass_test_symlink/notes.txt", 0o120777),
                     b"../../../../home/sandglass/.aws/credentials")
        for path, data in _wheel_metadata("sandglass-test-symlink", "1.0.0").items():
            whl.writestr(_zip_info(path, 0o100644), data)
    return out


def build_bomb_wheel(out_dir: Path) -> Path:
    """sandglass-test-bomb: a wheel of a few hundred KB holding one file of
    zeros that would unpack to more than 500 MB (a "zip bomb", gently)."""
    out = out_dir / "sandglass_test_bomb-1.0.0-py3-none-any.whl"
    chunk = bytes(1024 * 1024)
    with zipfile.ZipFile(out, "w") as whl:
        info = _zip_info("sandglass_test_bomb/zeros.bin", 0o100644)
        with whl.open(info, "w", force_zip64=True) as data:  # streamed: never all in memory
            for _ in range(BOMB_BYTES // len(chunk)):
                data.write(chunk)
        for path, content in _wheel_metadata("sandglass-test-bomb", "1.0.0").items():
            whl.writestr(_zip_info(path, 0o100644), content)
    return out


def build_traversal_tarball(out_dir: Path) -> Path:
    """sandglass-test-traversal: an npm tarball with a valid package.json, plus
    a "../" member and an absolute member that would land outside its folder."""
    out = out_dir / npm_tarball_name("sandglass-test-traversal", "1.0.0")
    manifest = json.dumps({"name": "sandglass-test-traversal", "version": "1.0.0",
                           "bin": {"sandglass-test-traversal": "server.js"}}).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        members = [("package/package.json", manifest), ("package/server.js", b"")]
        members += [(name, b"written outside the package folder\n") for name in HOSTILE_ESCAPE_TARGETS]
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
    out.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
    return out


def write_hostile_metadata(ecosystem: str, name: str, built: Path) -> Path:
    """Correct "published" hashes, so only the archive check can stop the scan."""
    data = built.read_bytes()
    if ecosystem == "pypi":
        metadata = {"info": {"name": name, "version": "1.0.0"},
                    "urls": [{"filename": built.name,
                              "digests": {"sha256": hashlib.sha256(data).hexdigest()}}]}
    else:
        metadata = {"name": name, "version": "1.0.0",
                    "dist": {"integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}}
    path = DIST / f"{ecosystem}-meta" / name / "1.0.0.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def build_hostile() -> list[Path]:
    built = [build_symlink_wheel(DIST / "pypi"), build_bomb_wheel(DIST / "pypi"),
             build_traversal_tarball(DIST / "npm")]
    for path, (ecosystem, name) in zip(built, (("pypi", "sandglass-test-symlink"),
                                               ("pypi", "sandglass-test-bomb"),
                                               ("npm", "sandglass-test-traversal"))):
        write_hostile_metadata(ecosystem, name, path)
    return built


def build_all() -> list[Path]:
    """Rebuild test_packages/dist/ from scratch; returns the files built."""
    built = []
    for ecosystem, build in (("pypi", build_wheel), ("npm", build_npm_tarball)):
        for folder in (DIST / ecosystem, DIST / f"{ecosystem}-meta"):
            shutil.rmtree(folder, ignore_errors=True)  # only what's in test_packages/ now
            folder.mkdir(parents=True)
        for source in sorted(p for p in (SOURCES / ecosystem).iterdir() if p.is_dir()):
            path = build(source, DIST / ecosystem)
            write_metadata(ecosystem, source, path)
            built.append(path)
    return built + build_hostile()


def main() -> int:
    for path in build_all():
        print(f"built {path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
