"""Build the test packages in test_packages/ into a local "registry" folder.

    uv run python scripts/build_test_packages.py

writes (git-ignored):
    test_packages/dist/pypi/<name>-<version>-py3-none-any.whl   one per test_packages/pypi/*/
    test_packages/dist/npm/<name>-<version>.tgz                 one per test_packages/npm/*/

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


def build_all() -> list[Path]:
    """Rebuild test_packages/dist/ from scratch; returns the files built."""
    built = []
    for ecosystem, build in (("pypi", build_wheel), ("npm", build_npm_tarball)):
        out_dir = DIST / ecosystem
        out_dir.mkdir(parents=True, exist_ok=True)
        for old in out_dir.iterdir():
            old.unlink()  # only what's in test_packages/ now
        for source in sorted(p for p in (SOURCES / ecosystem).iterdir() if p.is_dir()):
            built.append(build(source, out_dir))
    return built


def main() -> int:
    for path in build_all():
        print(f"built {path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
