"""`sandglass scan <pypi|npm>:<package>@<exact-version>`: get a package ready to run (#19).

The steps, in order (client.run_scan runs them and writes the report):

  1. parse_spec   "pypi:name@1.2.3" -> PackageSpec. Exact versions only:
                  "latest", ranges ("^1.2", ">=1", "1.*") are refused, so a
                  report always names exactly what was scanned.
  2. download     ON THE HOST, into a temporary folder, running no package code:
                    pypi  pip download, wheels only (--only-binary=:all:), for the
                          container's platform (Linux, CPython 3.12, its CPU).
                          Building an sdist would run its setup.py on the host.
                    npm   npm install --ignore-scripts in a scratch folder, which
                          fills an npm cache with the package and its
                          dependencies; only that cache, package.json and the
                          lockfile are kept.
                  With --registry-dir, our own test packages come from a local
                  folder instead of PyPI/npm (no network at all).
  2b. hash        (#21) the package's own file is hashed and compared with the
                  value the registry publishes (PyPI sha256, npm dist.integrity);
                  a mismatch stops the scan before the install
  3. install      INSIDE the sandbox (sandbox.scan_install_command): offline, no
                  network, into a fresh Docker volume at /package, the only
                  writable folder besides /tmp. Traced with strace (#16):
                  compare.compare_install judges it as the "install" phase.
  4. entry point  which program starts the server: a console script (pypi) or
                  a "bin" of package.json (npm). --entry picks one if there
                  are several. Read from the downloaded files on the host
                  (zip / tar), never by running anything.

Every failure is a ScanError with a plain reason; the scan is then INCOMPLETE.
"""

import base64
import configparser
import hashlib
import json
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from sandglass import sandbox

ECOSYSTEMS = ("pypi", "npm")

# PyPI project names (PEP 508): letters, digits, ".", "_", "-"; starts and
# ends with a letter or digit.
PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
# An exact PEP 440 version as published on PyPI: optional epoch, release
# numbers, optional pre-release (a/b/rc), post- and dev-release. No local
# versions ("+..."), no wildcards, no operators.
PYPI_VERSION_RE = re.compile(r"^(\d+!)?\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$")
# npm package names: lowercase, optionally "@scope/name", at most 214 characters.
NPM_NAME_RE = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
# An exact semver version: MAJOR.MINOR.PATCH, optional -prerelease and +build.
NPM_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                            r"(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$")

# The image is Debian 13 (glibc 2.41): Linux wheels for any manylinux up to
# that work. pip doesn't expand a manylinux tag to older ones by itself, so
# every one is listed (the legacy names cover 2.5, 2.12 and 2.17).
IMAGE_GLIBC_MINOR = 41
PYTHON_VERSION = "3.12"  # the image's Python (Dockerfile: python:3.12-slim-trixie)

HOST_TIMEOUT_SECONDS = 600     # downloading on the host
INSTALL_TIMEOUT_SECONDS = 600  # installing inside the sandbox
INSTALL_LOG_CHARS = 2000       # how much of the installer's output a failure reason keeps


class SpecError(ValueError):
    """The package spec is malformed (a usage error)."""


class ScanError(RuntimeError):
    """A step of the scan failed; the scan is INCOMPLETE with this reason."""


@dataclass(frozen=True)
class PackageSpec:
    ecosystem: str  # "pypi" or "npm"
    name: str
    version: str

    def __str__(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    @property
    def slug(self) -> str:
        """A file-name-safe label for reports: pypi_name_1.2.3, npm_scope-name_1.0.0."""
        return f"{self.ecosystem}_{self.name.lstrip('@').replace('/', '-')}_{self.version}"


@dataclass
class Prepared:
    """What the download step produced, in a temporary folder on the host."""
    spec: PackageSpec
    folder: Path                                       # mounted at /download in the install
    files: list[Path] = field(default_factory=list)    # the package files that were downloaded
    entries: dict[str, str] = field(default_factory=dict)  # entry name -> path inside the container
    artifact: Path | None = None   # the package's own file (wheel / tarball): its hash is checked (#21)
    labels: dict[Path, str] = field(default_factory=dict)  # name to show for a file (npm cache names are hashes)


def parse_spec(text: str) -> PackageSpec:
    """'<pypi|npm>:<name>@<exact-version>' -> PackageSpec, or SpecError saying why not."""
    ecosystem, colon, rest = text.partition(":")
    if not colon or ecosystem not in ECOSYSTEMS:
        raise SpecError(f"{text!r}: expected <pypi|npm>:<package>@<exact-version>, "
                        f"e.g. pypi:mcp-server-fetch@2025.4.7")
    name, at, version = rest.rpartition("@")  # rpartition: "@scope/name@1.0.0"
    if not at or not name or not version:
        raise SpecError(f"{text!r}: missing @<exact-version> (e.g. {ecosystem}:{rest or 'name'}@1.2.3)")
    if version == "latest":
        raise SpecError(f"{text!r}: 'latest' is not allowed; give the exact version to scan")
    if ecosystem == "pypi":
        if not PYPI_NAME_RE.match(name):
            raise SpecError(f"{text!r}: {name!r} is not a valid PyPI project name")
        if not PYPI_VERSION_RE.match(version):
            raise SpecError(f"{text!r}: {version!r} is not an exact version "
                            "(ranges, wildcards and local versions are not allowed)")
    else:
        if not NPM_NAME_RE.match(name) or len(name) > 214:
            raise SpecError(f"{text!r}: {name!r} is not a valid npm package name")
        if not NPM_VERSION_RE.match(version):
            raise SpecError(f"{text!r}: {version!r} is not an exact version "
                            "(ranges like ^1.2.3, ~1.2, 1.x or >=1 are not allowed)")
    return PackageSpec(ecosystem, name, version)


# ---------------------------------------------------------------------------
# Step 2: download on the host
# ---------------------------------------------------------------------------

def download(spec: PackageSpec, folder: Path, multiarch: str,
             registry_dir: Path | None = None) -> Prepared:
    """Download the package and its dependencies into `folder` (on the host)."""
    if spec.ecosystem == "pypi":
        return _download_pypi(spec, folder, multiarch, registry_dir)
    return _download_npm(spec, folder, registry_dir)


def _run_host(command: list[str], what: str, cwd: Path | None = None) -> None:
    """Run a download command on the host; ScanError with its output if it fails."""
    try:
        out = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                             timeout=HOST_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"{what} failed: {exc}") from None
    if out.returncode != 0:
        log = (out.stdout + out.stderr).strip()[-INSTALL_LOG_CHARS:]
        raise ScanError(f"{what} failed (exit {out.returncode}): {log}")


def pip_download_command(spec: PackageSpec, dest: Path, multiarch: str,
                         registry_dir: Path | None) -> list[str]:
    """pip download for the CONTAINER's platform, wheels only."""
    arch = multiarch.split("-", 1)[0]  # "x86_64-linux-gnu" -> "x86_64"
    platforms = [f"manylinux1_{arch}", f"manylinux2010_{arch}", f"manylinux2014_{arch}"]
    platforms += [f"manylinux_2_{minor}_{arch}" for minor in range(5, IMAGE_GLIBC_MINOR + 1)]
    command = [sys.executable, "-m", "pip", "download",
               "--disable-pip-version-check", "--no-cache-dir", "--no-input",
               "--only-binary=:all:",  # never an sdist: building one runs its code
               "--python-version", PYTHON_VERSION, "--implementation", "cp",
               "--abi", f"cp{PYTHON_VERSION.replace('.', '')}", "--abi", "abi3", "--abi", "none"]
    for platform in platforms:
        command += ["--platform", platform]
    if registry_dir is not None:
        command += ["--no-index", "--find-links", str(registry_dir / "pypi")]
    return command + ["--dest", str(dest), f"{spec.name}=={spec.version}"]


def _download_pypi(spec, folder, multiarch, registry_dir) -> Prepared:
    _run_host(pip_download_command(spec, folder, multiarch, registry_dir), "pip download (on the host)")
    files = sorted(folder.glob("*.whl"))
    main = _main_wheel(spec, files)
    entries = {name: str(sandbox.CONTAINER_SITE / "bin" / name) for name in _console_scripts(main)}
    return Prepared(spec, folder, files, entries, artifact=main)


def _normalize(name: str) -> str:
    """PEP 503 name normalization: 'Foo.Bar_baz' -> 'foo-bar-baz'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _main_wheel(spec: PackageSpec, wheels: list[Path]) -> Path:
    """The downloaded wheel of the package itself (the others are dependencies)."""
    for wheel in wheels:
        dist, version = wheel.name.split("-")[:2]
        if _normalize(dist) == _normalize(spec.name) and version == spec.version:
            return wheel
    raise ScanError(f"pip downloaded no wheel for {spec.name}=={spec.version}")


def _console_scripts(wheel: Path) -> list[str]:
    """The console scripts a wheel declares (its *.dist-info/entry_points.txt)."""
    with zipfile.ZipFile(wheel) as whl:
        names = [n for n in whl.namelist()
                 if n.count("/") == 1 and n.endswith(".dist-info/entry_points.txt")]
        if not names:
            return []
        parser = configparser.ConfigParser(interpolation=None, delimiters=("=",))
        parser.optionxform = str  # keep the script names' case
        parser.read_string(whl.read(names[0]).decode("utf-8"))
    return sorted(parser["console_scripts"]) if parser.has_section("console_scripts") else []


def npm_tarball_name(name: str, version: str) -> str:
    """What `npm pack` calls the file: "@scope/pkg" -> "scope-pkg-<version>.tgz"."""
    return f"{name.lstrip('@').replace('/', '-')}-{version}.tgz"


def _download_npm(spec, folder, registry_dir) -> Prepared:
    """Fill folder/ with project/package.json (+ lockfile), npm-cache/ and, for a
    local registry, the tarball. Install scripts never run on the host."""
    project = folder / "project"
    project.mkdir()
    (folder / "npm-cache").mkdir()
    manifest = {"name": "sandglass-scan", "version": "0.0.0", "private": True}

    if registry_dir is not None:
        # A local test package: no registry, no npm on the host. The install
        # in the sandbox installs this tarball directly.
        tarball = registry_dir / "npm" / npm_tarball_name(spec.name, spec.version)
        if not tarball.is_file():
            raise ScanError(f"{tarball.name} is not in {registry_dir / 'npm'}")
        shutil.copy2(tarball, folder / tarball.name)
        manifest["dependencies"] = {spec.name: f"file:{sandbox.CONTAINER_DOWNLOAD}/{tarball.name}"}
        (project / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        package_json = _package_json_from_tarball(folder / tarball.name)
        files = [folder / tarball.name]
        artifact, labels = files[0], {}
    else:
        npm = shutil.which("npm")
        if npm is None:
            raise ScanError("npm is not installed on the host (needed to download npm packages)")
        (project / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        _run_host([npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact",
                   "--cache", str(folder / "npm-cache"), f"{spec.name}@{spec.version}"],
                  "npm install --ignore-scripts (on the host)", cwd=project)
        installed = project / "node_modules" / spec.name / "package.json"
        package_json = json.loads(installed.read_text(encoding="utf-8"))
        # Only the cache and the lockfile go into the sandbox; the files npm
        # unpacked here are deleted (they were never run).
        shutil.rmtree(project / "node_modules")
        files, labels, artifact = _cache_tarballs(spec, folder)

    if package_json.get("name") != spec.name or package_json.get("version") != spec.version:
        raise ScanError(f"the downloaded package.json says {package_json.get('name')}@"
                        f"{package_json.get('version')}, not {spec.name}@{spec.version}")
    package_dir = sandbox.CONTAINER_PACKAGE / "node_modules" / spec.name
    entries = {}
    for name, target in _npm_bins(spec, package_json).items():
        target = posixpath.normpath(target)
        if target.startswith(("/", "../")) or target == "..":
            raise ScanError(f"bin {name!r} points outside the package: {target!r}")
        entries[name] = str(package_dir / target)
    return Prepared(spec, folder, files, entries, artifact=artifact, labels=labels)


def _cache_tarballs(spec: PackageSpec, folder: Path) -> tuple[list[Path], dict[Path, str], Path]:
    """The tarballs npm put in the cache, found through the lockfile.

    npm's cache (cacache) stores each tarball under its own hash, so the
    lockfile's "integrity" of every package says where it is. Returns (files,
    their names to show, the package's own tarball).
    """
    lock = json.loads((folder / "project" / "package-lock.json").read_text(encoding="utf-8"))
    files, labels, artifact = [], {}, None
    for key, info in sorted(lock.get("packages", {}).items()):
        if not key or "integrity" not in info:
            continue  # "" is the scan's own package.json
        path = cache_content_path(folder / "npm-cache", info["integrity"])
        if not path.is_file():
            raise ScanError(f"{key} is not in the downloaded npm cache")
        files.append(path)
        labels[path] = f"{key.removeprefix('node_modules/')}@{info.get('version')} (npm cache)"
        if key == f"node_modules/{spec.name}":
            artifact = path
    if artifact is None:
        raise ScanError(f"the lockfile doesn't list {spec.name}")
    return files, labels, artifact


def cache_content_path(cache: Path, integrity: str) -> Path:
    """Where cacache keeps the file with this integrity (its sha512 entry)."""
    algorithm, digest = _pick_sri(integrity)
    hex_digest = base64.b64decode(digest).hex()
    return cache / "_cacache" / "content-v2" / algorithm / hex_digest[:2] / hex_digest[2:4] / hex_digest[4:]


def _package_json_from_tarball(tarball: Path) -> dict:
    """package/package.json from an npm tarball, read without unpacking anything."""
    with tarfile.open(tarball, "r:gz") as tar:
        member = tar.extractfile("package/package.json")
        if member is None:
            raise ScanError(f"{tarball.name} has no package/package.json")
        return json.loads(member.read().decode("utf-8"))


def _npm_bins(spec: PackageSpec, package_json: dict) -> dict[str, str]:
    """package.json "bin": a string (named after the package) or {name: path}."""
    bins = package_json.get("bin") or {}
    if isinstance(bins, str):
        return {spec.name.split("/")[-1]: bins}
    return {str(k): str(v) for k, v in bins.items()}


def choose_entry(prepared: Prepared, wanted: str | None) -> tuple[str, str]:
    """(name, container path) of the program that starts the server.

    --entry wins; otherwise the only one, or the one named like the package.
    """
    entries = prepared.entries
    if wanted is not None:
        if wanted not in entries:
            raise ScanError(f"--entry {wanted!r} is not one of the package's entry points: "
                            f"{sorted(entries) or 'none'}")
        return wanted, entries[wanted]
    if len(entries) == 1:
        return next(iter(entries.items()))
    short_name = prepared.spec.name.split("/")[-1]
    for name in entries:
        if _normalize(name) == _normalize(short_name):
            return name, entries[name]
    if not entries:
        raise ScanError("the package declares no entry point (console script or npm bin) "
                        "to start a server with")
    raise ScanError(f"the package has several entry points, pick one with --entry: {sorted(entries)}")


# ---------------------------------------------------------------------------
# Step 2b: the package hash (#21), checked before anything is installed
# ---------------------------------------------------------------------------

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"
NPM_VERSION_URL = "https://registry.npmjs.org/{name}/{version}"
REGISTRY_TIMEOUT_SECONDS = 30
# The SRI algorithms npm uses, strongest first.
SRI_ALGORITHMS = ("sha512", "sha384", "sha256", "sha1")


def sha256_hex(path: Path) -> str:
    """The file's sha256, as hex (what PyPI publishes)."""
    return _digest(path, "sha256").hex()


def sri(path: Path, algorithm: str = "sha512") -> str:
    """The file's Subresource Integrity string, "sha512-<base64>" (what npm publishes)."""
    return f"{algorithm}-{base64.b64encode(_digest(path, algorithm)).decode()}"


def _digest(path: Path, algorithm: str) -> bytes:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.digest()


def _pick_sri(integrity: str) -> tuple[str, str]:
    """(algorithm, base64 digest) of the strongest hash in an SRI string.
    npm's may hold several, space-separated: "sha512-... sha1-..."."""
    found = dict(item.split("-", 1) for item in integrity.split() if "-" in item)
    for algorithm in SRI_ALGORITHMS:
        if algorithm in found:
            return algorithm, found[algorithm]
    raise ScanError(f"no supported hash in the integrity value {integrity!r}")


def registry_url(spec: PackageSpec) -> str:
    """Where the registry publishes this exact version's metadata."""
    if spec.ecosystem == "pypi":
        return PYPI_JSON_URL.format(name=spec.name, version=spec.version)
    return NPM_VERSION_URL.format(name=urllib.parse.quote(spec.name, safe="@"), version=spec.version)


def fetch_json(url: str) -> dict:
    """GET a registry's JSON (metadata only, never package code). ScanError if it fails."""
    try:
        with urllib.request.urlopen(url, timeout=REGISTRY_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ScanError(f"could not get the published hash from {url}: {exc}") from None


def published_metadata(spec: PackageSpec, registry_dir: Path | None, fetch=fetch_json) -> tuple[dict, str]:
    """(metadata, where it came from). A local test registry keeps registry-style
    metadata next to the files (scripts/build_test_packages.py writes it)."""
    if registry_dir is None:
        url = registry_url(spec)
        return fetch(url), url
    path = registry_dir / f"{spec.ecosystem}-meta" / spec.name / f"{spec.version}.json"
    if not path.is_file():
        raise ScanError(f"could not get the published hash: {path} doesn't exist")
    return (json.loads(path.read_text(encoding="utf-8")),
            f"the local test registry ({path.relative_to(registry_dir).as_posix()})")


def compare_hash(spec: PackageSpec, artifact: Path, metadata: dict) -> dict:
    """Our hash of the downloaded artifact vs the registry's published one.

      pypi  sha256 hex  vs  urls[].digests.sha256 of the same file name
      npm   SRI         vs  dist.integrity (or dist.shasum, sha1 hex, for old packages)
    Returns {"algorithm", "ours", "published", "match"}; ScanError if the
    registry publishes nothing to compare with.
    """
    if spec.ecosystem == "pypi":
        listed = [u for u in metadata.get("urls", []) if u.get("filename") == artifact.name]
        if not listed or "sha256" not in listed[0].get("digests", {}):
            raise ScanError(f"the registry lists no sha256 for {artifact.name}")
        ours, published, algorithm = sha256_hex(artifact), listed[0]["digests"]["sha256"].lower(), "sha256"
    else:
        dist = metadata.get("dist", {})
        if dist.get("integrity"):
            algorithm, digest = _pick_sri(dist["integrity"])
            published, ours = f"{algorithm}-{digest}", sri(artifact, algorithm)
        elif dist.get("shasum"):
            algorithm, published, ours = "sha1", dist["shasum"].lower(), _digest(artifact, "sha1").hex()
        else:
            raise ScanError(f"the registry publishes no integrity or shasum for {spec}")
    return {"algorithm": algorithm, "ours": ours, "published": published, "match": ours == published}


def verify_hash(prepared: Prepared, registry_dir: Path | None, fetch=fetch_json) -> dict:
    """Check the package's own artifact against the registry (#21).

    Returns the comparison (with "file" and "source") for the report, match or
    not; the caller stops the scan on a mismatch.
    """
    metadata, source = published_metadata(prepared.spec, registry_dir, fetch)
    result = compare_hash(prepared.spec, prepared.artifact, metadata)
    name = prepared.labels.get(prepared.artifact, prepared.artifact.name)
    return {"file": name, "source": source, **result}


def describe_files(prepared: Prepared) -> list[dict]:
    """Every downloaded file, with its size and sha256, for the report."""
    return [{"name": prepared.labels.get(f, f.name), "size": f.stat().st_size, "sha256": sha256_hex(f)}
            for f in prepared.files]


# ---------------------------------------------------------------------------
# Step 3: install inside the sandbox
# ---------------------------------------------------------------------------

# Fixed scripts: the package spec only ever reaches them as "$@" arguments.
# (Their output goes to the install log: sandbox.scan_install_command runs
# them after `exec 2>&1`.)
PIP_INSTALL_SCRIPT = (
    f'exec {sandbox.CONTAINER_SYSTEM_PYTHON} -m pip install --no-index'
    f' --find-links {sandbox.CONTAINER_DOWNLOAD} --target {sandbox.CONTAINER_SITE}'
    ' --no-cache-dir --disable-pip-version-check --no-input --no-warn-script-location "$@"'
)
NPM_INSTALL_SCRIPT = (
    f'cp {sandbox.CONTAINER_DOWNLOAD}/project/package*.json {sandbox.CONTAINER_PACKAGE}/'
    f' && cp -R {sandbox.CONTAINER_DOWNLOAD}/npm-cache /tmp/npm-cache'
    ' && exec npm install --offline --no-audit --no-fund'
)
INSTALL_TRACE_FILENAME = "install-trace.txt"  # next to the server's trace.txt
INSTALL_LOG_FILENAME = "install-log.txt"      # pip's / npm's own output
# npm settings for the install: cache and logs in /tmp (HOME is read-only),
# no update check, nothing fetched.
NPM_ENV = {
    "npm_config_cache": "/tmp/npm-cache",
    "npm_config_logs_dir": "/tmp/npm-logs",
    "npm_config_update_notifier": "false",
    "npm_config_offline": "true",
}


def install(prepared: Prepared, volume: str, trace_file: Path, log_file: Path) -> int | None:
    """Install the downloaded files into the volume, inside the sandbox, under strace (#16).

    The trace (the container's stderr) goes to `trace_file` and the
    installer's output to `log_file`, both straight to disk on the host.
    Returns the install's exit code, or None if it took longer than
    INSTALL_TIMEOUT_SECONDS (the container is then removed). Either way the
    caller judges the trace: an install that fails may still have misbehaved.
    """
    spec = prepared.spec
    container = f"{volume}-install"
    if spec.ecosystem == "pypi":
        command, args = sandbox.scan_install_command(volume, prepared.folder, PIP_INSTALL_SCRIPT,
                                                     [f"{spec.name}=={spec.version}"], name=container)
    else:
        command, args = sandbox.scan_install_command(volume, prepared.folder, NPM_INSTALL_SCRIPT,
                                                     [], env=NPM_ENV, name=container)
    with open(trace_file, "wb") as trace, open(log_file, "wb") as log:
        try:
            out = subprocess.run([command, *args], stdin=subprocess.DEVNULL, stdout=log, stderr=trace,
                                 timeout=INSTALL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            sandbox.remove_container(container)  # killing `docker run` doesn't stop the container
            return None
        except OSError as exc:
            raise ScanError(f"could not start the install container: {exc}") from None
    return out.returncode


def log_tail(log_file: Path, chars: int = INSTALL_LOG_CHARS) -> str:
    """The end of the install log, without reading a huge log whole."""
    try:
        with open(log_file, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - chars * 4))  # up to 4 bytes per UTF-8 character
            return f.read().decode("utf-8", "replace")[-chars:].strip()
    except FileNotFoundError:
        return ""
