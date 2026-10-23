"""Package hash (#21): our hash of the downloaded file vs the registry's published one.

Fixed sample data only: no real downloads, no registry contacted.
"""

import base64
import hashlib
import json

import pytest

from sandglass import PROJECT_ROOT, client, sandbox, scan
from sandglass.scan import PackageSpec, ScanError, compare_hash
from tests.test_scan import POLICY, REGISTRY, registry  # noqa: F401 (registry is a fixture)

DATA = b"pretend this is a wheel or a tarball\n"
SHA256 = hashlib.sha256(DATA).hexdigest()
SHA512_SRI = "sha512-" + base64.b64encode(hashlib.sha512(DATA).digest()).decode()
SHA1 = hashlib.sha1(DATA).hexdigest()
OTHER_SHA256 = hashlib.sha256(b"something else").hexdigest()

PYPI = PackageSpec("pypi", "demo-server", "1.2.3")
NPM = PackageSpec("npm", "@demo/server", "1.2.3")


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "demo_server-1.2.3-py3-none-any.whl"
    path.write_bytes(DATA)
    return path


def pypi_json(filename, sha256):
    """The part of https://pypi.org/pypi/<name>/<version>/json that we read."""
    return {"info": {"name": "demo-server", "version": "1.2.3"},
            "urls": [{"filename": "demo_server-1.2.3.tar.gz", "digests": {"sha256": OTHER_SHA256}},
                     {"filename": filename, "digests": {"md5": "x", "sha256": sha256}}]}


def test_pypi_match(artifact):
    assert compare_hash(PYPI, artifact, pypi_json(artifact.name, SHA256)) == {
        "algorithm": "sha256", "ours": SHA256, "published": SHA256, "match": True}


def test_pypi_mismatch(artifact):
    result = compare_hash(PYPI, artifact, pypi_json(artifact.name, OTHER_SHA256))
    assert result["match"] is False and result["published"] == OTHER_SHA256 and result["ours"] == SHA256


def test_pypi_hash_is_compared_case_insensitively(artifact):
    assert compare_hash(PYPI, artifact, pypi_json(artifact.name, SHA256.upper()))["match"] is True


def test_pypi_file_not_listed_is_an_error_not_a_pass(artifact):
    with pytest.raises(ScanError, match="lists no sha256"):
        compare_hash(PYPI, artifact, pypi_json("another-file.whl", SHA256))


@pytest.mark.parametrize("dist, expected", [
    ({"integrity": SHA512_SRI}, (SHA512_SRI, True)),
    # npm can list several hashes; the strongest (sha512) is used.
    ({"integrity": f"sha1-{base64.b64encode(hashlib.sha1(DATA).digest()).decode()} {SHA512_SRI}"},
     (SHA512_SRI, True)),
    ({"integrity": "sha512-" + base64.b64encode(hashlib.sha512(b"x").digest()).decode()}, (None, False)),
    # Old packages: only dist.shasum (sha1 hex).
    ({"shasum": SHA1}, (SHA1, True)),
    ({"shasum": "0" * 40}, (SHA1, False)),
])
def test_npm_integrity(artifact, dist, expected):
    ours, match = expected
    result = compare_hash(NPM, artifact, {"name": "@demo/server", "version": "1.2.3", "dist": dist})
    assert result["match"] is match
    if ours:
        assert result["ours"] == ours


def test_npm_without_any_published_hash_is_an_error(artifact):
    with pytest.raises(ScanError, match="no integrity or shasum"):
        compare_hash(NPM, artifact, {"dist": {}})


def test_registry_urls():
    assert scan.registry_url(PYPI) == "https://pypi.org/pypi/demo-server/1.2.3/json"
    assert scan.registry_url(NPM) == "https://registry.npmjs.org/@demo%2Fserver/1.2.3"


def test_unreachable_registry_is_a_scan_error(monkeypatch):
    def refuse(url, timeout):
        raise OSError("no route")
    monkeypatch.setattr(scan.urllib.request, "urlopen", refuse)
    with pytest.raises(ScanError, match="could not get the published hash from https://pypi.org/"):
        scan.published_metadata(PYPI, None)


def test_published_metadata_uses_the_fetcher_for_real_registries():
    seen = []
    metadata, source = scan.published_metadata(PYPI, None, fetch=lambda url: seen.append(url) or {"ok": 1})
    assert metadata == {"ok": 1} and source == seen[0] == "https://pypi.org/pypi/demo-server/1.2.3/json"


def test_npm_tarball_found_in_the_cache_through_the_lockfile(tmp_path):
    # What `npm install` leaves behind: a lockfile, and cacache content files
    # named after their sha512.
    folder = tmp_path
    (folder / "project").mkdir()
    lock = {"packages": {"": {"name": "sandglass-scan"},
                         "node_modules/@demo/server": {"version": "1.2.3", "integrity": SHA512_SRI}}}
    (folder / "project" / "package-lock.json").write_text(json.dumps(lock))
    content = scan.cache_content_path(folder / "npm-cache", SHA512_SRI)
    hex_digest = hashlib.sha512(DATA).hexdigest()
    assert content == folder / "npm-cache/_cacache/content-v2/sha512" / hex_digest[:2] / hex_digest[2:4] / hex_digest[4:]
    content.parent.mkdir(parents=True)
    content.write_bytes(DATA)
    files, labels, artifact = scan._cache_tarballs(NPM, folder)
    assert files == [content] and artifact == content
    assert labels[content] == "@demo/server@1.2.3 (npm cache)"


def test_a_mismatch_stops_the_scan_before_the_install(registry, monkeypatch, tmp_path):
    # The tampered test package: real (offline) download from the local test
    # registry, whose metadata publishes a wrong sha256. Nothing is installed.
    monkeypatch.setattr(client, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(sandbox, "detect_multiarch", lambda: "x86_64-linux-gnu")
    monkeypatch.setattr(sandbox, "create_volume", lambda name: pytest.fail("must not install"))
    report = client.run_scan(scan.parse_spec("pypi:sandglass-test-tampered@1.0.0"), POLICY, REGISTRY)
    assert report["verdict"] == "INCOMPLETE"
    assert report["incomplete_reasons"][0].startswith(
        "package hash mismatch: sandglass_test_tampered-1.0.0-py3-none-any.whl has sha256 ")
    h = report["package"]["hash"]
    assert h["match"] is False and h["ours"] == report["package"]["files"][0]["sha256"]
    assert "DOES NOT MATCH" in next(tmp_path.glob("*.md")).read_text()


def test_matching_test_packages_record_their_hashes(registry, tmp_path):
    prepared = scan.download(scan.parse_spec("npm:sandglass-test-notes@1.0.0"), tmp_path,
                             "x86_64-linux-gnu", REGISTRY)
    result = scan.verify_hash(prepared, REGISTRY)
    assert result["match"] is True and result["algorithm"] == "sha512"
    assert result["source"] == "the local test registry (npm-meta/sandglass-test-notes/1.0.0.json)"
    assert scan.describe_files(prepared)[0]["sha256"] == hashlib.sha256(prepared.artifact.read_bytes()).hexdigest()
    assert PROJECT_ROOT in REGISTRY.parents
