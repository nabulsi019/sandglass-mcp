"""`sandglass scan` (#19): spec parsing, download/install commands, entry points.

No Docker and no network: real registries are never contacted. The local
test registry (test_packages/dist, built from our own test packages) is used
with pip's --no-index.
"""

import importlib.util
import json

import pytest

from sandglass import PROJECT_ROOT, client, sandbox, scan
from sandglass.scan import PackageSpec, ScanError, SpecError, choose_entry, parse_spec

spec = importlib.util.spec_from_file_location("build_test_packages",
                                              PROJECT_ROOT / "scripts" / "build_test_packages.py")
build_test_packages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_test_packages)

REGISTRY = PROJECT_ROOT / "test_packages" / "dist"
POLICY = PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml"


# --- spec parsing --------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("pypi:mcp-server-fetch@2025.4.7", PackageSpec("pypi", "mcp-server-fetch", "2025.4.7")),
    ("pypi:Some_Package.Name@1.0rc1", PackageSpec("pypi", "Some_Package.Name", "1.0rc1")),
    ("pypi:pkg@2.0.post1", PackageSpec("pypi", "pkg", "2.0.post1")),
    ("pypi:pkg@1!2.0.dev3", PackageSpec("pypi", "pkg", "1!2.0.dev3")),
    ("npm:@modelcontextprotocol/server-everything@2025.1.14",
     PackageSpec("npm", "@modelcontextprotocol/server-everything", "2025.1.14")),
    ("npm:left-pad@1.3.0", PackageSpec("npm", "left-pad", "1.3.0")),
    ("npm:pkg@1.2.3-beta.1+build.5", PackageSpec("npm", "pkg", "1.2.3-beta.1+build.5")),
])
def test_valid_specs(text, expected):
    assert parse_spec(text) == expected


@pytest.mark.parametrize("text, message", [
    ("mcp-server-fetch@1.0.0", "expected <pypi|npm>"),
    ("cargo:pkg@1.0.0", "expected <pypi|npm>"),
    ("pypi:pkg", "missing @<exact-version>"),
    ("pypi:pkg@", "missing @<exact-version>"),
    ("pypi:pkg@latest", "'latest' is not allowed"),
    ("npm:pkg@latest", "'latest' is not allowed"),
    ("pypi:pkg@>=1.0", "not an exact version"),
    ("pypi:pkg@~=1.2", "not an exact version"),
    ("pypi:pkg@1.*", "not an exact version"),
    ("pypi:pkg@1.0+local", "not an exact version"),
    ("pypi:pkg@1.0,<2", "not an exact version"),
    ("npm:pkg@^1.2.3", "not an exact version"),
    ("npm:pkg@~1.2.3", "not an exact version"),
    ("npm:pkg@1.x", "not an exact version"),
    ("npm:pkg@1.2", "not an exact version"),
    ("npm:pkg@v1.2.3", "not an exact version"),
    ("npm:pkg@1.2.3 || 2.0.0", "not an exact version"),
    ("npm:Pkg@1.2.3", "not a valid npm package name"),
    ("pypi:-bad@1.0", "not a valid PyPI project name"),
    ("pypi:../../etc@1.0", "not a valid PyPI project name"),
])
def test_malformed_specs_are_refused(text, message):
    with pytest.raises(SpecError, match=message):
        parse_spec(text)


def test_slug_is_file_name_safe():
    assert parse_spec("npm:@scope/pkg@1.0.0").slug == "npm_scope-pkg_1.0.0"


# --- the command line ------------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["pypi:pkg@latest", "--policy", str(POLICY)],
    ["npm:pkg@^1.0.0", "--policy", str(POLICY)],
    ["pypi:pkg@1.0.0"],                                   # --policy is required
    ["pypi:pkg@1.0.0", "--policy", "no/such/policy.yaml"],
])
def test_usage_errors_exit_2_before_anything_runs(argv, monkeypatch, capsys):
    monkeypatch.setattr(client, "run_scan", lambda *a: pytest.fail("must not run"))
    with pytest.raises(SystemExit) as exit_info:
        client.scan_main(argv)
    assert exit_info.value.code == 2
    assert "usage: sandglass scan" in capsys.readouterr().err


@pytest.mark.parametrize("verdict, code", [("CLEAN", 0), ("VIOLATIONS", 1), ("INCOMPLETE", 2)])
def test_exit_code_is_the_verdict(verdict, code, monkeypatch):
    monkeypatch.setattr(client, "run_scan", lambda *a: {"verdict": verdict})
    with pytest.raises(SystemExit) as exit_info:
        client.scan_main(["pypi:pkg@1.0.0", "--policy", str(POLICY)])
    assert exit_info.value.code == code


def test_sandglass_scan_goes_to_the_scan_command(monkeypatch):
    seen = []
    monkeypatch.setattr(client, "scan_main", seen.append)
    monkeypatch.setattr("sys.argv", ["sandglass", "scan", "pypi:pkg@1.0.0", "--policy", "p.yaml"])
    client.main()
    assert seen == [["pypi:pkg@1.0.0", "--policy", "p.yaml"]]


def test_a_failed_download_still_writes_an_incomplete_report(monkeypatch, tmp_path):
    monkeypatch.setattr(client, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(sandbox, "detect_multiarch", lambda: "x86_64-linux-gnu")

    def fail(*args):
        raise ScanError("pip download (on the host) failed (exit 1): no matching distribution")
    monkeypatch.setattr(scan, "download", fail)
    report = client.run_scan(parse_spec("pypi:pkg@1.0.0"), POLICY)
    assert report["verdict"] == "INCOMPLETE"
    assert report["incomplete_reasons"] == ["pip download (on the host) failed (exit 1): no matching distribution"]
    assert report["trace_file"] is None and report["package"]["spec"] == "pypi:pkg@1.0.0"
    md = next(tmp_path.glob("*.md")).read_text()
    assert "## Package" in md and "Trace: none (the server was not run)" in md


# --- download (local test registry, no network) ------------------------------------

@pytest.fixture(scope="module")
def registry():
    build_test_packages.build_all()
    return REGISTRY


def test_pip_download_is_wheels_only_for_the_containers_platform(tmp_path):
    command = scan.pip_download_command(parse_spec("pypi:pkg@1.0.0"), tmp_path, "aarch64-linux-gnu", None)
    joined = " ".join(command)
    assert "--only-binary=:all:" in command          # never an sdist (its setup.py would run here)
    assert "--python-version 3.12" in joined and "--implementation cp" in joined
    assert "--platform manylinux_2_41_aarch64" in joined and "--platform manylinux2014_aarch64" in joined
    assert "x86_64" not in joined
    assert "--no-index" not in command               # real PyPI unless --registry-dir
    assert command[-1] == "pkg==1.0.0"


def test_pypi_download_from_the_local_registry(registry, tmp_path):
    prepared = scan.download(parse_spec("pypi:sandglass-test-notes@1.0.0"), tmp_path,
                             "x86_64-linux-gnu", registry)
    assert [f.name for f in prepared.files] == ["sandglass_test_notes-1.0.0-py3-none-any.whl"]
    assert prepared.entries == {"sandglass-test-notes": "/package/site/bin/sandglass-test-notes"}


def test_npm_download_from_the_local_registry(registry, tmp_path):
    prepared = scan.download(parse_spec("npm:sandglass-test-notes@1.0.0"), tmp_path,
                             "x86_64-linux-gnu", registry)
    assert [f.name for f in prepared.files] == ["sandglass-test-notes-1.0.0.tgz"]
    assert prepared.entries == {
        "sandglass-test-notes": "/package/node_modules/sandglass-test-notes/server.js"}
    manifest = json.loads((tmp_path / "project" / "package.json").read_text())
    assert manifest["dependencies"] == {"sandglass-test-notes": "file:/download/sandglass-test-notes-1.0.0.tgz"}


def test_unknown_package_in_the_local_registry_is_a_scan_error(registry, tmp_path):
    with pytest.raises(ScanError, match="pip download"):
        scan.download(parse_spec("pypi:not-there@1.0.0"), tmp_path, "x86_64-linux-gnu", registry)
    with pytest.raises(ScanError, match="not-there-1.0.0.tgz is not in"):
        scan.download(parse_spec("npm:not-there@1.0.0"), tmp_path, "x86_64-linux-gnu", registry)


def test_test_packages_build_byte_identical_every_time(registry):
    first = {p.name: p.read_bytes() for p in registry.rglob("*.*")}
    build_test_packages.build_all()
    assert {p.name: p.read_bytes() for p in registry.rglob("*.*")} == first


# --- entry points ------------------------------------------------------------------

def prepared_with(entries, name="pkg"):
    return scan.Prepared(PackageSpec("npm", name, "1.0.0"), folder=None, entries=entries)


def test_entry_choice():
    one = prepared_with({"srv": "/package/a.js"})
    assert choose_entry(one, None) == ("srv", "/package/a.js")
    several = prepared_with({"pkg": "/package/a.js", "pkg-admin": "/package/b.js"})
    assert choose_entry(several, None) == ("pkg", "/package/a.js")         # named like the package
    assert choose_entry(several, "pkg-admin") == ("pkg-admin", "/package/b.js")
    with pytest.raises(ScanError, match="pick one with --entry"):
        choose_entry(prepared_with({"a": "/x", "b": "/y"}), None)
    with pytest.raises(ScanError, match="no entry point"):
        choose_entry(prepared_with({}), None)
    with pytest.raises(ScanError, match="is not one of"):
        choose_entry(one, "other")


def test_npm_bin_forms():
    s = PackageSpec("npm", "@scope/tool", "1.0.0")
    assert scan._npm_bins(s, {"bin": "cli.js"}) == {"tool": "cli.js"}
    assert scan._npm_bins(s, {"bin": {"a": "a.js", "b": "bin/b"}}) == {"a": "a.js", "b": "bin/b"}
    assert scan._npm_bins(s, {}) == {}


# --- the two containers ------------------------------------------------------------

def test_install_container_is_offline_and_only_the_volume_is_writable(tmp_path):
    _, args = sandbox.scan_install_command("vol1", tmp_path, scan.PIP_INSTALL_SCRIPT, ["pkg==1.0.0"])
    joined = " ".join(args)
    assert "--network none" in joined and "--read-only" in joined
    assert "--user 10001:10001" in joined and "-e HOME=/home/sandglass" in joined
    assert "--cap-add" not in joined and "--privileged" not in joined
    volumes = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
    assert volumes == [f"{tmp_path}:/download:ro", "vol1:/package"]
    # The package spec is an argument of the fixed script, never part of it.
    assert args[-1] == "pkg==1.0.0" and "pkg==1.0.0" not in scan.PIP_INSTALL_SCRIPT


def env_of(args):
    """The -e NAME=value settings of a docker run command."""
    return [args[i + 1] for i, a in enumerate(args) if a == "-e"]


def test_run_container_mounts_the_package_read_only():
    _, args = sandbox.scan_run_command("vol1", "/package/site/bin/x", "python")
    joined = " ".join(args)
    assert "--network none" in joined and "--read-only" in joined and "--user 10001:10001" in joined
    assert "vol1:/package:ro" in joined
    assert "--cap-add" not in joined and "--privileged" not in joined
    assert env_of(args) == ["HOME=/home/sandglass", "SANDGLASS_RUNTIME=python",
                            "SANDGLASS_SITE_DIR=/package/site"]
    # The traced command is the same as for fixtures (strace, fd 3 to /dev/null).
    assert "-o /proc/self/fd/2" in joined and "3>/dev/null" in joined
    assert args[-3] == "/package/site/bin/x"


def test_npm_runs_with_node_and_no_site_dir():
    _, args = sandbox.scan_run_command("vol1", "/package/node_modules/x/cli", "node")
    assert env_of(args) == ["HOME=/home/sandglass", "SANDGLASS_RUNTIME=node"]


def test_launcher_adds_the_site_dir_after_the_fd_swap_not_via_pythonpath():
    main = sandbox.LAUNCHER[sandbox.LAUNCHER.index("def main()"):]
    assert main.index("os.close(3)") < main.index("site.addsitedir(") < main.index("runpy.run_path(")
    assert not any(e.startswith("PYTHONPATH") for e in env_of(sandbox.scan_run_command("v", "/p", "python")[1]))


def test_scan_policy_allows_reads_of_the_package_but_not_writes():
    from sandglass.policy import load_policy
    policy = load_policy(POLICY, in_sandbox=True, multiarch="x86_64-linux-gnu",
                         container_script="/package/site/bin/x", package_dir="/package")
    assert "/package" in map(str, policy.runtime_allow)
    assert policy.write_allow == []
    assert "/package/site/bin" in map(str, policy.list_exact)
