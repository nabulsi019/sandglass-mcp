"""(#159) No command line in the container names Sandglass or carries its source.

No Docker: the docker commands are built and inspected. The real check (every
visible process's /proc/<pid>/cmdline) is process_list_server in
scripts/check_fixtures.py.
"""

import pytest

from sandglass import PROJECT_ROOT, launcher, sandbox, scan
from sandglass.scan import parse_spec

SERVER = PROJECT_ROOT / "test_servers" / "good_notes_server.py"


def after_image(args: list[str]) -> str:
    """What runs inside the container: everything after the image name."""
    return " ".join(args[args.index(sandbox.IMAGE) + 1:])


@pytest.mark.parametrize("args", [
    sandbox.docker_command(SERVER, ["--x"])[1],
    sandbox.scan_run_command("v", "/package/site/bin/x", "python")[1],
    sandbox.scan_install_command("v", PROJECT_ROOT, scan.PIP_INSTALL_SCRIPT, ["x==1"])[1],
], ids=["fixture run", "scan run", "install"])
def test_no_command_line_names_sandglass(args):
    inside = after_image(args)
    assert "sandglass" not in inside.lower()
    # No helper source on a command line, only the helpers' paths in the image.
    assert "def main()" not in inside and "import os" not in inside


def test_the_npm_download_container_names_no_sandglass(tmp_path):
    _, args = scan.npm_download_container_command(parse_spec("npm:demo@1.0.0"), tmp_path)
    assert "sandglass" not in after_image(args).lower()


def test_the_helpers_are_started_by_their_paths_in_the_image():
    assert str(sandbox.CONTAINER_LAUNCHER) == "/usr/local/lib/mcp-runtime/run.py"
    assert launcher.SINK_SCRIPT == "/usr/local/lib/mcp-runtime/sink.py"
    assert launcher.RELAY_SCRIPT == "/usr/local/lib/mcp-runtime/relay.py"
    for function, script in (("start_sink", "SINK_SCRIPT"), ("start_relay", "RELAY_SCRIPT")):
        body = sandbox.LAUNCHER[sandbox.LAUNCHER.index(f"def {function}()"):]
        body = body[:body.index("\ndef ")]
        assert f'[PYTHON, "-I", "-S", {script}]' in body


def test_the_dockerfile_copies_each_helper_where_the_launcher_starts_it():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    for name, path in sandbox.IMAGE_HELPERS.items():
        assert f"COPY sandglass/{name} {path}\n" in dockerfile


def test_a_stale_image_is_refused():
    import hashlib
    hashes = [hashlib.sha256((PROJECT_ROOT / "sandglass" / name).read_bytes()).hexdigest()
              for name in sandbox.IMAGE_HELPERS]
    assert sandbox.stale_helpers(hashes) == []
    assert sandbox.stale_helpers([hashes[0], "0" * 64, *hashes[2:]]) == ["netsink.py"]
    assert sandbox.stale_helpers(["missing"]) == list(sandbox.IMAGE_HELPERS)  # an image from before #159
