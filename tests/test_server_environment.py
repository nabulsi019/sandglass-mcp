"""The server's environment (#146): no Sandglass name in it.

The real-sandbox check is in scripts/check_fixtures.py (EXPECTED_ENVIRONMENT);
these tests need no Docker.
"""

import json
import subprocess
import sys

from sandglass import PROJECT_ROOT, sandbox

SERVER = PROJECT_ROOT / "test_servers" / "env_report_server.py"
NODE_SERVER = PROJECT_ROOT / "test_servers" / "env_report_server.js"


def env_of(args: list[str]) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == "-e"]


def test_no_sandglass_variable_is_passed_to_any_container():
    commands = [sandbox.docker_command(SERVER)[1], sandbox.docker_command(NODE_SERVER)[1],
                sandbox.scan_run_command("v", "/package/site/bin/x", "python")[1],
                sandbox.scan_run_command("v", "/package/node_modules/x/cli", "node")[1]]
    for args in commands:
        assert env_of(args) == ["HOME=/home/sandglass"]


def test_runtime_and_site_dir_are_launcher_arguments():
    assert sandbox.docker_command(SERVER)[1][-2:] == ["python", ""]
    assert sandbox.docker_command(NODE_SERVER)[1][-2:] == ["node", ""]
    assert sandbox.scan_run_command("v", "/p", "python")[1][-2:] == ["python", "/package/site"]
    assert sandbox.scan_run_command("v", "/p", "node")[1][-2:] == ["node", ""]


def test_the_launcher_reads_them_from_argv_and_deletes_any_sandglass_variable():
    main = sandbox.LAUNCHER[sandbox.LAUNCHER.index("def main()"):]
    assert "server, runtime, site_dir = sys.argv[1:4]" in main  # (#159: no helper source)
    assert "os.environ.get(" not in main  # nothing read from the environment any more
    assert 'n.upper().startswith("SANDGLASS")' in main and "del os.environ[name]" in main
    # Deleted before the server starts (Node exec, or Python's runpy), after the fd swap.
    assert main.index("os.close(3)") < main.index("del os.environ[name]") < main.index("os.execv(NODE")
    assert main.index("del os.environ[name]") < main.index("runpy.run_path(")
    assert 'if runtime == "node":' in main


def test_sh_unsets_the_build_variables_before_tracing(tmp_path):
    # Run the real sh script on the host with a fake `strace` that prints the
    # environment it was started with: the variables are gone, the rest stays.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    strace = fake_bin / "strace"
    strace.write_text(f"#!{sys.executable}\nimport json, os\nprint(json.dumps(dict(os.environ)))\n")
    strace.chmod(0o755)
    args = sandbox.docker_command(SERVER)[1]
    i = args.index("sh")
    script = args[i + 2].replace(str(sandbox.CONTAINER_WORKDIR), str(tmp_path / "work"))
    env = {"PATH": f"{fake_bin}:/usr/bin:/bin", "LANG": "C.UTF-8", "GPG_KEY": "x",
           "PYTHON_VERSION": "3.12", "PYTHON_SHA256": "y", "HOME": "/home/sandglass"}
    out = subprocess.run(["sh", "-c", script, *args[i + 3:]], capture_output=True, text=True,
                         cwd=tmp_path, env=env, check=True)
    seen = json.loads(out.stdout)
    for name in sandbox.UNSET_BEFORE_TRACING:
        assert name not in seen
    assert seen["LANG"] == "C.UTF-8" and seen["HOME"] == "/home/sandglass"


def test_the_image_keeps_uv_settings_to_the_build_step():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    env_lines = [line for line in dockerfile.splitlines() if line.startswith("ENV ")]
    assert not any("UV_" in line for line in env_lines)
    assert "RUN UV_PROJECT_ENVIRONMENT=/opt/venv UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy" in dockerfile
