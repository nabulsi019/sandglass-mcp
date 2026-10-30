"""Server setup (#144): --server-arg, --env and the /tmp/work work folder.

The real-sandbox runs are in scripts/check_fixtures.py (EXPECTED_SERVER_SETUP);
these tests need no Docker.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sandglass import PROJECT_ROOT, client, sandbox
from sandglass.compare import _markdown, build_report
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, run, sandbox_policy

SERVER = PROJECT_ROOT / "test_servers" / "setup_required_server.py"
POLICY = PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml"


# --- --env: the refusal rules --------------------------------------------------

GLIBC_OR_SHELL = "read by glibc or the shell before tracing starts"


@pytest.mark.parametrize("name, reason", [
    ("PATH", "set by Sandglass"), ("HOME", "set by Sandglass"),
    ("HTTP_PROXY", "network sink"), ("HTTPS_PROXY", "network sink"), ("NO_PROXY", "network sink"),
    ("http_proxy", "network sink"), ("https_proxy", "network sink"), ("no_proxy", "network sink"),
    ("SANDGLASS_RUNTIME", "launcher"), ("SANDGLASS_SITE_DIR", "launcher"), ("sandglass_x", "launcher"),
    ("LD_PRELOAD", "trace stream"), ("LD_LIBRARY_PATH", "trace stream"),
    ("PYTHONPATH", "trace stream"), ("PYTHONSTARTUP", "trace stream"), ("PythonHome", "trace stream"),
    ("NODE_OPTIONS", "starts Node"),
    ("DOCKER_HOST", "docker command"), ("DOCKER_CONFIG", "docker command"),
    # Added on review: read before tracing starts, by glibc or by sh.
    ("GCONV_PATH", GLIBC_OR_SHELL), ("LOCPATH", GLIBC_OR_SHELL), ("GLIBC_TUNABLES", GLIBC_OR_SHELL),
    ("MALLOC_ARENA_MAX", GLIBC_OR_SHELL), ("MALLOC_CHECK_", GLIBC_OR_SHELL), ("MALLOC_", GLIBC_OR_SHELL),
    ("IFS", GLIBC_OR_SHELL), ("ENV", GLIBC_OR_SHELL), ("BASH_ENV", GLIBC_OR_SHELL),
    ("bash_env", GLIBC_OR_SHELL),
])
def test_refused_names(name, reason):
    with pytest.raises(ValueError, match=f"--env {name}: refused, .*{reason}"):
        client.parse_server_env([f"{name}=x"])


@pytest.mark.parametrize("name", ["MEMORY_FILE_PATH", "API_KEY", "ENVIRONMENT", "PATHS", "HOMEPAGE",
                                  "MALLOCX", "NODE_ENV", "_private", "LDAP_URL"])
def test_names_that_only_look_alike_are_allowed(name):
    assert client.parse_server_env([f"{name}=fake"]) == {name: "fake"}


@pytest.mark.parametrize("item, message", [
    ("NOVALUE", "expected KEY=VALUE"),
    ("=x", "not a valid variable name"),
    ("1ABC=x", "not a valid variable name"),
    ("A-B=x", "not a valid variable name"),
    ("A B=x", "not a valid variable name"),
])
def test_bad_formats(item, message):
    with pytest.raises(ValueError, match=message):
        client.parse_server_env([item])


def test_values_are_kept_as_given_and_names_only_once():
    assert client.parse_server_env(["A=", "B=x=y", "C= spaced 'quoted' $(not run)"]) == \
        {"A": "", "B": "x=y", "C": " spaced 'quoted' $(not run)"}
    with pytest.raises(ValueError, match="given twice"):
        client.parse_server_env(["A=1", "A=2"])


@pytest.mark.parametrize("argv", [
    ["sandglass", "test_servers/setup_required_server.py", "--policy", "policies/notes_readonly.yaml",
     "--sandbox", "--env", "LD_PRELOAD=/x.so"],
    ["sandglass", "test_servers/setup_required_server.py", "--env", "A=1"],         # needs --sandbox
    ["sandglass", "test_servers/setup_required_server.py", "--server-arg", "x"],    # needs --sandbox
])
def test_the_normal_run_refuses_with_exit_code_2(monkeypatch, argv):
    monkeypatch.chdir(PROJECT_ROOT)
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(client, "run_sandboxed", lambda *a: pytest.fail("must not run"))
    monkeypatch.setattr(client, "run_host", lambda *a: pytest.fail("must not run"))
    with pytest.raises(SystemExit) as exc:
        client.main()
    assert exc.value.code == 2


def test_scan_refuses_with_exit_code_2(monkeypatch, capsys):
    monkeypatch.setattr(client, "run_scan", lambda *a: pytest.fail("must not run"))
    with pytest.raises(SystemExit) as exc:
        client.scan_main(["pypi:x@1.0", "--policy", str(POLICY), "--env", "GLIBC_TUNABLES=x"])
    assert exc.value.code == 2
    assert "--env GLIBC_TUNABLES: refused, read by glibc or the shell" in capsys.readouterr().err


def test_scan_passes_the_setup_on(monkeypatch):
    seen = {}
    monkeypatch.setattr(client, "run_scan", lambda *a: seen.update(args=a) or {"verdict": "CLEAN"})
    with pytest.raises(SystemExit):
        client.scan_main(["pypi:x@1.0", "--policy", str(POLICY), "--server-arg", "stdio",
                          "--server-arg=--db-path", "--env", "MEMORY_FILE_PATH=/tmp/work/m.jsonl"])
    # Then the input mode (#145), the default when --inputs isn't given.
    assert seen["args"][4:] == (["stdio", "--db-path"], {"MEMORY_FILE_PATH": "/tmp/work/m.jsonl"},
                                "described")


# --- the docker command: values never on a command line --------------------------

def test_env_names_only_and_args_after_the_relay():
    args = sandbox.docker_command(SERVER, ["--note-name", "a b"], ["SETUP_TEST_TOKEN"])[1]
    env = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
    assert env == ["HOME=/home/sandglass", "SETUP_TEST_TOKEN"]  # no "=value"
    assert args[-8:] == [sandbox.LAUNCHER, "/project/test_servers/setup_required_server.py",
                         sandbox.NETSINK, sandbox.STDIN_RELAY, "python", "", "--note-name", "a b"]
    scan_args = sandbox.scan_run_command("v", "/package/x", "node", ["stdio"], ["K"])[1]
    assert scan_args[-4:] == [sandbox.STDIN_RELAY, "node", "", "stdio"]
    assert [scan_args[i + 1] for i, a in enumerate(scan_args) if a == "-e"] == \
        ["HOME=/home/sandglass", "K"]


def test_without_setup_the_command_only_gains_the_work_folder():
    args = sandbox.docker_command(SERVER)[1]
    assert args[-3:] == [sandbox.STDIN_RELAY, "python", ""]  # runtime and site dir (#146)
    script = args[args.index("sh") + 2]
    assert script.startswith("mkdir -m 0700 /tmp/work && cd /tmp/work && ")
    # The hardening flags are unchanged (the docker options, before the image name).
    joined = " ".join(args[:args.index(sandbox.IMAGE)])
    for flag in ("--network none", "--read-only", "--tmpfs /tmp", "--user 10001:10001",
                 "-e HOME=/home/sandglass"):
        assert flag in joined
    assert "--cap-add" not in joined and "seccomp" not in joined


def test_the_shell_passes_arguments_on_unchanged(tmp_path):
    # Run the real sh script on the host, with a fake `strace` that prints its
    # arguments and working directory: every argument arrives as one item,
    # exactly as given, and nothing in them is run by the shell.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    strace = fake_bin / "strace"
    strace.write_text(f"#!{sys.executable}\nimport json, os, sys\n"
                      "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd()}))\n")
    strace.chmod(0o755)
    tricky = ["stdio", "a b", "$(touch pwned)", "x; touch pwned2", "'\"", "--db-path", ""]
    args = sandbox.docker_command(SERVER, tricky)[1]
    i = args.index("sh")
    workdir = tmp_path / "work"
    script = args[i + 2].replace(str(sandbox.CONTAINER_WORKDIR), str(workdir))
    out = subprocess.run(["sh", "-c", script, *args[i + 3:]], capture_output=True, text=True,
                         cwd=tmp_path, env={"PATH": f"{fake_bin}:/usr/bin:/bin"}, check=True)
    seen = json.loads(out.stdout)
    python_args = seen["argv"][seen["argv"].index("-c") + 1:]
    assert python_args == [sandbox.LAUNCHER, "/project/test_servers/setup_required_server.py",
                           sandbox.NETSINK, sandbox.STDIN_RELAY, "python", "", *tricky]
    assert Path(seen["cwd"]).resolve() == workdir.resolve()
    assert oct(workdir.stat().st_mode & 0o777) == "0o700"
    assert not list(tmp_path.glob("pwned*")) and not list(workdir.glob("pwned*"))


def test_the_launcher_hands_the_arguments_to_python_and_node():
    main = sandbox.LAUNCHER[sandbox.LAUNCHER.index("def main()"):]
    assert "server_args = sys.argv[6:]" in main  # after the runtime and site dir (#146)
    assert "sys.argv = [server, *server_args]" in main
    assert "os.execv(NODE, [NODE, server, *server_args])" in main
    # Still after the fd swap and the filter (protected order, unchanged).
    assert main.index("os.close(3)") < main.index("filter_self_test()") < main.index("server_args =")


def test_the_client_gives_values_to_docker_through_its_environment(monkeypatch, tmp_path):
    seen = {}

    async def fake_run(params, *a):
        seen["params"] = params
        raise RuntimeError("stop here")

    monkeypatch.setattr(client, "run", fake_run)
    monkeypatch.setattr(client, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(sandbox, "detect_multiarch", lambda: "aarch64-linux-gnu")
    report = client.run_sandboxed(SERVER, POLICY, ["--note-name", "setup_note"],
                                  {"SETUP_TEST_TOKEN": "fake-token-for-tests"})
    params = seen["params"]
    assert params.env == {"SETUP_TEST_TOKEN": "fake-token-for-tests"}
    assert not any("fake-token-for-tests" in arg for arg in params.args)
    # The report: names only, never the value, and a command that reproduces the run.
    assert report["server_setup"] == {
        "args": ["--note-name", "setup_note"], "env": ["SETUP_TEST_TOKEN"], "workdir": "/tmp/work",
        "inputs": "described",
        "command": "sandglass test_servers/setup_required_server.py --policy "
                   f"{POLICY} --sandbox --inputs described --server-arg=--note-name --server-arg=setup_note "
                   "'--env=SETUP_TEST_TOKEN=<redacted>'"}
    assert report["path_mapping"]["/tmp/work"].startswith("the server's working directory")
    for path in tmp_path.glob("*_*.*"):
        assert "fake-token-for-tests" not in path.read_text(encoding="utf-8")


# --- the report -------------------------------------------------------------------

def test_markdown_header_shows_the_setup():
    setup = client.server_setup(["sandglass", "scan", "pypi:x@1.0", "--policy", "p.yaml"],
                                ["stdio"], {"MEMORY_FILE_PATH": "/tmp/work/m.jsonl"})
    session = {"tools": [{"name": "read_note"}],
               "calls": [{"tool": "read_note", "arguments": {}, "status": "OK", "result": "x"}]}
    report = build_report("x", "t", sandbox_policy(), session, run([LAUNCH, NOTE_READ, EXITED], session=session),
                          Path("trace.txt"), {}, {"name": "b", "file": "f", "multiarch": "m"}, None, setup)
    md = _markdown(report)
    assert ('- Server setup: arguments `["stdio"]`, environment `MEMORY_FILE_PATH` (values not recorded),'
            ' work dir `/tmp/work`') in md
    assert ("- Reproduce: `sandglass scan pypi:x@1.0 --policy p.yaml --inputs described --server-arg=stdio "
            "'--env=MEMORY_FILE_PATH=<redacted>'`") in md
    assert "/tmp/work/m.jsonl" not in md and "/tmp/work/m.jsonl" not in json.dumps(report)


def test_reports_without_setup_have_no_setup_lines():
    session = {"tools": [], "calls": []}
    report = build_report("x", "t", sandbox_policy(), session, run([LAUNCH, EXITED], session=session),
                          Path("trace.txt"), {}, {"name": "b", "file": "f", "multiarch": "m"})
    assert report["server_setup"] is None and "Server setup" not in _markdown(report)


def test_the_fixture_needs_its_setup(tmp_path):
    # On the host, without Docker: no setup -> it exits with its message.
    out = subprocess.run([sys.executable, str(SERVER)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, env={**os.environ, "SETUP_TEST_TOKEN": ""})
    assert out.returncode == 1 and "needs the arguments --note-name setup_note" in out.stderr
