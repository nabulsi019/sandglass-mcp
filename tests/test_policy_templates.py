"""Standard policy templates (#112): each one allows what it says, flags the rest.

Hand-written traces through compare(), like tests/test_sandbox_pipeline.py.
"""

import re

import pytest

from sandglass import PROJECT_ROOT
from sandglass.policy import load_policy
from tests.test_sandbox_pipeline import EXITED, LAUNCH, SERVER, run

TEMPLATES = PROJECT_ROOT / "policies" / "templates"


def template(name: str):
    return load_policy(TEMPLATES / f"{name}.v1.yaml", server_script=SERVER, in_sandbox=True,
                       multiarch="x86_64-linux-gnu")


def judge(name: str, line: str) -> tuple[str, list]:
    """Verdict and (mode, target) violations for one event under a template."""
    result = run([LAUNCH, line, EXITED], policy=template(name))
    return result["verdict"], [(v["mode"], v["target"]) for v in result["violations"]]


def read(path):
    return f'8 10:00:00.2 openat(AT_FDCWD, "{path}", O_RDONLY|O_CLOEXEC) = 3'


def write(path):
    return f'8 10:00:00.2 openat(AT_FDCWD, "{path}", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3'


EXEC_SH = '8 10:00:00.2 execve("/bin/sh", ["sh", "-c", "true"], 0x0 /* 8 vars */) = 0'
CONNECT = ('8 10:00:00.2 connect(5, {sa_family=AF_INET, sin_port=htons(443), '
           'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (Network is unreachable)')


def asked_sink_for(host):
    """The server connecting to the sink, and the sink (pid 9) recording a
    request for `host` (two trace lines: every connection has its record, #136)."""
    return ('8 10:00:00.25 connect(5, {sa_family=AF_INET, sin_port=htons(18080), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
            f'9 10:00:00.3 newfstatat(AT_FDCWD, "/sandglass-netsink/CONNECT/{host}/443", '
            '0x7ffe8cb57b40, 0) = -1 ENOENT (No such file or directory)')


CREDS = "/home/sandglass/.aws/credentials"


# --- read_only_folder.v1 ---------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    (read("/data/notes/hello.txt"), ("CLEAN", [])),
    (read(CREDS), ("VIOLATIONS", [("read", CREDS)])),
    (read("/etc/passwd"), ("VIOLATIONS", [("read", "/etc/passwd")])),
    (write("/data/notes/hello.txt"), ("VIOLATIONS", [("write", "/data/notes/hello.txt")])),
    (write("/tmp/cache"), ("VIOLATIONS", [("write", "/tmp/cache")])),
    (EXEC_SH, ("VIOLATIONS", [(None, "/bin/sh")])),
    (CONNECT, ("VIOLATIONS", [(None, '{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}')])),
    (asked_sink_for("api.example.com"), ("VIOLATIONS", [("domain", "api.example.com")])),
])
def test_read_only_folder(line, expected):
    assert judge("read_only_folder", line) == expected


# --- no_network.v1 ---------------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    (read(CREDS), ("VIOLATIONS", [("read", CREDS)])),   # read_deny: /home (#121)
    (read("/root/.ssh/id_rsa"), ("VIOLATIONS", [("read", "/root/.ssh/id_rsa")])),
    (read("/etc/passwd"), ("CLEAN", [])),         # other reads aren't restricted (documented)
    (write("/tmp/cache"), ("CLEAN", [])),
    (write("/home/sandglass/.bashrc"), ("VIOLATIONS", [("write", "/home/sandglass/.bashrc")])),
    (EXEC_SH, ("VIOLATIONS", [(None, "/bin/sh")])),
    (CONNECT, ("VIOLATIONS", [(None, '{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}')])),
    (asked_sink_for("api.example.com"), ("VIOLATIONS", [("domain", "api.example.com")])),
])
def test_no_network(line, expected):
    assert judge("no_network", line) == expected


# --- listed_domains_only.v1 ------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    (asked_sink_for("api.example.com"), ("CLEAN", [])),
    (asked_sink_for("evil.example.net"), ("VIOLATIONS", [("domain", "evil.example.net")])),
    (asked_sink_for("sub.api.example.com"), ("VIOLATIONS", [("domain", "sub.api.example.com")])),  # exact only
    (CONNECT, ("VIOLATIONS", [(None, '{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}')])),
    (read(CREDS), ("VIOLATIONS", [("read", CREDS)])),   # read_deny: /home (#121)
    (read("/etc/passwd"), ("CLEAN", [])),
    (write("/tmp/cache"), ("CLEAN", [])),
    (write("/opt/venv/lib/x.py"), ("VIOLATIONS", [("write", "/opt/venv/lib/x.py")])),
    (EXEC_SH, ("VIOLATIONS", [(None, "/bin/sh")])),
])
def test_listed_domains_only(line, expected):
    assert judge("listed_domains_only", line) == expected


# --- every template ----------------------------------------------------------------

def all_templates():
    return sorted(TEMPLATES.glob("*.yaml"))


def test_there_are_three_templates():
    assert [p.name for p in all_templates()] == [
        "listed_domains_only.v1.yaml", "no_network.v1.yaml", "read_only_folder.v1.yaml"]


@pytest.mark.parametrize("path", all_templates(), ids=lambda p: p.name)
def test_template_is_versioned_and_named_after_its_file(path):
    match = re.fullmatch(r"([a-z_]+)\.v(\d+)\.yaml", path.name)
    assert match, f"{path.name}: templates are named <name>.v<N>.yaml"
    policy = load_policy(path, server_script=SERVER)  # host mode loads too
    assert policy.name == f"{match[1]}_v{match[2]}"
    assert f"version {match[2]}" in path.read_text(encoding="utf-8").splitlines()[0]


@pytest.mark.parametrize("path", all_templates(), ids=lambda p: p.name)
def test_template_is_documented_in_the_readme(path):
    assert f"policies/templates/{path.name}" in (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("name, deny", [
    ("no_network", ["/home", "/root"]),
    ("listed_domains_only", ["/home", "/root"]),
    ("read_only_folder", []),   # reads only /data anyway
])
def test_read_anywhere_templates_deny_home_folders(name, deny):
    assert [str(p) for p in template(name).read_deny] == deny


@pytest.mark.parametrize("path", all_templates(), ids=lambda p: p.name)
def test_templates_never_allow_the_network_or_programs(path):
    # Domains go through the sink only; no direct network, no extra programs.
    policy = load_policy(path, server_script=SERVER, in_sandbox=True, multiarch="x86_64-linux-gnu")
    assert policy.network_allow is False and policy.exec_allow == []
