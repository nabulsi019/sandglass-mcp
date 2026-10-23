"""Install capture (#16): the install runs under strace, and its trace is judged.

Hand-written traces (no Docker). The lines look like the real ones from
installing our test packages (strace -y, so fds carry their paths).
"""

from pathlib import Path

import pytest

from sandglass import PROJECT_ROOT, sandbox, scan
from sandglass.compare import _markdown, build_report, compare_install, not_run, with_install
from sandglass.policy import load_install_baseline, load_policy
from sandglass.trace_parser import parse_trace
from tests.test_sandbox_pipeline import EXITED, LAUNCH, run

POLICY = load_policy(PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml",
                     in_sandbox=True, multiarch="x86_64-linux-gnu",
                     container_script="/package/node_modules/x/server.js", package_dir="/package")
BASELINE = load_install_baseline("x86_64-linux-gnu")

# The installer's shell (strace can't read the first exec's arguments) ...
START = "8     10:00:00.000001 execve(0x7ffdc67270d0, 0x7ffdc6728518, 0x7ffdc6728548) = 0"
# ... npm doing its job ...
NPM = [
    '8     10:00:00.1 execve("/usr/bin/cp", ["cp", "/download/project/package.json", "/package/"], 0x5 /* 9 vars */) = 0',
    '9     10:00:00.2 execve("/usr/bin/npm", ["npm", "install", "--offline"], 0x5 /* 9 vars */) = 0',
    '9     10:00:00.3 execve("/usr/bin/node", ["node", "/usr/bin/npm", "install"], 0x5 /* 9 vars */) = 0',
    '9     10:00:00.4 openat(AT_FDCWD</package>, "/usr/share/nodejs/npm/lib/cli.js", O_RDONLY|O_CLOEXEC) = 17</usr/share/nodejs/npm/lib/cli.js>',
    '9     10:00:00.5 openat(AT_FDCWD</package>, "/etc/npmrc", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
    '9     10:00:00.6 bind(18<socket:[1]>, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0',
    '9     10:00:00.7 mkdirat(AT_FDCWD</package>, "node_modules", 0777) = 0',
    '9     10:00:00.8 openat(17</package/node_modules>, "x/server.js", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 19</package/node_modules/x/server.js>',
    '9     10:00:00.9 openat(AT_FDCWD</package>, "/tmp/npm-cache/index", O_RDWR|O_CREAT, 0644) = 20</tmp/npm-cache/index>',
    '9     10:00:01.0 openat(AT_FDCWD</package>, "/etc", O_RDONLY|O_DIRECTORY) = 21</etc>',
]
DONE = "8     10:00:02.000000 +++ exited with 0 +++"


def judge(lines, exit_code=0, log=""):
    events = parse_trace("\n".join([START] + lines + [DONE]), cwd="/package")
    return compare_install(events, POLICY, BASELINE, exit_code, log)


def found(result):
    return [(v["mode"], v["target"]) for v in result["violations"]]


def test_the_installers_own_work_is_clean():
    result = judge(NPM)
    assert found(result) == [] and result["incomplete_reasons"] == []
    assert [a["target"] for a in result["attempted"]] == []  # /etc/npmrc is in the baseline


@pytest.mark.parametrize("line, expected", [
    # A postinstall script reading the decoy credentials (relative to its own folder).
    ('12    10:00:01.5 openat(AT_FDCWD</package/node_modules/x>, "../../../home/sandglass/.aws/credentials", O_RDONLY) = 3</home/sandglass/.aws/credentials>',
     [("read", "/home/sandglass/.aws/credentials")]),
    ('12    10:00:01.5 openat(AT_FDCWD</package/node_modules/x>, "/etc/passwd", O_RDONLY) = 3</etc/passwd>',
     [("read", "/etc/passwd")]),
    # Running something besides the installer's tools.
    ('12    10:00:01.5 execve("/usr/bin/id", ["id"], 0x5 /* 9 vars */) = 0', [(None, "/usr/bin/id")]),
    # Any network attempt (there is no sink during the install).
    ('12    10:00:01.5 connect(5<socket:[2]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ENETUNREACH (Network is unreachable)',
     [(None, '{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}')]),
    # A link in /tmp to a secret: the read through it would look like a /tmp read.
    ('12    10:00:01.5 symlink("/home/sandglass/.aws/credentials", "/tmp/c") = 0',
     [("write", "/home/sandglass/.aws/credentials")]),
    ('12    10:00:01.5 symlinkat("../home/sandglass/.ssh/id_rsa", 4</tmp>, "k") = 0',
     [("write", "/home/sandglass/.ssh/id_rsa")]),
    # Listing /etc is fine (pip does it), reading inside it is not.
    ('12    10:00:01.5 openat(AT_FDCWD</package>, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)',
     [("read", "/etc/shadow")]),
])
def test_install_misbehaviour_is_flagged_in_the_install_phase(line, expected):
    result = judge(NPM + [line])
    assert found(result) == expected
    assert {v["phase"] for v in result["violations"]} == {"install"}


def test_a_failed_install_is_incomplete_with_the_end_of_its_log():
    result = judge(NPM, exit_code=1, log="npm ERR! ENOTCACHED")
    assert result["incomplete_reasons"] == [
        "the install failed (exit 1); the server was not run. End of the install log: npm ERR! ENOTCACHED"]
    assert judge(NPM, exit_code=None)["incomplete_reasons"] == ["the install took too long and was stopped"]


def test_a_truncated_install_trace_is_incomplete():
    events = parse_trace("\n".join([START] + NPM), cwd="/package")  # no exit record
    result = compare_install(events, POLICY, BASELINE, 0)
    assert result["incomplete_reasons"] == [
        "the install trace has no exit record for the installer (possibly truncated)"]
    assert compare_install([], POLICY, BASELINE, 0)["incomplete_reasons"] == [
        "the install trace is missing or empty"]


def test_install_findings_join_the_run_and_set_the_verdict():
    clean_run = run([LAUNCH, EXITED])
    assert clean_run["verdict"] == "CLEAN"
    creds = '12    10:00:01.5 openat(AT_FDCWD</x>, "/home/sandglass/.aws/credentials", O_RDONLY) = 3</y>'
    merged = with_install(clean_run, judge(NPM + [creds]))
    assert merged["verdict"] == "VIOLATIONS"
    assert [(v["target"], v["phase"]) for v in merged["violations"]] == [
        ("/home/sandglass/.aws/credentials", "install")]
    # A failed install: the server never ran, the install gives the reason.
    failed = with_install(not_run(None), judge(NPM, exit_code=1))
    assert failed["verdict"] == "INCOMPLETE" and failed["incomplete_reasons"][0].startswith("the install failed")


def test_markdown_lists_install_violations_under_install():
    creds = '12    10:00:01.5 openat(AT_FDCWD</x>, "/home/sandglass/.aws/credentials", O_RDONLY) = 3</y>'
    install = judge(NPM + [creds])
    package = {"spec": "npm:x@1.0.0", "source": "local", "files": [], "entry": None,
               "install": {"trace_file": "i.txt", "log_file": "l.txt", "exit_code": 0,
                           "baseline": BASELINE.name, "violations": 1}}
    report = build_report("x", "t", POLICY, {"tools": [], "calls": []},
                          with_install(run([LAUNCH, EXITED]), install), Path("trace.txt"), {},
                          {"name": "b", "file": "f", "multiarch": "m"}, package)
    md = _markdown(report)
    assert "/home/sandglass/.aws/credentials" in md[md.index("### Install"):md.index("### Startup")]
    assert "traced (exit 0; 1 violation(s)" in md and "install trace: `i.txt`" in md


# --- the parser and strace -y ----------------------------------------------------

@pytest.mark.parametrize("line, target", [
    ('9 10:00:00.1 unlinkat(3</tmp/pip-x/lib>, "RECORD", 0) = 0', "/tmp/pip-x/lib/RECORD"),
    ('9 10:00:00.1 openat(AT_FDCWD</package/node_modules/x>, "notes/a.txt", O_RDONLY) = 17</p>', "/package/node_modules/x/notes/a.txt"),
    ('9 10:00:00.1 openat(3</tmp/a\\"b>, "notes", O_RDONLY) = 4</tmp/a\\"b/notes>', '/tmp/a"b/notes'),   # a quote inside <...>
    ('9 10:00:00.1 openat(3</tmp/a\\76b>, "n", O_RDONLY) = 4', "/tmp/a>b/n"),                             # ">" is escaped as \\76
    ('9 10:00:00.1 openat(AT_FDCWD, "/x/3<y>", O_RDONLY) = 4', "/x/3<y>"),                                # a NAME that looks like -y
    ('9 10:00:00.1 renameat2(3</tmp/a>, "x", 4</package/site>, "y", RENAME_NOREPLACE) = 0', "/package/site/y"),
    ('9 10:00:00.1 renameat2(3</tmp/a>, "x", AT_FDCWD, "y", RENAME_NOREPLACE) = 0', "/package/y"),
    ('9 10:00:00.1 openat(3, "notes", O_RDONLY) = 4', "<dirfd 3>/notes"),                                 # no -y: unknown
])
def test_parser_uses_the_folders_strace_y_prints(line, target):
    assert parse_trace(line, cwd="/package")[0].target == target


def test_a_returned_fd_path_cannot_change_the_result():
    # A file named "a) = -1 ENOENT (b" in /tmp: the open still succeeded.
    event = parse_trace('9 10:00:00.1 openat(AT_FDCWD, "/tmp/a) = -1 ENOENT (b", O_RDONLY) = 3</tmp/a) = -1 ENOENT (b>')[0]
    assert (event.target, event.succeeded, event.error) == ("/tmp/a) = -1 ENOENT (b", True, None)


def test_parser_records_where_links_point():
    events = parse_trace("\n".join([
        '9 10:00:00.1 symlink("../home/sandglass/.aws/credentials", "/tmp/c") = 0',
        '9 10:00:00.1 symlinkat("/etc/passwd", 3</tmp>, "p") = 0',
        '9 10:00:00.1 linkat(3</tmp>, "a", AT_FDCWD, "/tmp/b", 0) = 0',
        '9 10:00:00.1 openat(AT_FDCWD, "/tmp/c", O_RDONLY) = 3',
    ]))
    assert [(e.target, e.link_target) for e in events] == [
        ("/tmp/c", "/home/sandglass/.aws/credentials"), ("/tmp/p", "/etc/passwd"),
        ("/tmp/b", "/tmp/a"), ("/tmp/c", None)]


# --- the install container ---------------------------------------------------------

def test_install_runs_under_strace_and_never_holds_the_trace_stream(tmp_path):
    _, args = sandbox.scan_install_command("vol1", tmp_path, scan.NPM_INSTALL_SCRIPT, [],
                                           env=scan.NPM_ENV, name="vol1-install")
    joined = " ".join(args)
    traced = args[args.index("-c") + 1]
    assert "exec strace -f -tt -y -e trace=" in traced and "--kill-on-exit" in traced
    assert "-o /proc/self/fd/2" in traced
    # The traced shell's first act: its stderr (the trace stream) becomes stdout.
    assert '/bin/sh -c "exec 2>&1; $script"' in traced
    assert "--network none" in joined and "--read-only" in joined and "--user 10001:10001" in joined
    assert "--cap-add" not in joined and "--privileged" not in joined
    assert [args[i + 1] for i, a in enumerate(args) if a == "-v"] == [
        f"{tmp_path}:/download:ro", "vol1:/package"]
    assert args[args.index("--name") + 1] == "vol1-install"


def test_install_baseline_loads():
    assert BASELINE.name == "install + python312_slim + node_debian"
    assert [str(p) for p in BASELINE.write_allow] == ["/package", "/tmp", "/dev/null"]
    assert "/usr/lib/x86_64-linux-gnu/nodejs" in map(str, BASELINE.read_allow)
    assert BASELINE.network_families_allow == ["AF_NETLINK"]
    # The decoy home is never in it.
    assert not any(str(p).startswith("/home") for p in BASELINE.read_allow)
