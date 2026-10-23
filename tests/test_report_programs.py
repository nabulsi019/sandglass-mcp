"""The report's "Programs run" section and grouped Attempted list (#120).

No Docker. SAMPLE is a fixed excerpt of a real install trace: the npm
postinstall fixture (`sandglass scan npm:sandglass-test-postinstall@1.0.0`),
lines copied as strace -y printed them.
"""

from sandglass import PROJECT_ROOT
from sandglass.compare import (DEPENDENCY_HASH_NOTE, _markdown, build_report, compare_install,
                               group_attempted, not_run, with_install)
from sandglass.policy import load_install_baseline, load_policy
from sandglass.trace_parser import exec_argv, parse_trace

POLICY = load_policy(PROJECT_ROOT / "policies" / "templates" / "read_only_folder.v1.yaml",
                     in_sandbox=True, multiarch="x86_64-linux-gnu",
                     container_script="/package/node_modules/x/server.js", package_dir="/package")
BASELINE = load_install_baseline("x86_64-linux-gnu")

NPM_ARGS = '["npm", "install", "--offline", "--no-audit", "--no-fund"], 0x565459be39d0 /* 17 vars */'
NODE_ARGS = '["node", "/usr/bin/npm", "install", "--offline", "--no-audit", "--no-fund"], 0x7ffd41479378 /* 17 vars */'
SH_ARGS = '["sh", "-c", "node postinstall.js"], 0x55f6dd0cad00 /* 49 vars */'
ENOENT = "= -1 ENOENT (No such file or directory)"
LOCALE = ('openat(AT_FDCWD</package>, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) '
          + ENOENT)

SAMPLE = [
    "10    19:32:45.431307 execve(0x7ffd9b97c180, 0x7ffd9b97d5d0, 0x7ffd9b97d5f8) = 0",
    '11    19:32:45.437183 execve("/usr/bin/cp", ["cp", "/download/project/package.json", "/package/"], 0x565459be39a8 /* 17 vars */ <unfinished ...>',
    "11    19:32:45.437613 <... execve resumed>) = 0",
    "11    19:32:45.441955 " + LOCALE,
    "12    19:32:45.449085 " + LOCALE,
    f'10    19:32:45.451540 execve("/opt/venv/bin/npm", {NPM_ARGS}) {ENOENT}',
    f'10    19:32:45.451782 execve("/usr/local/bin/npm", {NPM_ARGS}) {ENOENT}',
    f'10    19:32:45.452082 execve("/usr/local/sbin/npm", {NPM_ARGS}) {ENOENT}',
    f'10    19:32:45.452347 execve("/usr/local/bin/npm", {NPM_ARGS}) {ENOENT}',
    f'10    19:32:45.452635 execve("/usr/sbin/npm", {NPM_ARGS}) {ENOENT}',
    f'10    19:32:45.452673 execve("/usr/bin/npm", {NPM_ARGS}) = 0',
    "10    19:32:45.455577 " + LOCALE,
    f'10    19:32:45.457273 execve("/opt/venv/bin/node", {NODE_ARGS}) {ENOENT}',
    f'10    19:32:45.457311 execve("/usr/local/bin/node", {NODE_ARGS}) {ENOENT}',
    f'10    19:32:45.457340 execve("/usr/local/sbin/node", {NODE_ARGS}) {ENOENT}',
    f'10    19:32:45.457366 execve("/usr/local/bin/node", {NODE_ARGS}) {ENOENT}',
    f'10    19:32:45.457387 execve("/usr/sbin/node", {NODE_ARGS}) {ENOENT}',
    f'10    19:32:45.457412 execve("/usr/bin/node", {NODE_ARGS}) = 0',
    f'23    19:32:46.626104 execve("/package/node_modules/sandglass-test-postinstall/node_modules/.bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.626318 execve("/package/node_modules/node_modules/.bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.626504 execve("/package/node_modules/.bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.626651 execve("/node_modules/.bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.626833 execve("/usr/share/nodejs/@npmcli/run-script/lib/node-gyp-bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.627090 execve("/opt/venv/bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.627247 execve("/usr/local/bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.627446 execve("/usr/local/sbin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.627640 execve("/usr/local/bin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.627775 execve("/usr/sbin/sh", {SH_ARGS}) {ENOENT}',
    f'23    19:32:46.627976 execve("/usr/bin/sh", {SH_ARGS}) = 0',
    '24    19:32:46.636273 execve("/usr/bin/node", ["node", "postinstall.js"], 0x557376fefdb8 /* 48 vars */ <unfinished ...>',
    "24    19:32:46.636451 <... execve resumed>) = 0",
    "10    19:32:46.794460 +++ exited with 0 +++",
]


def judge(lines=SAMPLE):
    return compare_install(parse_trace("\n".join(lines), cwd="/package"), POLICY, BASELINE, 0)


def test_exec_argv_reads_the_argument_list():
    assert exec_argv(SAMPLE[-4]) == ["sh", "-c", "node postinstall.js"]
    assert exec_argv(SAMPLE[0]) is None  # strace couldn't read the first exec
    # strace cuts long strings short: the "..." is kept.
    cut = ('11 1:0:0.1 execve("/opt/venv/bin/python", ["/opt/venv/bin/python", "-c", '
           '"\\"\\"\\"The local network sink: a fak"...], 0x7fa6 /* 0 vars */) = 0')
    assert exec_argv(cut)[-1] == '"""The local network sink: a fak...'


def test_programs_lists_every_successful_exec_with_its_argv():
    programs = judge()["programs"]
    assert [(p["pid"], p["path"], p["argv"]) for p in programs] == [
        (10, "<unreadable>", None),
        (11, "/usr/bin/cp", ["cp", "/download/project/package.json", "/package/"]),
        (10, "/usr/bin/npm", ["npm", "install", "--offline", "--no-audit", "--no-fund"]),
        (10, "/usr/bin/node", ["node", "/usr/bin/npm", "install", "--offline", "--no-audit", "--no-fund"]),
        (23, "/usr/bin/sh", ["sh", "-c", "node postinstall.js"]),
        (24, "/usr/bin/node", ["node", "postinstall.js"]),
    ]
    assert all(p["phase"] == "install" for p in programs)
    assert programs[0]["note"] == "the installer's shell"


def test_path_searches_are_one_entry_each_with_where_they_were_found():
    result = judge()
    groups = group_attempted(result["attempted"], result["programs"])
    searches = [(g["label"], g["found_at"], g["count"]) for g in groups if g["path_search"]]
    assert searches == [
        ("looked for npm in PATH (5 places)", "/usr/bin/npm", 5),
        ("looked for node in PATH (5 places)", "/usr/bin/node", 5),
        ("looked for sh in PATH (10 places)", "/usr/bin/sh", 10),
    ]


def test_other_attempts_are_grouped_by_category_path_errno_and_phase():
    result = judge()
    groups = [g for g in group_attempted(result["attempted"], result["programs"]) if not g["path_search"]]
    # Three failed reads of locale.alias (pids 11, 12, 10): one entry, counted.
    assert [(g["label"], g["target"], g["error"], g["phase"], g["count"]) for g in groups] == [
        ("install read outside allowed paths", "/usr/share/locale/locale.alias", "ENOENT", "install", 3)]
    assert groups[0]["first"]["timestamp"] == "19:32:45.441955"
    assert groups[0]["first"]["pid"] == 11
    # The JSON keeps every event: 3 reads + 20 failed execs.
    assert len(result["attempted"]) == 23


def test_a_lone_failed_exec_is_not_a_path_search():
    # One failed exec, never found: an ordinary attempt, and never "ran".
    lone = [SAMPLE[0], f'10    19:32:45.5 execve("/usr/local/bin/missing", ["missing"], 0x1 /* 1 vars */) {ENOENT}',
            SAMPLE[-1]]
    result = judge(lone)
    groups = group_attempted(result["attempted"], result["programs"])
    assert [(g["path_search"], g["label"]) for g in groups] == [
        (False, "install tried to run a program not in the install baseline or exec_allow")]


def test_another_event_of_the_same_pid_ends_a_path_search():
    # npm: 2 failed places, then a failed read from the same pid, then 3 more.
    lines = SAMPLE[:7] + ["10    19:32:45.4521 " + LOCALE] + SAMPLE[7:10] + [SAMPLE[-1]]
    result = judge(lines)
    groups = group_attempted(result["attempted"], result["programs"])
    assert [g["label"] for g in groups if g["path_search"]] == [
        "looked for npm in PATH (2 places)", "looked for npm in PATH (3 places)"]


def test_markdown_shows_programs_grouped_attempts_and_the_dependency_note():
    install = judge()
    package = {"spec": "npm:sandglass-test-postinstall@1.0.0", "source": "test", "files": [],
               "entry": None, "hash": None, "install": None}
    report = build_report("x", "t", POLICY, {}, with_install(not_run(None), install), None, {},
                          {"name": "b", "file": "f", "multiarch": "m"}, package)
    md = _markdown(report)
    programs = md[md.index("## Programs run"):md.index("## Attempted")]
    assert "### Install" in programs
    assert '`/usr/bin/sh`: `sh -c "node postinstall.js"`' in programs
    attempted = md[md.index("## Attempted"):md.index("## Probes")]
    assert "23 failed attempt(s) in 4 group(s)" in attempted
    assert "**looked for sh in PATH (10 places)**, found at `/usr/bin/sh`" in attempted
    assert "x3, first at 19:32:45.441955, pid 11 (install)" in attempted
    assert "ran a program" not in attempted
    assert report["not_tested"] == [DEPENDENCY_HASH_NOTE]
    assert "## Not tested" in md and DEPENDENCY_HASH_NOTE in md


def test_fixture_reports_have_no_dependency_note():
    report = build_report("x", "t", POLICY, {}, not_run("r"), None, {},
                          {"name": "b", "file": "f", "multiarch": "m"})
    assert report["not_tested"] == [] and "## Not tested" not in _markdown(report)
    assert "Nothing is installed in a fixture run." in _markdown(report)
