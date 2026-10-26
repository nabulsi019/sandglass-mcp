"""Links (#122): a read is judged by the file really opened, in every phase.

Hand-written traces in strace -y format (no Docker): a successful open
shows the opened file after the returned fd, e.g. `= 8</home/x>`.
"""

import pytest

from sandglass import PROJECT_ROOT, sandbox
from sandglass.compare import compare_install
from sandglass.policy import load_install_baseline, load_policy
from sandglass.trace_parser import parse_trace
from tests.test_install import DONE, START
from tests.test_policy_templates import template
from tests.test_sandbox_pipeline import EXITED, LAUNCH, TOOL_CALL, run

CREDS = "/home/sandglass/.aws/credentials"
SYMLINK = f'14 10:00:00.3 symlink("{CREDS}", "/tmp/tmpx/note.txt") = 0'
OPEN_LINK = f'14 10:00:00.4 openat(AT_FDCWD</project>, "/tmp/tmpx/note.txt", O_RDONLY|O_CLOEXEC) = 8<{CREDS}>'


def found(result):
    return [(v["mode"], v["target"], v["phase"]) for v in result["violations"]]


# --- the parser ---------------------------------------------------------------

def test_a_successful_open_records_the_file_really_opened():
    [event] = parse_trace(OPEN_LINK)
    assert (event.target, event.opened) == ("/tmp/tmpx/note.txt", CREDS)


@pytest.mark.parametrize("line", [
    '8 10:00:00.1 openat(AT_FDCWD, "/x", O_RDONLY) = -1 ENOENT (No such file or directory)',
    '8 10:00:00.1 openat(AT_FDCWD, "/x", O_RDONLY) = 3',            # no -y
    '8 10:00:00.1 openat(AT_FDCWD, "/proc/self/fd/0", O_RDONLY) = 3<pipe:[42]>',  # not a file
])
def test_no_opened_path_without_a_file_behind_the_fd(line):
    assert parse_trace(line)[0].opened is None


@pytest.mark.parametrize("requested, opened, expected", [
    ("/proc/self/cgroup", "/proc/42/cgroup", "/proc/self/cgroup"),   # its own /proc folder
    ("/proc/mounts", "/proc/42/mounts", "/proc/mounts"),            # /proc/mounts -> self/mounts
    ("/proc/self/fd/3", f"{CREDS}", CREDS),                         # leads elsewhere: kept
    ("/proc/self/root/home/sandglass/.aws/credentials", CREDS, CREDS),
    ("/proc/self/cgroup", "/proc/1/environ", "/proc/1/environ"),    # not the same file: kept
])
def test_proc_self_is_judged_as_asked_only_when_it_is_the_same_file(requested, opened, expected):
    line = f'8 10:00:00.1 openat(AT_FDCWD, "{requested}", O_RDONLY) = 3<{opened}>'
    assert parse_trace(line)[0].opened == expected


def test_the_servers_strace_prints_fd_paths():
    args = sandbox.docker_command(PROJECT_ROOT / "test_servers" / "good_notes_server.py")[1]
    assert "exec strace -f -tt -y " in " ".join(args)


# --- the server's run: startup and tool calls ------------------------------------

def test_reading_through_a_link_is_caught_in_the_tool_call_phase():
    # Under no_network.v1, /tmp is writable and readable: by path alone, CLEAN.
    result = run([LAUNCH, TOOL_CALL, SYMLINK, OPEN_LINK, EXITED], policy=template("no_network"))
    assert found(result) == [("write", CREDS, "tool-call"), ("read", CREDS, "tool-call")]
    link, read = result["violations"]
    assert link["reason"] == "linked to a path outside allowed reads"
    assert read["reason"] == f"read matches read_deny (requested /tmp/tmpx/note.txt, opened {CREDS})"
    assert (read["requested"], read["opened"]) == ("/tmp/tmpx/note.txt", CREDS)


def test_links_are_caught_at_startup_too():
    result = run([LAUNCH, SYMLINK, OPEN_LINK, EXITED], policy=template("no_network"))
    assert found(result) == [("write", CREDS, "startup"), ("read", CREDS, "startup")]


def test_a_relative_symlink_target_is_resolved_against_the_links_folder():
    line = '14 10:00:00.3 symlinkat("../../home/sandglass/.aws/credentials", AT_FDCWD</project>, "/tmp/x/l") = 0'
    result = run([LAUNCH, line, EXITED], policy=template("no_network"))
    assert found(result) == [("write", CREDS, "startup")]


def test_either_path_outside_the_policy_is_a_violation():
    notes = load_policy(PROJECT_ROOT / "policies" / "notes_readonly.yaml",
                        server_script=PROJECT_ROOT / "test_servers" / "good_notes_server.py",
                        in_sandbox=True, multiarch="x86_64-linux-gnu")
    allowed = "/project/test_servers/allowed_notes/hello.txt"
    # Requested path allowed, opened file not: a violation naming the opened file.
    escape = f'10 10:00:00.2 openat(AT_FDCWD, "{allowed}", O_RDONLY) = 8</etc/passwd>'
    assert found(run([LAUNCH, escape, EXITED], policy=notes)) == [("read", "/etc/passwd", "startup")]
    # Both the same and allowed: nothing.
    same = f'10 10:00:00.2 openat(AT_FDCWD, "{allowed}", O_RDONLY) = 8<{allowed}>'
    assert run([LAUNCH, same, EXITED], policy=notes)["verdict"] == "CLEAN"


# --- /proc/self can't excuse a read that leaves /proc (#131) ----------------------

ROOT_ESCAPE = (f'10 10:00:00.2 openat(AT_FDCWD, "/proc/self/root{CREDS}", O_RDONLY|O_CLOEXEC)'
               f' = 7<{CREDS}>')
OPEN_CREDS = f'10 10:00:00.3 openat(AT_FDCWD, "{CREDS}", O_RDONLY|O_CLOEXEC) = 8<{CREDS}>'
FD_REOPEN = f'10 10:00:00.4 openat(AT_FDCWD, "/proc/self/fd/100", O_RDONLY|O_CLOEXEC) = 9<{CREDS}>'
NOTE = "/project/test_servers/allowed_notes/hello.txt"


def notes_readonly():
    return load_policy(PROJECT_ROOT / "policies" / "notes_readonly.yaml",
                       server_script=PROJECT_ROOT / "test_servers" / "good_notes_server.py",
                       in_sandbox=True, multiarch="x86_64-linux-gnu")


@pytest.mark.parametrize("policy, expected", [
    # Read anywhere but /home: the requested /proc paths are fine, the opened file isn't.
    (lambda: template("no_network"), [("read", CREDS)] * 3),
    # Only the notes folder: the requested paths are already outside it.
    (notes_readonly, [("read", f"/proc/self/root{CREDS}"), ("read", CREDS),
                      ("read", "/proc/self/fd/100")]),
])
def test_proc_self_root_and_fd_escapes_are_violations(policy, expected):
    result = run([LAUNCH, ROOT_ESCAPE, OPEN_CREDS, FD_REOPEN, EXITED], policy=policy())
    assert result["verdict"] == "VIOLATIONS"
    assert [(v["mode"], v["target"]) for v in result["violations"]] == expected
    # Under either policy, the report names the file really opened.
    assert all(v.get("opened", CREDS) == CREDS for v in result["violations"])


def test_proc_self_fd_reopening_an_allowed_file_stays_allowed():
    note = f'10 10:00:00.3 openat(AT_FDCWD, "{NOTE}", O_RDONLY|O_CLOEXEC) = 8<{NOTE}>'
    reopen = f'10 10:00:00.4 openat(AT_FDCWD, "/proc/self/fd/8", O_RDONLY|O_CLOEXEC) = 9<{NOTE}>'
    # Under no_network.v1 /proc/self/fd/8 and the note are both readable: CLEAN.
    assert run([LAUNCH, note, reopen, EXITED], policy=template("no_network"))["verdict"] == "CLEAN"
    # The opened path is the note itself, never mapped back to /proc.
    assert parse_trace(reopen)[0].opened == NOTE


@pytest.mark.parametrize("requested, opened", [
    ("/proc/self/root/proc/1/environ", "/proc/1/environ"),   # through /proc/self/root
    ("/proc/self/fd/5", "/proc/1/environ"),                  # an fd of another process's file
    ("/proc/self/environ", "/proc/1/cmdline"),               # a different file
    ("/proc/self/root/proc/self/environ", "/proc/1/environ"),
])
def test_another_pids_proc_file_is_never_mapped(requested, opened):
    line = f'8 10:00:00.1 openat(AT_FDCWD, "{requested}", O_RDONLY) = 3<{opened}>'
    assert parse_trace(line)[0].opened == opened


# --- the install phase ----------------------------------------------------------

def test_the_install_judges_the_opened_file_too():
    policy = load_policy(PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml", in_sandbox=True,
                         multiarch="x86_64-linux-gnu", container_script="/package/x/server.js",
                         package_dir="/package")
    line = f'9 10:00:00.4 openat(AT_FDCWD</package>, "/package/x/note.txt", O_RDONLY) = 17<{CREDS}>'
    events = parse_trace("\n".join([START, line, DONE]), cwd="/package")
    result = compare_install(events, policy, load_install_baseline("x86_64-linux-gnu"), 0)
    assert [(v["mode"], v["target"]) for v in result["violations"]] == [("read", CREDS)]
