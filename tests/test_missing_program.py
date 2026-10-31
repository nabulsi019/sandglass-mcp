"""(#148) "the server needs a program the sandbox doesn't have: <name>".

Hand-written traces, no Docker. The reason is only added to a run that is
already INCOMPLETE because the server exited during startup (#24).
"""

from sandglass.compare import MISSING_PROGRAM, _missing_program, compare
from sandglass.trace_parser import parse_trace
from tests.test_sandbox_pipeline import LAUNCH, RELAY_START, SINK_LINES, run, sandbox_policy
from tests.test_startup_failure import FAILED_SESSION, RELAY_SAW_SERVER_GO, SERVER_EXIT_1

PATH_DIRS = ["/opt/venv/bin", "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]


def search(name: str, pid: int = 12, second: int = 0, argv: str | None = None) -> list[str]:
    """A PATH search for `name` by `pid`: one failed execve per PATH folder,
    like GitPython's `git version` in mcp-server-git's trace."""
    argv = argv or f'["{name}", "version"]'
    return [f'{pid} 10:00:0{second}.{100 + i:06d} execve("{folder}/{name}", {argv}, 0x0 /* 8 vars */)'
            " = -1 ENOENT (No such file or directory)" for i, folder in enumerate(PATH_DIRS)]


def found(name: str, pid: int, second: int = 0) -> str:
    """A successful exec of /usr/bin/<name> by `pid`."""
    return f'{pid} 10:00:0{second}.200000 execve("/usr/bin/{name}", ["{name}"], 0x0 /* 8 vars */) = 0'


def startup_exit(lines: list[str], session=FAILED_SESSION) -> dict:
    """The server (pid 8) runs `lines`, then exits at startup (at 10:00:00.300100)."""
    trace = [LAUNCH] + SINK_LINES + RELAY_START + lines + [SERVER_EXIT_1] + RELAY_SAW_SERVER_GO
    return compare(parse_trace("\n".join(trace)), sandbox_policy(), session)


def missing_reasons(result: dict) -> list[str]:
    return [r for r in result["incomplete_reasons"] if r.startswith(MISSING_PROGRAM)]


def test_the_git_server_names_git():
    result = startup_exit(search("git"))
    assert result["verdict"] == "INCOMPLETE" and result["violations"] == []
    assert missing_reasons(result) == [f"{MISSING_PROGRAM}: git"]


def test_a_search_found_later_by_another_process_gives_no_reason():
    # e.g. `uname`: searched by one pid, then run by another.
    result = startup_exit(search("uname") + [found("uname", pid=13)])
    assert missing_reasons(result) == []


def test_a_search_the_same_process_finds_gives_no_reason():
    # A shell finds node in its 3rd PATH folder: two failures, then success.
    result = startup_exit(search("node")[:2] + [found("node", pid=12)])
    assert missing_reasons(result) == []


def test_a_single_failed_exec_is_not_a_search():
    result = startup_exit(search("git")[:1])
    assert missing_reasons(result) == []


def test_two_unfound_searches_name_the_last_one():
    result = startup_exit(search("lsb_release") + search("git", pid=14))
    assert missing_reasons(result) == [f"{MISSING_PROGRAM}: git"]


def test_runs_that_called_tools_never_get_the_reason():
    # Tools ran: no startup exit, so no reason, even with an unfound search.
    result = run([LAUNCH] + search("git"))
    assert missing_reasons(result) == []


def test_a_search_after_the_server_exited_gives_no_reason():
    # Another process searching after the exit didn't make the server exit.
    late = search("git", pid=14, second=5)
    trace = [LAUNCH] + SINK_LINES + RELAY_START + [SERVER_EXIT_1] + late + RELAY_SAW_SERVER_GO
    result = compare(parse_trace("\n".join(trace)), sandbox_policy(), FAILED_SESSION)
    assert missing_reasons(result) == []


def test_a_lookup_without_exec_gives_no_reason():
    # shutil.which only stats the PATH folders: no execs, nothing is guessed.
    stats = [f'12 10:00:00.{100 + i:06d} newfstatat(AT_FDCWD, "{folder}/git", 0x7ffe, 0)'
             " = -1 ENOENT (No such file or directory)" for i, folder in enumerate(PATH_DIRS)]
    result = startup_exit(stats)
    assert result["verdict"] == "INCOMPLETE" and missing_reasons(result) == []


def test_an_install_phase_search_gives_no_reason():
    # pip's lsb_release probe while installing (#16): phase "install", never counted.
    events = parse_trace("\n".join([LAUNCH, SERVER_EXIT_1]))
    records = [{"pid": 12, "syscall": "execve", "error": "ENOENT", "phase": "install",
                "target": f"{folder}/lsb_release", "timestamp": f"10:00:00.{100 + i:06d}",
                "evidence": line}
               for i, (folder, line) in enumerate(zip(PATH_DIRS, search("lsb_release")))]
    assert _missing_program(events, events[0], records, [], (None, None)) is None
    # The same records in the startup phase do name it (so the test means something).
    startup = [{**r, "phase": "startup"} for r in records]
    assert _missing_program(events, events[0], startup, [], (None, None)) == "lsb_release"


def test_a_helper_process_search_gives_no_reason():
    # The sink (pid 9) and relay (pid 7) are Sandglass's; their searches don't count.
    result = startup_exit(search("git", pid=9))
    assert missing_reasons(result) == []
