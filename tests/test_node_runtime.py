"""Node.js servers (#17): runtime choice, baselines, and the node launch exec."""

from pathlib import Path, PurePosixPath as P

import pytest

from sandglass import PROJECT_ROOT, sandbox
from sandglass.compare import compare
from sandglass.policy import PolicyError, load_policy
from sandglass.trace_parser import parse_trace
from tests.test_sandbox_pipeline import (EXITED, LAUNCH, POLICY_FILE, SELF_TEST, SESSION_OK, SINK_LINES,
                                         RELAY_END, RELAY_START, TOOL_CALL)

NODE_SERVER = PROJECT_ROOT / "test_servers" / "good_notes_node_server.js"
NODE_EXEC = '8  10:00:00.000060 execve("/usr/bin/node", ["/usr/bin/node", "/project/test_servers/good_notes_node_server.js"], 0x0 /* 9 vars */) = 0'
LIBNODE = '8  10:00:00.000070 openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libnode.so.115", O_RDONLY|O_CLOEXEC) = 3'


def node_policy():
    return load_policy(POLICY_FILE, server_script=NODE_SERVER, in_sandbox=True,
                       multiarch="x86_64-linux-gnu", runtime="node")


def run(lines, runtime):
    # Sandglass's sink and stdin relay, like in a real run (see test_sandbox_pipeline.run).
    lines = lines[:1] + SELF_TEST + SINK_LINES + RELAY_START + lines[1:] + [TOOL_CALL] + RELAY_END
    return compare(parse_trace("\n".join(lines)), node_policy(), SESSION_OK, runtime=runtime)


def test_runtime_from_extension():
    assert sandbox.runtime_for(Path("x/server.js")) == "node"
    assert sandbox.runtime_for(Path("x/server.py")) == "python"


def test_node_loads_both_baselines():
    policy = node_policy()
    assert policy.baseline_name == "python312_slim + node_debian"
    assert P("/usr/lib/x86_64-linux-gnu/libnode.so.115") in policy.baseline_read_allow
    assert P("/etc/ld.so.cache") in policy.baseline_read_allow  # from python312_slim
    assert P("/project/test_servers/good_notes_node_server.js") in policy.runtime_allow


def test_unknown_runtime():
    with pytest.raises(PolicyError, match="Unknown runtime"):
        load_policy(POLICY_FILE, server_script=NODE_SERVER, in_sandbox=True,
                    multiarch="x86_64-linux-gnu", runtime="ruby")


def test_node_exec_is_part_of_the_launch_for_node_servers():
    result = run([LAUNCH, NODE_EXEC, LIBNODE, EXITED], runtime="node")
    assert result["verdict"] == "CLEAN"


def test_node_exec_is_a_violation_for_python_servers():
    result = run([LAUNCH, NODE_EXEC, EXITED], runtime="python")
    assert [v["target"] for v in result["violations"]] == ["/usr/bin/node"]


def test_only_one_node_exec_is_the_launch():
    second = NODE_EXEC.replace("10:00:00.000060", "10:00:00.9")
    result = run([LAUNCH, NODE_EXEC, second, EXITED], runtime="node")
    assert [v["target"] for v in result["violations"]] == ["/usr/bin/node"]


def test_node_exec_from_another_process_is_a_violation():
    child = NODE_EXEC.replace("8  ", "12 ", 1)  # a child process, not the launcher
    result = run([LAUNCH, child, EXITED], runtime="node")
    assert [v["target"] for v in result["violations"]] == ["/usr/bin/node"]
