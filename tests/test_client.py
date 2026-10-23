"""Tests for the client's console output (no Docker or MCP session needed)."""

from sandglass import PROJECT_ROOT
from sandglass.client import print_policy
from sandglass.policy import load_policy

POLICY_FILE = PROJECT_ROOT / "policies" / "notes_readonly.yaml"
SERVER = PROJECT_ROOT / "test_servers" / "good_notes_server.py"


def first_line(capsys) -> str:
    return capsys.readouterr().out.splitlines()[0]


def test_sandbox_mode_says_enforced(capsys):
    policy = load_policy(POLICY_FILE, server_script=SERVER, in_sandbox=True,
                         multiarch="x86_64-linux-gnu")
    print_policy(policy, enforced=True)
    assert first_line(capsys) == "Policy: notes_readonly (enforced)"


def test_host_mode_says_not_enforced(capsys):
    print_policy(load_policy(POLICY_FILE, server_script=SERVER), enforced=False)
    assert first_line(capsys) == "Policy: notes_readonly (not enforced (host mode))"


def test_client_builds_inputs_from_the_schema():
    # #22: an enum and a nested object, which the old "hello"-for-everything
    # inputs got wrong.
    from mcp.types import Tool

    from sandglass.client import build_safe_arguments
    tool = Tool(name="t", input_schema={"type": "object", "required": ["mode", "opts"], "properties": {
        "mode": {"type": "string", "enum": ["fast", "slow"]},
        "opts": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 10}}}}})
    assert build_safe_arguments(tool) == {"mode": "fast", "opts": {"limit": 10}}


def test_old_label_is_gone():
    for path in (PROJECT_ROOT / "sandglass").rglob("*.py"):
        assert "NOT enforced yet" not in path.read_text(), path
