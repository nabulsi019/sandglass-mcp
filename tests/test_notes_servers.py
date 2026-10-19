"""Tests for the fixture servers' path handling (no MCP session or Docker needed).

The tool functions are plain Python, so we import each server module from its
file and call them directly.
"""

import importlib.util
import sys

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from guard.policy import PROJECT_ROOT

SERVERS = PROJECT_ROOT / "test_servers"


def load_server(name: str):
    """Import test_servers/<name>.py as a module without touching sys.path."""
    spec = importlib.util.spec_from_file_location(name, SERVERS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


good = load_server("good_notes_server")
overreach = load_server("overreach_notes_server")


@pytest.mark.parametrize("name", ["hello", "hello.txt"])
def test_good_server_reads_allowed_note(name):
    assert "Hello from allowed_notes" in good.read_note(name)


@pytest.mark.parametrize("name", [
    "../decoy_home/.fake_credentials",   # climbs out with ..
    "/etc/passwd",                       # absolute path replaces NOTES_DIR
    "../../pyproject",                   # .txt is appended, still outside
    "../good_notes_server.py",           # sibling file
])
def test_good_server_rejects_paths_outside_notes(name):
    with pytest.raises(ToolError, match="outside the allowed notes folder"):
        good.resolve_note_path(name)


def test_good_server_reports_missing_note():
    with pytest.raises(ToolError, match="not found"):
        good.resolve_note_path("does_not_exist")


# --- the fixtures really behave as advertised --------------------------------

# Audit hooks can't be removed, so one hook records into a list we reset per test.
_opened: list[str] = []
sys.addaudithook(lambda event, args: _opened.append(str(args[0])) if event == "open" else None)


def opened_while(fn) -> list[str]:
    _opened.clear()
    fn()
    return list(_opened)


def test_good_server_does_not_touch_decoy():
    paths = opened_while(lambda: good.read_note("hello"))
    assert not any(".fake_credentials" in p for p in paths)


def test_overreach_server_opens_decoy_and_still_returns_note():
    result = None

    def call():
        nonlocal result
        result = overreach.read_note("hello")

    paths = opened_while(call)
    assert any(p.endswith("decoy_home/.fake_credentials") for p in paths)
    assert "Hello from allowed_notes" in result  # looks normal from the outside
