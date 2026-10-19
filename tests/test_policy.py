"""Tests for policy loading: validation errors and project-root path resolution.

Bad policies are made by loading the real policy file and breaking one thing,
so these tests keep working when the policy format grows new sections.
"""

from pathlib import Path

import pytest
import yaml

from guard.policy import PROJECT_ROOT, PolicyError, load_policy

POLICY_FILE = PROJECT_ROOT / "policies" / "notes_readonly.yaml"
SERVER = PROJECT_ROOT / "test_servers" / "good_notes_server.py"


def real_policy() -> dict:
    return yaml.safe_load(POLICY_FILE.read_text())


def write(tmp_path: Path, data) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data) if not isinstance(data, str) else data)
    return path


def test_real_policy_loads():
    policy = load_policy(POLICY_FILE, server_script=SERVER)
    assert policy.name == "notes_readonly"
    assert policy.network_allow is False


# --- loading errors -----------------------------------------------------------

@pytest.mark.parametrize("key", ["name", "description", "filesystem", "network", "runtime_allow"])
def test_missing_top_level_key(tmp_path, key):
    data = real_policy()
    del data[key]
    with pytest.raises(PolicyError, match=f"Missing required key '{key}'"):
        load_policy(write(tmp_path, data), server_script=SERVER)


def test_missing_nested_key(tmp_path):
    data = real_policy()
    del data["filesystem"]["read_allow"]
    with pytest.raises(PolicyError, match="filesystem.read_allow"):
        load_policy(write(tmp_path, data), server_script=SERVER)


def test_wrong_type(tmp_path):
    data = real_policy()
    data["network"]["allow"] = "no"  # a string, not a bool
    with pytest.raises(PolicyError, match="'network.allow' must be bool, got str"):
        load_policy(write(tmp_path, data), server_script=SERVER)


def test_non_string_path_entry(tmp_path):
    data = real_policy()
    data["filesystem"]["read_allow"] = [123]
    with pytest.raises(PolicyError, match="must be a string path"):
        load_policy(write(tmp_path, data), server_script=SERVER)


def test_top_level_not_a_mapping(tmp_path):
    with pytest.raises(PolicyError, match="YAML mapping"):
        load_policy(write(tmp_path, "- just\n- a list\n"), server_script=SERVER)


def test_server_script_placeholder_without_script():
    with pytest.raises(PolicyError, match="server_script"):
        load_policy(POLICY_FILE)  # runtime_allow uses {server_script}


# --- path resolution ----------------------------------------------------------

def test_relative_paths_resolve_against_project_root_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # run from somewhere unrelated
    policy = load_policy(POLICY_FILE, server_script=SERVER)
    assert policy.read_allow == [PROJECT_ROOT / "test_servers" / "allowed_notes"]


def test_same_result_from_a_subfolder(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT / "test_servers")
    policy = load_policy(POLICY_FILE, server_script=SERVER)
    assert policy.read_allow == [PROJECT_ROOT / "test_servers" / "allowed_notes"]


def test_absolute_paths_are_kept(tmp_path):
    data = real_policy()
    data["filesystem"]["read_allow"] = [str(tmp_path)]
    policy = load_policy(write(tmp_path, data), server_script=SERVER)
    assert policy.read_allow == [tmp_path.resolve()]
