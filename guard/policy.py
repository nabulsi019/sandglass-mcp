"""Load and validate MCP Guard policy files.

A policy states what a server is ALLOWED to do. This module only loads it;
nothing is enforced or checked against real behaviour yet.

Path resolution rule: every relative path in a policy is resolved against
the PROJECT ROOT (the folder containing guard/), NOT the current working
directory. That way `uv run python -m guard.client ...` gives the same
result whether you launch it from the project root or from a subfolder.
"""

import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

# guard/policy.py -> guard/ -> project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class PolicyError(ValueError):
    """Raised when a policy file is missing fields or has the wrong types."""


@dataclass(frozen=True)
class Policy:
    name: str
    description: str
    read_allow: list[Path]     # files/folders the tools may read
    write_allow: list[Path]    # files/folders the tools may write
    network_allow: bool        # may the server open network connections?
    runtime_allow: list[Path]  # interpreter/server files, excluded from violations


def _expand(raw: str, server_script: Path | None) -> Path:
    """Fill in placeholders, then resolve the path against PROJECT_ROOT."""
    if "{server_script}" in raw and server_script is None:
        raise PolicyError("Policy uses {server_script} but no server script was given")
    text = raw.format(
        python_base=sys.base_prefix,  # the Python installation itself
        venv=sys.prefix,              # the active virtualenv (== base if none)
        server_script=server_script or "",
    )
    path = Path(text)
    # Absolute paths are kept as-is; relative ones are anchored to the project root.
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def _require(data: dict, key: str, expected_type: type, where: str):
    """Fetch data[key] and check its type, with a readable error if it's wrong."""
    if key not in data:
        raise PolicyError(f"Missing required key '{where}{key}'")
    value = data[key]
    if not isinstance(value, expected_type):
        raise PolicyError(
            f"'{where}{key}' must be {expected_type.__name__}, got {type(value).__name__}"
        )
    return value


def _path_list(data: dict, key: str, where: str, server_script: Path | None) -> list[Path]:
    items = _require(data, key, list, where)
    for item in items:
        if not isinstance(item, str):
            raise PolicyError(f"Every entry in '{where}{key}' must be a string path")
    return [_expand(item, server_script) for item in items]


def load_policy(path: str | Path, server_script: str | Path | None = None) -> Policy:
    """Read a YAML policy file and return a validated Policy.

    Relative paths INSIDE the policy are resolved against the project root,
    not the current working directory. `server_script` fills the
    {server_script} placeholder in runtime_allow.
    """
    script = Path(server_script).resolve() if server_script else None

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)  # safe_load: never constructs arbitrary objects
    if not isinstance(data, dict):
        raise PolicyError("Policy file must be a YAML mapping at the top level")

    filesystem = _require(data, "filesystem", dict, "")
    network = _require(data, "network", dict, "")

    return Policy(
        name=_require(data, "name", str, ""),
        description=_require(data, "description", str, ""),
        read_allow=_path_list(filesystem, "read_allow", "filesystem.", script),
        write_allow=_path_list(filesystem, "write_allow", "filesystem.", script),
        network_allow=_require(network, "allow", bool, "network."),
        runtime_allow=_path_list(data, "runtime_allow", "", script),
    )
