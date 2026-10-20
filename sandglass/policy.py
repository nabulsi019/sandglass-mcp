"""Load and validate Sandglass policy files (and the container baseline).

A policy states what a server is ALLOWED to do. sandglass/compare.py checks the
recorded behaviour against it.

Path resolution rule: every relative path in a policy is resolved against
the PROJECT ROOT, NOT the current working directory:
  - host mode:    the folder containing sandglass/
  - sandbox mode: /project, where the project is mounted in the container
That way the policy means the same thing wherever you launch the client from.

Placeholders are filled with host paths or container paths depending on mode:
  {python_base}  {venv}  {server_script}  {server_dir}  {multiarch} (sandbox only)

Exact-match entries: a runtime_allow entry starting with "=" (e.g.
"={server_dir}") matches ONLY that exact directory, and only for directory
listings. It never allows anything inside the directory.

In sandbox mode the container baseline (sandglass/baselines/python312_slim.yaml)
is loaded automatically: system files the interpreter reads at startup.
runtime_allow and the baseline allow READS (and listings) only, never writes.
"""

import posixpath
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from sandglass import PROJECT_ROOT
from sandglass import sandbox

BASELINE_FILE = PROJECT_ROOT / "sandglass" / "baselines" / "python312_slim.yaml"


class PolicyError(ValueError):
    """Raised when a policy file is missing fields or has the wrong types."""


@dataclass(frozen=True)
class Policy:
    name: str
    description: str
    read_allow: list[Path]     # files/folders the tools may read
    write_allow: list[Path]    # files/folders the tools may write
    network_allow: bool        # may the server open network connections?
    exec_allow: list[Path]     # programs the server may launch (besides itself)
    runtime_allow: list[Path]  # interpreter/server files: READS only
    list_exact: list[Path] = field(default_factory=list)        # "=" entries: exact dir listings only
    allow_domains: list[str] = field(default_factory=list)      # domains the server may contact (via the sink)
    baseline_name: str | None = None                            # sandbox only
    baseline_read_allow: list[Path] = field(default_factory=list)  # sandbox only: READS only


def _placeholders(server_script: Path | None, in_sandbox: bool, multiarch: str | None) -> dict[str, str]:
    """Values for the {placeholders}, as host paths or container paths."""
    if in_sandbox:
        script = str(sandbox.to_container_path(server_script)) if server_script else ""
        return {
            "python_base": str(sandbox.CONTAINER_PYTHON_BASE),
            "venv": str(sandbox.CONTAINER_VENV),
            "server_script": script,
            "server_dir": posixpath.dirname(script) if script else "",
            "multiarch": multiarch or "",
        }
    return {
        "python_base": sys.base_prefix,  # the Python installation itself
        "venv": sys.prefix,              # the active virtualenv (== base if none)
        "server_script": str(server_script or ""),
        "server_dir": str(server_script.parent) if server_script else "",
        "multiarch": "",                 # only meaningful inside the Linux container
    }


def _expand(raw: str, values: dict[str, str], in_sandbox: bool) -> Path:
    """Fill in placeholders, then resolve the path against the project root."""
    for key, value in values.items():
        if "{" + key + "}" in raw and not value:
            raise PolicyError(f"Placeholder {{{key}}} in {raw!r} has no value in this mode")
    try:
        text = raw.format(**values)
    except (KeyError, IndexError, ValueError) as exc:
        raise PolicyError(f"Unknown or malformed placeholder in {raw!r}: {exc}") from None

    if in_sandbox:
        # Container paths: purely textual. Don't touch the host filesystem,
        # whose symlinks (e.g. macOS /tmp -> /private/tmp) would corrupt them.
        path = PurePosixPath(text)
        if not path.is_absolute():
            path = sandbox.CONTAINER_PROJECT / path
        return PurePosixPath(posixpath.normpath(path))

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


def _strings(data: dict, key: str, where: str) -> list[str]:
    items = _require(data, key, list, where)
    for item in items:
        if not isinstance(item, str):
            raise PolicyError(f"Every entry in '{where}{key}' must be a string path")
    return items


def _path_list(data: dict, key: str, where: str, values: dict, in_sandbox: bool) -> list[Path]:
    """A list of prefix paths. "=" exact entries are only valid in runtime_allow."""
    items = _strings(data, key, where)
    for item in items:
        if item.startswith("="):
            raise PolicyError(f"'{where}{key}': exact entries ('=...') are only allowed in runtime_allow")
    return [_expand(item, values, in_sandbox) for item in items]


def _domains(network: dict) -> list[str]:
    """network.allow_domains: optional list of host names. "example.com" means
    exactly that host; "*.example.com" means any subdomain of it."""
    if "allow_domains" not in network:
        return []
    domains = _strings(network, "allow_domains", "network.")
    for domain in domains:
        bare = domain[2:] if domain.startswith("*.") else domain
        if not bare or "*" in bare or "/" in bare or ":" in bare:
            raise PolicyError(f"'network.allow_domains': {domain!r} is not a host name "
                              "(use 'example.com' or '*.example.com')")
    return [d.lower() for d in domains]


def _read_yaml(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)  # safe_load: never constructs arbitrary objects
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: must be a YAML mapping at the top level")
    return data


def load_policy(
    path: str | Path,
    server_script: str | Path | None = None,
    in_sandbox: bool = False,
    multiarch: str | None = None,
) -> Policy:
    """Read a YAML policy file and return a validated Policy.

    Relative paths INSIDE the policy are resolved against the project root
    (/project in the sandbox), not the current working directory.
    `server_script` fills {server_script} and {server_dir}.
    `in_sandbox` switches to container paths and loads the container baseline;
    `multiarch` (asked from the container) fills {multiarch} in the baseline.
    """
    script = Path(server_script).resolve() if server_script else None
    values = _placeholders(script, in_sandbox, multiarch)

    data = _read_yaml(path)
    filesystem = _require(data, "filesystem", dict, "")
    network = _require(data, "network", dict, "")
    process = _require(data, "process", dict, "")

    # runtime_allow: "=path" -> exact listing entry, anything else -> prefix (reads).
    runtime_allow, list_exact = [], []
    for item in _strings(data, "runtime_allow", ""):
        if item.startswith("="):
            list_exact.append(_expand(item[1:], values, in_sandbox))
        else:
            runtime_allow.append(_expand(item, values, in_sandbox))

    baseline_name, baseline_read_allow = None, []
    if in_sandbox:
        baseline = _read_yaml(BASELINE_FILE)
        baseline_name = _require(baseline, "name", str, "baseline.")
        baseline_read_allow = _path_list(baseline, "read_allow", "baseline.", values, in_sandbox)

    return Policy(
        name=_require(data, "name", str, ""),
        description=_require(data, "description", str, ""),
        read_allow=_path_list(filesystem, "read_allow", "filesystem.", values, in_sandbox),
        write_allow=_path_list(filesystem, "write_allow", "filesystem.", values, in_sandbox),
        network_allow=_require(network, "allow", bool, "network."),
        allow_domains=_domains(network),
        exec_allow=_path_list(process, "exec_allow", "process.", values, in_sandbox),
        runtime_allow=runtime_allow,
        list_exact=list_exact,
        baseline_name=baseline_name,
        baseline_read_allow=baseline_read_allow,
    )
