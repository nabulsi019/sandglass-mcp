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
is loaded automatically: system files the interpreter reads at startup. For a
Node.js server (runtime="node") the Node baseline (node_debian.yaml) is loaded
as well; the Python one is still needed for Sandglass's launcher, which runs
before Node.
runtime_allow and the baseline allow READS (and listings) only, never writes.
"""

import posixpath
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from sandglass import PROJECT_ROOT
from sandglass import sandbox

BASELINES_DIR = PROJECT_ROOT / "sandglass" / "baselines"
BASELINE_FILE = BASELINES_DIR / "python312_slim.yaml"
# Baselines per server runtime. Python's is always first: the launcher is Python.
BASELINE_FILES = {
    "python": [BASELINE_FILE],
    "node": [BASELINE_FILE, BASELINES_DIR / "node_debian.yaml"],
}


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
    # Reads that are ALWAYS a violation, even under read_allow, runtime_allow
    # or the baseline: deny wins (#121). e.g. /home in a "read anywhere" template.
    read_deny: list[Path] = field(default_factory=list)


INSTALL_BASELINE_FILE = BASELINES_DIR / "install.yaml"


@dataclass(frozen=True)
class InstallBaseline:
    """What the installers themselves may do in a scan's install phase (#16)."""
    name: str
    read_allow: list[PurePosixPath]     # install.yaml + python312_slim + node_debian reads
    list_exact: list[PurePosixPath]     # folders that may be listed, nothing inside them (/etc)
    write_allow: list[PurePosixPath]    # /package, /tmp, /dev/null
    exec_allow: list[PurePosixPath]     # sh, cp, node, npm, the image's Python, ...
    network_families_allow: list[str]   # e.g. AF_NETLINK: sockets that can't leave the machine
    loopback_bind_allow: bool           # bind() to 127.0.0.1 / ::1 (pip checking for IPv6)


def load_install_baseline(multiarch: str) -> InstallBaseline:
    """sandglass/baselines/install.yaml, plus the startup reads of both runtimes
    (pip is Python, npm is Node.js), with container paths."""
    values = _placeholders(None, True, multiarch)
    data = _read_yaml(INSTALL_BASELINE_FILE)
    reads = _path_list(data, "read_allow", "install.", values, True)
    for runtime_file in BASELINE_FILES["node"]:  # python312_slim + node_debian
        reads += _path_list(_read_yaml(runtime_file), "read_allow", "baseline.", values, True)
    names = ["install"] + [f.stem for f in BASELINE_FILES["node"]]
    return InstallBaseline(
        name=" + ".join(names),
        read_allow=reads,
        list_exact=_path_list(data, "list_exact", "install.", values, True),
        write_allow=_path_list(data, "write_allow", "install.", values, True),
        exec_allow=_path_list(data, "exec_allow", "install.", values, True),
        network_families_allow=_strings(data, "network_families_allow", "install."),
        loopback_bind_allow=_require(data, "loopback_bind_allow", bool, "install."),
    )


def _placeholders(server_script: Path | None, in_sandbox: bool, multiarch: str | None,
                  container_script: str | None = None) -> dict[str, str]:
    """Values for the {placeholders}, as host paths or container paths.
    `container_script` (scan mode) is already a container path, e.g.
    /package/site/bin/<script>: there is no host file to map."""
    if in_sandbox:
        if container_script:
            script = container_script
        else:
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
    runtime: str = "python",
    container_script: str | None = None,
    package_dir: str | None = None,
) -> Policy:
    """Read a YAML policy file and return a validated Policy.

    Relative paths INSIDE the policy are resolved against the project root
    (/project in the sandbox), not the current working directory.
    `server_script` fills {server_script} and {server_dir}.
    `in_sandbox` switches to container paths and loads the container baseline;
    `multiarch` (asked from the container) fills {multiarch} in the baseline.
    `runtime` ("python" or "node") picks which baselines are loaded.
    Scan mode (`sandglass scan`, #19) passes `container_script` (the entry
    point inside the container) instead of `server_script`, and `package_dir`
    (/package): reads there (the package and its dependencies) are added to
    runtime_allow, like {venv} for the fixtures. Reads only, never writes.
    """
    script = Path(server_script).resolve() if server_script else None
    values = _placeholders(script, in_sandbox, multiarch, container_script)

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
    if package_dir:
        runtime_allow.append(PurePosixPath(package_dir))  # the installed package: reads only

    baseline_name, baseline_read_allow = None, []
    if in_sandbox:
        if runtime not in BASELINE_FILES:
            raise PolicyError(f"Unknown runtime {runtime!r} (expected one of {sorted(BASELINE_FILES)})")
        names = []
        for baseline_file in BASELINE_FILES[runtime]:
            baseline = _read_yaml(baseline_file)
            names.append(_require(baseline, "name", str, "baseline."))
            baseline_read_allow += _path_list(baseline, "read_allow", "baseline.", values, in_sandbox)
        baseline_name = " + ".join(names)  # e.g. "python312_slim + node_debian"

    return Policy(
        name=_require(data, "name", str, ""),
        description=_require(data, "description", str, ""),
        read_allow=_path_list(filesystem, "read_allow", "filesystem.", values, in_sandbox),
        # Optional (#121); same path rules as read_allow.
        read_deny=(_path_list(filesystem, "read_deny", "filesystem.", values, in_sandbox)
                   if "read_deny" in filesystem else []),
        write_allow=_path_list(filesystem, "write_allow", "filesystem.", values, in_sandbox),
        network_allow=_require(network, "allow", bool, "network."),
        allow_domains=_domains(network),
        exec_allow=_path_list(process, "exec_allow", "process.", values, in_sandbox),
        runtime_allow=runtime_allow,
        list_exact=list_exact,
        baseline_name=baseline_name,
        baseline_read_allow=baseline_read_allow,
    )
