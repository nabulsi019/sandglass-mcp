"""Docker sandbox settings: container paths and the `docker run` command.

The server runs inside the sandglass-sandbox image (see Dockerfile) under
strace. Inside the container:

    /project    the project folder, mounted READ-ONLY
    /trace      reports/trace/<run>/, mounted read-write; strace writes here
    /opt/venv   the project's dependencies, baked into the image
    /usr/local  the Python installation from python:3.12-slim
"""

import shutil
import subprocess
from pathlib import Path, PurePosixPath

from sandglass import PROJECT_ROOT

IMAGE = "sandglass-sandbox"

CONTAINER_PROJECT = PurePosixPath("/project")
CONTAINER_TRACE_DIR = PurePosixPath("/trace")
CONTAINER_PYTHON_BASE = PurePosixPath("/usr/local")
CONTAINER_VENV = PurePosixPath("/opt/venv")
CONTAINER_PYTHON = CONTAINER_VENV / "bin" / "python"
TRACE_FILENAME = "trace.txt"

# Matches the non-root user created in the Dockerfile.
CONTAINER_USER = "10001:10001"


def to_container_path(host_path: Path) -> PurePosixPath:
    """Map a file inside the project on the host to its path inside the container."""
    relative = host_path.resolve().relative_to(PROJECT_ROOT)  # ValueError if outside
    return CONTAINER_PROJECT / relative.as_posix()


class SandboxError(RuntimeError):
    """The sandbox itself can't run (Docker missing, image not built, ...)."""


def detect_multiarch() -> str:
    """Ask Python INSIDE the image for its Debian multiarch triplet.

    e.g. "aarch64-linux-gnu" on Apple chips, "x86_64-linux-gnu" on CI runners.
    Asking the container (not the host) keeps the baseline correct on both.
    """
    docker = shutil.which("docker") or "docker"
    query = "import sysconfig; print(sysconfig.get_config_var('MULTIARCH') or '')"
    try:
        out = subprocess.run(
            [docker, "run", "--rm", "--network", "none", IMAGE, "python", "-c", query],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError(f"could not run docker: {exc}") from None
    multiarch = out.stdout.strip()
    if out.returncode != 0 or not multiarch:
        raise SandboxError(
            f"could not read multiarch from image '{IMAGE}' "
            f"(is it built? `docker build -t {IMAGE} .`): {out.stderr.strip()[:200]}"
        )
    return multiarch


def docker_command(server_script: Path, trace_dir: Path) -> tuple[str, list[str]]:
    """Return (command, args) that run the server under strace in the sandbox."""
    docker = shutil.which("docker") or "docker"
    args = [
        "run",
        "-i",                       # keep stdin open: it's the MCP stdio channel
        "--rm",                     # delete the container when it exits
        "--network", "none",        # no network interfaces except loopback
        "--read-only",              # container filesystem is read-only...
        "--tmpfs", "/tmp",          # ...except a scratch /tmp in memory
        "--user", CONTAINER_USER,   # never root inside the container
        "-v", f"{PROJECT_ROOT}:{CONTAINER_PROJECT}:ro",
        "-v", f"{trace_dir.resolve()}:{CONTAINER_TRACE_DIR}:rw",
        "-w", str(CONTAINER_PROJECT),
        IMAGE,
        # strace flags:
        #   -f   follow child processes and threads
        #   -tt  timestamp every line (microseconds)
        #   -e   only the syscall classes we care about
        #   -o   write the trace to a file, NOT stderr, so it can't mix with MCP traffic
        "strace", "-f", "-tt",
        "-e", "trace=file,process,network",
        "-o", str(CONTAINER_TRACE_DIR / TRACE_FILENAME),
        str(CONTAINER_PYTHON), str(to_container_path(server_script)),
    ]
    return docker, args
