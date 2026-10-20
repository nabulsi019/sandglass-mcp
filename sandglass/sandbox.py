"""Docker sandbox settings: container paths and the `docker run` command.

The server runs inside the sandglass-sandbox image (see Dockerfile) under
strace. Inside the container:

    /project          the project folder, mounted READ-ONLY
    /project/reports  hidden behind an empty read-only tmpfs (old reports and traces)
    /opt/venv         the project's dependencies, baked into the image
    /usr/local        the Python installation from python:3.12-slim

Trace integrity: the trace is the evidence, so the server must not be able to
read, change or delete it. There is no trace file in the container at all:

  1. strace writes the trace to the container's stderr. The client saves that
     stream to reports/trace/<run>/trace.txt on the HOST.
  2. The server never gets a handle on that stream. `sh` gives strace an
     extra fd 3 pointing at /dev/null; the launcher below swaps the server's
     stderr for it (and closes fd 3) before any package code runs.
  3. strace's own fds can't be reopened through /proc/1/fd/...: the Dockerfile
     makes the strace binary executable but not readable, which makes the
     strace process "non-dumpable", so the server gets EACCES there.
"""

import shutil
import subprocess
from pathlib import Path, PurePosixPath

from sandglass import PROJECT_ROOT

IMAGE = "sandglass-sandbox"

CONTAINER_PROJECT = PurePosixPath("/project")
CONTAINER_REPORTS = CONTAINER_PROJECT / "reports"   # hidden from the server
CONTAINER_PYTHON_BASE = PurePosixPath("/usr/local")
CONTAINER_VENV = PurePosixPath("/opt/venv")
CONTAINER_PYTHON = CONTAINER_VENV / "bin" / "python"
TRACE_FILENAME = "trace.txt"

# Matches the non-root user created in the Dockerfile.
CONTAINER_USER = "10001:10001"

# Runs first inside the traced Python (`python -S -c LAUNCHER <server>`), in
# this order:
#   - point the server's stderr (fd 2, which is the trace stream) at /dev/null
#     (fd 3, opened by sh), then close fd 3
#   - make sys.argv / sys.path[0] look like `python <server>` would
#   - only THEN load site-packages (-S skipped it, because .pth files there can
#     run code), and run the server as __main__
# Everything before site.main() is frozen stdlib, so no package code runs while
# the trace stream is still reachable.
LAUNCHER = "; ".join([
    "import os, sys",
    "os.dup2(3, 2)",
    "os.close(3)",
    "sys.argv = sys.argv[1:]",
    "sys.path[0] = os.path.dirname(sys.argv[0])",
    "import site",
    "site.main()",
    "import runpy",
    "runpy.run_path(sys.argv[0], run_name='__main__')",
])


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


def docker_command(server_script: Path) -> tuple[str, list[str]]:
    """Return (command, args) that run the server under strace in the sandbox.

    The trace comes out on the container's STDERR (see the module docstring);
    the caller saves that stream to a file on the host.
    """
    docker = shutil.which("docker") or "docker"
    # strace flags:
    #   -f               follow child processes and threads
    #   -tt              timestamp every line (microseconds)
    #   -e               only the syscall classes we care about
    #   --kill-on-exit   if strace dies, the server dies too (no untraced tail)
    #   -o /proc/self/fd/2   write to strace's own stderr; strace opens it
    #                    close-on-exec, so the server doesn't inherit that copy
    strace = ("exec strace -f -tt -e trace=file,process,network --kill-on-exit"
              f" -o /proc/self/fd/2 {CONTAINER_PYTHON} -S -c \"$1\" \"$2\" 3>/dev/null")
    args = [
        "run",
        "-i",                       # keep stdin open: it's the MCP stdio channel
        "--rm",                     # delete the container when it exits
        "--network", "none",        # no network interfaces except loopback
        "--read-only",              # container filesystem is read-only...
        "--tmpfs", "/tmp",          # ...except a scratch /tmp in memory
        "--user", CONTAINER_USER,   # never root inside the container
        "-v", f"{PROJECT_ROOT}:{CONTAINER_PROJECT}:ro",
        # Cover reports/ (old reports, traces) with an empty, read-only folder.
        "--mount", f"type=tmpfs,destination={CONTAINER_REPORTS},tmpfs-mode=0555",
        "-w", str(CONTAINER_PROJECT),
        IMAGE,
        # sh runs before strace, so it isn't traced. "$1"/"$2" are the
        # launcher code and the server path, passed as separate arguments.
        "sh", "-c", strace, "sandglass-launch",
        LAUNCHER, str(to_container_path(server_script)),
    ]
    return docker, args
