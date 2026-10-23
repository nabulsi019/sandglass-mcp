"""Docker sandbox settings: container paths and the `docker run` command.

The server runs inside the sandglass-sandbox image (see Dockerfile) under
strace. Inside the container:

    /project          the project folder, mounted READ-ONLY
    /project/reports  hidden behind an empty read-only tmpfs (old reports and traces)
    /home/sandglass   $HOME: a decoy with fake credentials, baked into the image
    /opt/venv         the project's dependencies, baked into the image
    /usr/local        the Python installation from python:3.12-slim

Trace integrity: the trace is the evidence, so the server must not be able to
read, change or delete it. There is no trace file in the container at all:

  1. strace writes the trace to the container's stderr. The client saves that
     stream to reports/trace/<run>/trace.txt on the HOST.
  2. The server never gets a handle on that stream. `sh` gives strace an
     extra fd 3 pointing at /dev/null; the launcher (sandglass/launcher.py)
     swaps the server's stderr for it (and closes fd 3) before any package
     code runs.
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
CONTAINER_NODE = PurePosixPath("/usr/bin/node")  # Debian's nodejs, for .js servers


def runtime_for(server_script: Path) -> str:
    """Which runtime runs this server: "node" for .js files, else "python"."""
    return "node" if server_script.suffix == ".js" else "python"
TRACE_FILENAME = "trace.txt"

# Matches the non-root user created in the Dockerfile.
CONTAINER_USER = "10001:10001"
# That user's home: a decoy with fake credentials, baked into the image from
# sandbox/decoy_home/. The host's home is never mounted.
CONTAINER_HOME = PurePosixPath("/home/sandglass")

# The launcher (sandglass/launcher.py) runs first inside the traced Python as
# `python -S -c LAUNCHER <server>`: it hides the trace stream from the server,
# starts the local network sink, then runs the server. Its source is read here,
# on the host, so the container doesn't have to read an extra file.
LAUNCHER = (PROJECT_ROOT / "sandglass" / "launcher.py").read_text(encoding="utf-8")
# The local network sink the launcher starts (see sandglass/netsink.py).
NETSINK = (PROJECT_ROOT / "sandglass" / "netsink.py").read_text(encoding="utf-8")
# The stdin relay the launcher starts (see sandglass/stdin_relay.py).
STDIN_RELAY = (PROJECT_ROOT / "sandglass" / "stdin_relay.py").read_text(encoding="utf-8")

# What strace records (-e trace=...): strace's file, process and network
# classes, plus:
#   memfd_create  an anonymous in-memory file (#77). Code written there can be
#                 run with execveat() without ever touching the disk.
#   io_uring_*    (#75) the kernel does io_uring's reads and opens itself, so
#                 strace can't see them; we can only see that a ring was used.
TRACED_SYSCALLS = ("file,process,network,memfd_create,"
                   "io_uring_setup,io_uring_enter,io_uring_register")


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
    #   -e               only the syscalls we care about (TRACED_SYSCALLS)
    #   --kill-on-exit   if strace dies, the server dies too (no untraced tail)
    #   -o /proc/self/fd/2   write to strace's own stderr; strace opens it
    #                    close-on-exec, so the server doesn't inherit that copy
    strace = (f"exec strace -f -tt -e trace={TRACED_SYSCALLS} --kill-on-exit"
              f" -o /proc/self/fd/2 {CONTAINER_PYTHON} -S -c \"$1\" \"$2\" \"$3\" \"$4\" 3>/dev/null")
    args = [
        "run",
        "-i",                       # keep stdin open: it's the MCP stdio channel
        "--rm",                     # delete the container when it exits
        "--network", "none",        # no network interfaces except loopback
        "--read-only",              # container filesystem is read-only...
        "--tmpfs", "/tmp",          # ...except a scratch /tmp in memory
        "--user", CONTAINER_USER,   # never root inside the container
        "-e", f"HOME={CONTAINER_HOME}",  # the decoy home, never the host's
        "-v", f"{PROJECT_ROOT}:{CONTAINER_PROJECT}:ro",
        # Cover reports/ (old reports, traces) with an empty, read-only folder.
        "--mount", f"type=tmpfs,destination={CONTAINER_REPORTS},tmpfs-mode=0555",
        "-w", str(CONTAINER_PROJECT),
        IMAGE,
        # sh runs before strace, so it isn't traced. "$1".."$4" are the launcher
        # code, the server path, the sink code and the relay code, as separate arguments.
        "sh", "-c", strace, "sandglass-launch",
        LAUNCHER, str(to_container_path(server_script)), NETSINK, STDIN_RELAY,
    ]
    return docker, args
