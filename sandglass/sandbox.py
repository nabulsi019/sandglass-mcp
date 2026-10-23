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
    mounts = [
        "-v", f"{PROJECT_ROOT}:{CONTAINER_PROJECT}:ro",
        # Cover reports/ (old reports, traces) with an empty, read-only folder.
        "--mount", f"type=tmpfs,destination={CONTAINER_REPORTS},tmpfs-mode=0555",
    ]
    return docker, _traced_run_args(str(to_container_path(server_script)), mounts)


def _traced_run_args(server_path: str, mounts: list[str], env: dict | None = None,
                     workdir: PurePosixPath = CONTAINER_PROJECT) -> list[str]:
    """`docker run` arguments that run one server under strace, hardened.

    Shared by the fixture mode (docker_command) and scan mode
    (scan_run_command); only the mounts, the working directory and a few
    environment variables differ.
    """
    strace = (f"exec strace -f -tt -e trace={TRACED_SYSCALLS} --kill-on-exit"
              f" -o /proc/self/fd/2 {CONTAINER_PYTHON} -S -c \"$1\" \"$2\" \"$3\" \"$4\" 3>/dev/null")
    env_args = [arg for name, value in (env or {}).items() for arg in ("-e", f"{name}={value}")]
    return [
        "run",
        "-i",                       # keep stdin open: it's the MCP stdio channel
        "--rm",                     # delete the container when it exits
        "--network", "none",        # no network interfaces except loopback
        "--read-only",              # container filesystem is read-only...
        "--tmpfs", "/tmp",          # ...except a scratch /tmp in memory
        "--user", CONTAINER_USER,   # never root inside the container
        "-e", f"HOME={CONTAINER_HOME}",  # the decoy home, never the host's
        *env_args,
        *mounts,
        "-w", str(workdir),
        IMAGE,
        # sh runs before strace, so it isn't traced. "$1".."$4" are the launcher
        # code, the server path, the sink code and the relay code, as separate arguments.
        "sh", "-c", strace, "sandglass-launch",
        LAUNCHER, server_path, NETSINK, STDIN_RELAY,
    ]


# ---------------------------------------------------------------------------
# Scan mode (`sandglass scan`, #19): install a package, then run it
# ---------------------------------------------------------------------------

# Where the scanned package is installed: a fresh Docker volume per scan,
# writable only for the install container, read-only for the server.
CONTAINER_PACKAGE = PurePosixPath("/package")
# Python packages go here (pip install --target); the launcher adds it to sys.path.
CONTAINER_SITE = CONTAINER_PACKAGE / "site"
# The files downloaded on the host, mounted read-only into the install container.
CONTAINER_DOWNLOAD = PurePosixPath("/download")
# The interpreter with pip (the image's /opt/venv, made by uv, has no pip).
CONTAINER_SYSTEM_PYTHON = PurePosixPath("/usr/local/bin/python")


def create_volume(name: str) -> None:
    """A new, empty Docker volume. Mounted at /package, it starts as a copy of
    the image's empty /package (owned by the sandbox user), so it's writable."""
    _docker(["volume", "create", name], "create the install volume")


def remove_volume(name: str) -> None:
    """Delete the volume (and the installed package) after the scan."""
    subprocess.run([shutil.which("docker") or "docker", "volume", "rm", "-f", name],
                   capture_output=True, text=True, timeout=60)


def _docker(args: list[str], what: str) -> subprocess.CompletedProcess:
    docker = shutil.which("docker") or "docker"
    try:
        out = subprocess.run([docker, *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError(f"could not {what}: {exc}") from None
    if out.returncode != 0:
        raise SandboxError(f"could not {what}: {out.stderr.strip()[:200]}")
    return out


def remove_container(name: str) -> None:
    """Stop and delete a container (e.g. an install that ran too long)."""
    subprocess.run([shutil.which("docker") or "docker", "rm", "-f", name],
                   capture_output=True, text=True, timeout=60)


def scan_install_command(volume: str, download_dir: Path, script: str, script_args: list[str],
                         env: dict | None = None, name: str | None = None) -> tuple[str, list[str]]:
    """`docker run` that installs the downloaded files into the volume, under strace (#16).

    Same hardening as the server's container (no network, read-only root,
    non-root, decoy home, no extra capabilities). The ONLY writable places are
    the volume at /package and the scratch /tmp. `script` is a fixed shell
    script from scan.py; package names only ever reach it as "$@" arguments.

    The trace: like the server's, strace writes it to the container's stderr
    and the host saves it (install-trace.txt). The traced shell's first act is
    `exec 2>&1`, so the installer and every install script it runs (npm's
    preinstall/postinstall) write to stdout (the install log) and never hold
    the trace stream. Before that line only /bin/sh runs.
    """
    docker = shutil.which("docker") or "docker"
    env_args = [arg for name, value in (env or {}).items() for arg in ("-e", f"{name}={value}")]
    # "$1" is the install script, the rest are its arguments. sh runs before
    # strace, so it isn't traced; the traced part starts at the inner /bin/sh.
    # -y: print the folder behind each fd, so pip's and npm's dirfd-relative
    # calls (openat(3</tmp/pip-x>, "lib")) get real paths in the trace.
    traced = ('script="$1"; shift; '
              f'exec strace -f -tt -y -e trace={TRACED_SYSCALLS} --kill-on-exit -o /proc/self/fd/2 '
              '/bin/sh -c "exec 2>&1; $script" sandglass-installer "$@"')
    args = [
        "run", "--rm",
        *(["--name", name] if name else []),  # so it can be removed if it runs too long
        "--network", "none",        # offline: everything comes from /download
        "--read-only",
        "--tmpfs", "/tmp",
        "--user", CONTAINER_USER,
        "-e", f"HOME={CONTAINER_HOME}",
        *env_args,
        "-v", f"{download_dir}:{CONTAINER_DOWNLOAD}:ro",
        "-v", f"{volume}:{CONTAINER_PACKAGE}",   # the one writable mount
        "-w", str(CONTAINER_PACKAGE),
        IMAGE,
        "sh", "-c", traced, "sandglass-install", script, *script_args,
    ]
    return docker, args


def scan_run_command(volume: str, server_path: str, runtime: str) -> tuple[str, list[str]]:
    """`docker run` that runs the installed package's server under strace.

    The ONLY mount is the package's volume, READ-ONLY at /package (#20). The
    project is NOT mounted: a scanned package can't read Sandglass's code,
    policies, fixtures or reports (its launcher, sink and relay arrive as
    arguments). The working directory is /package.
    """
    docker = shutil.which("docker") or "docker"
    mounts = ["-v", f"{volume}:{CONTAINER_PACKAGE}:ro"]
    # Read by the launcher after the fd swap (sandglass/launcher.py, step 4).
    env = {"SANDGLASS_RUNTIME": runtime}
    if runtime == "python":
        env["SANDGLASS_SITE_DIR"] = str(CONTAINER_SITE)
    return docker, _traced_run_args(server_path, mounts, env, workdir=CONTAINER_PACKAGE)
