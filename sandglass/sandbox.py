"""Docker sandbox settings: container paths and the `docker run` command.

The server runs inside the sandglass-sandbox image (see Dockerfile) under
strace. Inside the container:

    /project          the project folder, mounted READ-ONLY
    /project/reports  hidden behind an empty read-only tmpfs (old reports and traces)
    /home/sandglass   $HOME: a decoy with fake credentials, baked into the image
    /opt/venv         the project's dependencies, baked into the image
    /usr/local        the Python installation from python:3.12-slim
    /tmp/work         the server's working directory (#144): an empty folder in
                      the scratch /tmp, made before tracing starts

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

import hashlib
import shutil
import subprocess
from pathlib import Path, PurePosixPath

from sandglass import PROJECT_ROOT, launcher

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
# The server's working directory (#144): a fresh, empty folder in the scratch
# /tmp (already a tmpfs), so a server can write next to itself. No new mount,
# and writes there are judged by the policy like any other.
CONTAINER_WORKDIR = PurePosixPath("/tmp/work")

# The launcher (sandglass/launcher.py) runs first inside the traced Python as
# `python -S CONTAINER_LAUNCHER <server>`: it hides the trace stream from the
# server, starts the local network sink and the stdin relay, then runs the
# server. (#159) The Dockerfile copies the three into the image at a neutral
# path, so no command line in the container carries their source or the
# name Sandglass; the server can read every process's /proc/<pid>/cmdline.
CONTAINER_RUNTIME_DIR = PurePosixPath(launcher.RUNTIME_DIR)
CONTAINER_LAUNCHER = CONTAINER_RUNTIME_DIR / "run.py"
# host file -> its copy in the image (must match the Dockerfile's COPY lines)
IMAGE_HELPERS = {
    "launcher.py": CONTAINER_LAUNCHER,
    "netsink.py": PurePosixPath(launcher.SINK_SCRIPT),
    "stdin_relay.py": PurePosixPath(launcher.RELAY_SCRIPT),
}
# Their source, as on the host: the image's copies must be the same (see
# check_image_helpers), and tests read it.
LAUNCHER = (PROJECT_ROOT / "sandglass" / "launcher.py").read_text(encoding="utf-8")
NETSINK = (PROJECT_ROOT / "sandglass" / "netsink.py").read_text(encoding="utf-8")
STDIN_RELAY = (PROJECT_ROOT / "sandglass" / "stdin_relay.py").read_text(encoding="utf-8")

# What strace records (-e trace=...): strace's file, process and network
# classes, plus:
#   memfd_create  an anonymous in-memory file (#77). Code written there can be
#                 run with execveat() without ever touching the disk.
#   io_uring_*    (#75) the kernel does io_uring's reads and opens itself, so
#                 strace can't see them; we can only see that a ring was used.
#   ptrace, process_vm_readv, process_vm_writev   (#84) tracing another
#                 process or reaching into its memory; refused by Sandglass's
#                 syscall filter (launcher.py), recorded as attempts to evade.
#                 (clone and clone3 are already in "process".)
#   pidfd_getfd, unshare, setns, userfaultfd   (#155) also refused by the
#                 filter, and recorded as attempts to evade like the above.
TRACED_SYSCALLS = ("file,process,network,memfd_create,"
                   "io_uring_setup,io_uring_enter,io_uring_register,"
                   "ptrace,process_vm_readv,process_vm_writev,"
                   "pidfd_getfd,unshare,setns,userfaultfd")


def filtered(argv: list[str]) -> list[str]:
    """`argv` run through Sandglass's syscall filter (#155): the launcher in
    its --filter-then-exec mode installs the filter on itself, runs the
    self-test, then execs argv. The system Python (/usr/local/bin/python),
    -S: no site-packages, so no package code runs before the filter. The
    launcher by its path in the image (#159), never its source."""
    return [str(CONTAINER_SYSTEM_PYTHON), "-S", str(CONTAINER_LAUNCHER), launcher.FILTER_THEN_EXEC, *argv]


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

    (#159) The same run also hashes the image's copies of the launcher, sink
    and relay: an image built from older code would run older helpers, so a
    mismatch stops here (SandboxError: rebuild the image).
    """
    docker = shutil.which("docker") or "docker"
    paths = [str(path) for path in IMAGE_HELPERS.values()]
    query = ("import hashlib, sys, sysconfig; print(sysconfig.get_config_var('MULTIARCH') or '')\n"
             "for path in sys.argv[1:]:\n"
             "    try:\n"
             "        print(hashlib.sha256(open(path, 'rb').read()).hexdigest())\n"
             "    except OSError:\n"
             "        print('missing')")
    try:
        out = subprocess.run(
            [docker, "run", "--rm", "--network", "none", IMAGE, "python", "-c", query, *paths],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError(f"could not run docker: {exc}") from None
    lines = out.stdout.split("\n")
    multiarch = lines[0].strip()
    if out.returncode != 0 or not multiarch:
        raise SandboxError(
            f"could not read multiarch from image '{IMAGE}' "
            f"(is it built? `docker build -t {IMAGE} .`): {out.stderr.strip()[:200]}"
        )
    stale = stale_helpers(lines[1:1 + len(paths)])
    if stale:
        raise SandboxError(f"the image '{IMAGE}' has older copies of {', '.join(stale)} than this "
                           f"checkout; rebuild it: `docker build -t {IMAGE} .`")
    return multiarch


def stale_helpers(image_hashes: list[str]) -> list[str]:
    """(#159) The helpers whose copy in the image (by its sha256, in
    IMAGE_HELPERS order) differs from the file in this checkout."""
    stale = []
    for (name, _), image_hash in zip(IMAGE_HELPERS.items(), image_hashes + [""] * len(IMAGE_HELPERS)):
        host_hash = hashlib.sha256((PROJECT_ROOT / "sandglass" / name).read_bytes()).hexdigest()
        if image_hash.strip() != host_hash:
            stale.append(name)
    return stale


def docker_command(server_script: Path, server_args: list[str] = (),
                   env_names: list[str] = ()) -> tuple[str, list[str]]:
    """Return (command, args) that run the server under strace in the sandbox.

    The trace comes out on the container's STDERR (see the module docstring);
    the caller saves that stream to a file on the host. `server_args` and
    `env_names`: the user's server setup (#144), see _traced_run_args.
    """
    docker = shutil.which("docker") or "docker"
    # strace flags:
    #   -f               follow child processes and threads
    #   -tt              timestamp every line (microseconds)
    #   -y               print the path behind each fd (#122)
    #   -e               only the syscalls we care about (TRACED_SYSCALLS)
    #   --kill-on-exit   if strace dies, the server dies too (no untraced tail)
    #   -o /proc/self/fd/2   write to strace's own stderr; strace opens it
    #                    close-on-exec, so the server doesn't inherit that copy
    mounts = [
        "-v", f"{PROJECT_ROOT}:{CONTAINER_PROJECT}:ro",
        # Cover reports/ (old reports, traces) with an empty, read-only folder.
        "--mount", f"type=tmpfs,destination={CONTAINER_REPORTS},tmpfs-mode=0555",
    ]
    return docker, _traced_run_args(str(to_container_path(server_script)), mounts,
                                    runtime_for(server_script),
                                    server_args=server_args, env_names=env_names)


# Variables the image has that a server shouldn't see (#146): the base image's
# build metadata, and the folder sh came from (/project or /package, which
# would show it's a fixture run or a scan). sh unsets them before tracing.
UNSET_BEFORE_TRACING = ("OLDPWD", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256")


def _traced_run_args(server_path: str, mounts: list[str], runtime: str, site_dir: str = "",
                     workdir: PurePosixPath = CONTAINER_PROJECT, server_args: list[str] = (),
                     env_names: list[str] = ()) -> list[str]:
    """`docker run` arguments that run one server under strace, hardened.

    Shared by the fixture mode (docker_command) and scan mode
    (scan_run_command); only the mounts, `workdir` (Docker's -w) and
    `site_dir` differ. Either way the server itself runs in CONTAINER_WORKDIR (#144).

    `runtime` ("python" or "node") and `site_dir` (where pip installed a
    scanned package, or "") are launcher ARGUMENTS, not environment
    variables (#146): for a Python server the launcher and the server are one
    process, and /proc/self/environ would keep a variable even after the
    launcher deleted it.

    The user's server setup (#144): `server_args` go after them, as separate
    list items (never through a shell string), and the launcher hands them
    to the server. `env_names` become `-e NAME` with no value: Docker copies
    the value from its own environment, which the client sets, so values
    never appear on a command line.
    """
    # sh, before strace (so untraced): make the empty work folder, owned by
    # the sandbox user, go into it, and unset what the server shouldn't see.
    # Then "$@" is the server path, the runtime, the site dir and the
    # server's arguments, each passed on exactly as given. The launcher is a
    # file in the image (#159), never source on a command line.
    # -y (#122): print the file behind each fd, so a successful open shows the
    # file it really opened (= 3</home/x>), even through a symlink.
    strace = (f"mkdir -m 0700 {CONTAINER_WORKDIR} && cd {CONTAINER_WORKDIR} && "
              f"unset {' '.join(UNSET_BEFORE_TRACING)} && "
              f"exec strace -f -tt -y -e trace={TRACED_SYSCALLS} --kill-on-exit"
              f" -o /proc/self/fd/2 {CONTAINER_PYTHON} -S {CONTAINER_LAUNCHER} \"$@\" 3>/dev/null")
    env_args = [arg for name in env_names for arg in ("-e", name)]
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
        # sh runs before strace, so it isn't traced. "$1".."$3" are the server
        # path, the runtime and the site dir, as separate arguments; the
        # server's own arguments follow (#144). "launch" is sh's $0, a neutral
        # name (#159); sh then execs strace, so it's gone anyway.
        "sh", "-c", strace, "launch",
        server_path, runtime, site_dir, *server_args,
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
    the trace stream. Before that line only Sandglass's filter and /bin/sh run.

    (#155) The first traced program is Sandglass's syscall filter (the
    launcher's --filter-then-exec mode, see `filtered`): it installs the
    filter on itself, runs the self-test, then execs that shell, so the
    installer and its children are filtered like the server; strace isn't.
    """
    docker = shutil.which("docker") or "docker"
    env_args = [arg for name, value in (env or {}).items() for arg in ("-e", f"{name}={value}")]
    # "$@" is the whole traced command, as separate arguments: the filter,
    # then the installer's shell with the fixed script and its arguments.
    # The outer sh runs before strace, so it isn't traced; the traced part
    # starts at the filter.
    # -y: print the folder behind each fd, so pip's and npm's dirfd-relative
    # calls (openat(3</tmp/pip-x>, "lib")) get real paths in the trace.
    traced = (f'exec strace -f -tt -y -e trace={TRACED_SYSCALLS} --kill-on-exit -o /proc/self/fd/2 "$@"')
    # "installer": the shell's $0, a neutral name (#159), visible to install scripts.
    installer = ["/bin/sh", "-c", f"exec 2>&1; {script}", "installer", *script_args]
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
        "sh", "-c", traced, "install", *filtered(installer),
    ]
    return docker, args


# The npm download container (#138): where its output folder is mounted.
CONTAINER_OUT = PurePosixPath("/out")
# Its HOME: an empty folder in its tmpfs, so no decoy (or real) credentials are near npm.
DOWNLOAD_HOME = PurePosixPath("/tmp/home")


def npm_download_container_args(out_dir: Path, out_group: int, script: str, npm_command: list[str],
                                env: dict, network: str, name: str) -> list[str]:
    """`docker run` arguments of the npm DOWNLOAD container (#138).

    A separate, short-lived container, not the analysis sandbox: it only
    downloads. It is the one Sandglass container with network access
    (`network`, Docker's default bridge), and only for this step. npm runs
    with --ignore-scripts, so no package code runs here either.

    Hardening: non-root (the sandbox user), read-only root filesystem, every
    capability dropped, no privilege gain (setuid), HOME an empty folder in
    /tmp. The ONLY writable places are `out_dir` (at /out) and a tmpfs /tmp
    with noexec. The project is not mounted. `script` is a fixed shell script
    from scan.py; the npm command reaches it as "$@" arguments.

    `out_group` (the output folder's group, the host user's) is added to the
    user's groups: that is what lets it write into the folder on a Linux host
    (the folder is group-writable), without making the folder writable for
    every user.
    """
    env_args = [arg for key, value in env.items() for arg in ("-e", f"{key}={value}")]
    return [
        "run", "--rm",
        "--name", name,              # so it can be removed if it runs too long
        "--network", network,        # the download step only; the sandbox stays --network none
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid",
        "--user", CONTAINER_USER,    # never root
        "--group-add", str(out_group),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-e", f"HOME={DOWNLOAD_HOME}",
        *env_args,
        "-v", f"{out_dir}:{CONTAINER_OUT}",  # the one writable mount
        "-w", "/tmp",
        IMAGE,
        # (#155) npm runs through Sandglass's syscall filter here too.
        "sh", "-c", script, "download", *filtered(npm_command),
    ]


def scan_run_command(volume: str, server_path: str, runtime: str, server_args: list[str] = (),
                     env_names: list[str] = ()) -> tuple[str, list[str]]:
    """`docker run` that runs the installed package's server under strace.

    The ONLY mount is the package's volume, READ-ONLY at /package (#20). The
    project is NOT mounted: a scanned package can't read Sandglass's code,
    policies, fixtures or reports (its launcher, sink and relay arrive as
    arguments). Docker starts in /package; the server runs in
    CONTAINER_WORKDIR (#144). `server_args`, `env_names`: see _traced_run_args.
    """
    docker = shutil.which("docker") or "docker"
    mounts = ["-v", f"{volume}:{CONTAINER_PACKAGE}:ro"]
    # Read by the launcher after the fd swap (sandglass/launcher.py, step 4).
    # An npm "bin" file doesn't always end in .js, so the runtime is passed.
    site_dir = str(CONTAINER_SITE) if runtime == "python" else ""
    return docker, _traced_run_args(server_path, mounts, runtime, site_dir, workdir=CONTAINER_PACKAGE,
                                    server_args=server_args, env_names=env_names)
