# Sandglass sandbox image: Python 3.12 + strace + the project's locked dependencies.
#
# Build:  docker build -t sandglass-sandbox .
#
# Only dependencies are baked in. The project source is mounted read-only at
# /project at run time (see sandglass/sandbox.py), so editing a server never
# requires a rebuild. The host's macOS .venv is never used.

# Pinned to a Debian release (13, "trixie"), so a rebuild can't quietly move to
# a new release with a different strace (the trace parser depends on its
# output format) or different system files (the baselines list them).
# trixie gives strace 6.13 and Node.js 20. Tag, not digest: security updates
# within the release still arrive on rebuild.
FROM python:3.12-slim-trixie

# strace records every syscall the server makes. nodejs (Debian's package)
# runs Node.js servers. npm installs scanned npm packages inside the sandbox
# (`sandglass scan npm:...`, #19), offline, from files downloaded on the host.
# git (#148): servers like mcp-server-git exit at startup without it. It
# brings perl (about 101 MB in all). Running it is still the server's own
# action: a violation unless the policy's exec_allow lists /usr/bin/git.
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace nodejs npm git \
    && rm -rf /var/lib/apt/lists/*

# Executable but NOT readable for the server's user. Linux marks a process
# running an unreadable binary "non-dumpable", so the server (same uid) can't
# open strace's file descriptors through /proc/1/fd/... and reach the trace.
RUN chmod 0711 /usr/bin/strace

# uv, pinned to the same version used on the host, installs from uv.lock.
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv

# PYTHONDONTWRITEBYTECODE: belt and braces; no __pycache__ writes show up in traces.
ENV PYTHONDONTWRITEBYTECODE=1

# Install dependencies only (--no-install-project): the code itself comes from the mount.
# The UV_* settings are for this step only, not ENV, so a server never sees them (#146):
# UV_PROJECT_ENVIRONMENT puts the venv at /opt/venv (outside the /project mount),
# UV_COMPILE_BYTECODE precompiles .pyc now, so the server never writes them at run time.
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN UV_PROJECT_ENVIRONMENT=/opt/venv UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
        uv sync --frozen --no-install-project --no-dev && rm -rf /build
# (#159) No project name in the venv a server can read: uv writes it as the
# venv's prompt (pyvenv.cfg) and into the activate scripts, which nothing here uses.
RUN rm -f /opt/venv/bin/activate* && sed -i '/^prompt = /d' /opt/venv/pyvenv.cfg

# The slim image ships the standard library without .pyc files; compile them
# now so Python doesn't try to write them into /usr/local at run time.
RUN python -m compileall -q /usr/local/lib/python3.12

# Non-root user that runs the server. sandglass/sandbox.py passes the same uid with --user.
RUN useradd --system --uid 10001 --home-dir /home/sandglass --no-create-home \
        --shell /usr/sbin/nologin sandglass

# Where `sandglass scan` installs a package (#19). An empty folder owned by
# that user: a new Docker volume mounted here starts as a copy of it, so the
# install container (non-root) can write into the volume. The server's
# container then mounts the same volume read-only.
RUN mkdir /package && chown 10001:10001 /package

# Decoy $HOME with obviously fake credentials (sandbox/decoy_home/, FAKE_ values
# only), so a server that goes looking for secrets finds something to read and
# shows up in the report. Permissions like a real home; the container's root
# filesystem is --read-only, so the server can read these but never change them.
COPY --chown=10001:10001 sandbox/decoy_home/ /home/sandglass/
RUN chmod 700 /home/sandglass /home/sandglass/.ssh /home/sandglass/.aws \
    && chmod 600 /home/sandglass/.ssh/id_rsa /home/sandglass/.aws/credentials /home/sandglass/.env

# (#159) Sandglass's launcher, network sink and stdin relay, at a neutral
# path, started by path: no command line in the container carries their
# source or the name Sandglass (the server can read every process's
# /proc/<pid>/cmdline). Root-owned and read-only like the rest of the image.
# Must match launcher.RUNTIME_DIR; the client checks these copies against its
# own files before every run (sandbox.detect_multiarch), so rebuild after
# changing them.
COPY sandglass/launcher.py /usr/local/lib/mcp-runtime/run.py
COPY sandglass/netsink.py /usr/local/lib/mcp-runtime/sink.py
COPY sandglass/stdin_relay.py /usr/local/lib/mcp-runtime/relay.py
USER 10001:10001

ENV PATH=/opt/venv/bin:$PATH
WORKDIR /project
