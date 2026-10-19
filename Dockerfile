# Sandglass sandbox image: Python 3.12 + strace + the project's locked dependencies.
#
# Build:  docker build -t sandglass-sandbox .
#
# Only dependencies are baked in. The project source is mounted read-only at
# /project at run time (see sandglass/sandbox.py), so editing a server never
# requires a rebuild. The host's macOS .venv is never used.

FROM python:3.12-slim

# strace records every syscall the server makes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

# uv, pinned to the same version used on the host, installs from uv.lock.
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv

# UV_PROJECT_ENVIRONMENT: put the venv at /opt/venv (outside the /project mount).
# UV_COMPILE_BYTECODE: precompile .pyc now, so the server never writes them at run time.
# PYTHONDONTWRITEBYTECODE: belt and braces; no __pycache__ writes show up in traces.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1

# Install dependencies only (--no-install-project): the code itself comes from the mount.
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev && rm -rf /build

# The slim image ships the standard library without .pyc files; compile them
# now so Python doesn't try to write them into /usr/local at run time.
RUN python -m compileall -q /usr/local/lib/python3.12

# Non-root user that runs the server. sandglass/sandbox.py passes the same uid with --user.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sandglass
USER 10001:10001

ENV PATH=/opt/venv/bin:$PATH
WORKDIR /project
