"""Sandglass: run an MCP server, observe what it does, compare against a policy."""

from pathlib import Path

# The folder that contains sandglass/. Policy paths are resolved against this
# (or against /project when running in the sandbox), never the CWD.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
