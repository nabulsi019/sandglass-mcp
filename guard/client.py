"""Minimal MCP Guard client.

Launches an MCP server as a subprocess over stdio, lists its tools, calls
each tool once with a simple safe input, and prints what came back.
Optionally loads a policy file and prints it (not enforced yet).

Usage:
    uv run python -m guard.client <server.py> [--policy <policy.yaml>]
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent, Tool

from guard.policy import Policy, load_policy

# The one input value we use for every string argument. For the notes
# servers this means read_note("hello") -> allowed_notes/hello.txt.
SAFE_STRING = "hello"


def build_safe_arguments(tool: Tool) -> dict:
    """Build a harmless argument dict from the tool's JSON input schema."""
    defaults = {"string": SAFE_STRING, "integer": 1, "number": 1.0, "boolean": False}
    properties = tool.input_schema.get("properties", {})
    return {
        name: defaults.get(spec.get("type"), SAFE_STRING)
        for name, spec in properties.items()
    }


def format_result(result) -> str:
    """Turn a tool result into printable text."""
    if not isinstance(result, CallToolResult):
        return f"(unexpected result type: {type(result).__name__})"
    texts = [c.text for c in result.content if isinstance(c, TextContent)]
    status = "ERROR" if result.is_error else "OK"
    return f"[{status}] " + "\n".join(texts).strip()


def print_policy(policy: Policy) -> None:
    print(f"Policy: {policy.name} (loaded, NOT enforced yet)")
    print(f"  {policy.description}")
    print(f"  read_allow:    {[str(p) for p in policy.read_allow]}")
    print(f"  write_allow:   {[str(p) for p in policy.write_allow]}")
    print(f"  network_allow: {policy.network_allow}")
    print("  runtime_allow (excluded from violations):")
    for p in policy.runtime_allow:
        print(f"    - {p}")
    print()


async def run(server_script: Path) -> None:
    # Start the server with the same Python interpreter running this client,
    # so it sees the same installed packages (the project's .venv).
    params = StdioServerParameters(command=sys.executable, args=[str(server_script)])

    # stdio_client spawns the subprocess and gives us its stdin/stdout streams.
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()  # MCP handshake

            tools = (await session.list_tools()).tools
            print(f"Server: {server_script.name}")
            print(f"Tools ({len(tools)}):")
            for tool in tools:
                print(f"  - {tool.name}: {tool.description}")
                print(f"    input schema: {json.dumps(tool.input_schema)}")
            print()

            for tool in tools:
                args = build_safe_arguments(tool)
                print(f"Calling {tool.name}({args})")
                result = await session.call_tool(tool.name, args)
                print(f"  -> {format_result(result)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Exercise an MCP server's tools over stdio.")
    parser.add_argument("server", type=Path, help="path to the server .py file")
    parser.add_argument("--policy", type=Path, help="policy YAML to load and display")
    args = parser.parse_args()

    # The server path is a normal CLI argument, so it's relative to the CWD.
    # (Paths INSIDE the policy file are relative to the project root instead.)
    server_script = args.server.resolve()
    if not server_script.is_file():
        parser.error(f"server script not found: {server_script}")

    if args.policy:
        print_policy(load_policy(args.policy, server_script=server_script))

    asyncio.run(run(server_script))


if __name__ == "__main__":
    main()
