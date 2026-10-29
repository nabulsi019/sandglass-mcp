"""Fixture server for Sandglass: a tool that only works with the example its description gives (#145).

One tool, timezone_offset(timezone), like mcp-server-time's get_current_time:
the argument's description says "IANA timezone name (e.g. 'America/New_York')",
and the tool returns an error (isError) unless it gets a name shaped like
Area/City. "hello" (the minimal and schema modes' input) fails; the
described mode reads 'America/New_York' from the description and succeeds.

Expected in the sandbox under policies/notes_readonly.yaml:
  --inputs described (the default)  CLEAN, no coverage summary
  --inputs minimal                  CLEAN (but 1 of 1 tool returned errors)

Safety constraints (intentional): reads no files (not even the tz database),
no network. The answer is a fixed table, not the real time.
"""

import re
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

server = MCPServer("described_input_server")

# A few fixed offsets; any other Area/City name gets "+00:00".
OFFSETS = {"America/New_York": "-05:00", "Europe/London": "+00:00", "Asia/Tokyo": "+09:00"}
TIMEZONE_NAME = re.compile(r"[A-Z][A-Za-z_]+/[A-Z][A-Za-z_]+")


@server.tool(description="Return the standard UTC offset of a timezone.")
def timezone_offset(
    timezone: Annotated[str, Field(description="IANA timezone name (e.g. 'America/New_York').")],
) -> str:
    if not TIMEZONE_NAME.fullmatch(timezone):
        raise ToolError(f"Invalid timezone: {timezone!r} is not an IANA timezone name")
    return f"{timezone}: UTC{OFFSETS.get(timezone, '+00:00')}"


if __name__ == "__main__":
    # stdio transport: the client talks to us over stdin/stdout.
    server.run(transport="stdio")
