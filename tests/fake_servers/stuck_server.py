"""A tiny single-threaded MCP server for tests/test_coverage.py (#140), run on the host.

A raw stdio loop, no SDK: it reads one JSON-RPC message per line and answers
it before reading the next. Its "stuck" tool never returns, so after that
call the server reads nothing more: no later call or ping gets an answer.

With --ping-error it answers ping with method-not-found instead of a result,
and "stuck" only waits for the next message instead of hanging forever: a
server that is alive but doesn't support ping.

Three tools, in this order: first_tool, stuck, last_tool. It touches no
files and no network.
"""

import json
import sys
import threading

PING_ERROR = "--ping-error" in sys.argv
TOOLS = [{"name": name, "description": "", "inputSchema": {"type": "object", "properties": {}}}
         for name in ("first_tool", "stuck", "last_tool")]


def send(message: dict) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", **message}) + "\n")
    sys.stdout.flush()


def answer(request: dict) -> None:
    method, request_id = request.get("method"), request.get("id")
    if request_id is None:
        return  # a notification: nothing to answer
    if method == "initialize":
        send({"id": request_id, "result": {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {"tools": {}}, "serverInfo": {"name": "stuck_server", "version": "1"}}})
    elif method == "tools/list":
        send({"id": request_id, "result": {"tools": TOOLS}})
    elif method == "ping" and PING_ERROR:
        send({"id": request_id, "error": {"code": -32601, "message": "Method not found: ping"}})
    elif method == "ping":
        send({"id": request_id, "result": {}})
    elif method == "tools/call" and request["params"]["name"] == "stuck":
        if not PING_ERROR:
            threading.Event().wait()  # stuck for good: the loop never reads again
        # --ping-error: no answer to this call, but the loop keeps reading.
    elif method == "tools/call":
        send({"id": request_id, "result": {
            "content": [{"type": "text", "text": "done"}], "isError": False}})
    else:
        send({"id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})


if __name__ == "__main__":
    for line in sys.stdin:
        answer(json.loads(line))
