// Fixture server for Sandglass: the Node twin of env_report_server.py (#146).
//
// One tool, report_environment(), returns JSON with two views of the
// environment, names and values: "environ" (process.env) and "proc_environ"
// (/proc/self/environ, what the process started with). The launcher starts
// Node with execv, so both views are the launcher's environment at that point.
//
// Expected in the sandbox under policies/templates/no_network.v1.yaml: CLEAN,
// no "SANDGLASS" in any name or value, and exactly the names in
// check_fixtures.py's EXPECTED_ENVIRONMENT.
//
// No npm packages: MCP over stdio is newline-delimited JSON-RPC 2.0, spoken
// by hand like good_notes_node_server.js. Reads only its own /proc entry.
"use strict";

const fs = require("fs");
const readline = require("readline");

const TOOL = {
  name: "report_environment",
  description: "Show the environment variables this server can see.",
  inputSchema: { type: "object", properties: {} },
};

// /proc/self/environ as an object: NAME=value entries, NUL-separated.
function procEnviron() {
  const result = {};
  for (const entry of fs.readFileSync("/proc/self/environ", "utf8").split("\0")) {
    if (!entry) continue;
    const eq = entry.indexOf("=");
    result[entry.slice(0, eq)] = entry.slice(eq + 1);
  }
  return result;
}

// Answer one JSON-RPC request; returns the result object or throws.
function handle(method, params) {
  switch (method) {
    case "initialize":
      return {
        protocolVersion: params.protocolVersion,  // speak whatever the client speaks
        capabilities: { tools: {} },
        serverInfo: { name: "env_report_server_js", version: "0.1.0" },
      };
    case "ping":
      return {};
    case "tools/list":
      return { tools: [TOOL] };
    case "tools/call": {
      if (params.name !== TOOL.name) throw new Error(`Unknown tool: ${params.name}`);
      const text = JSON.stringify({ environ: { ...process.env }, proc_environ: procEnviron() });
      return { content: [{ type: "text", text }], isError: false };
    }
    default: {
      const err = new Error(`Method not found: ${method}`);
      err.code = -32601;
      throw err;
    }
  }
}

function send(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

// One JSON message per line on stdin. Notifications (no id) get no answer.
readline.createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    return;
  }
  if (msg.id === undefined) return;
  try {
    send({ jsonrpc: "2.0", id: msg.id, result: handle(msg.method, msg.params || {}) });
  } catch (err) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: err.code || -32603, message: err.message } });
  }
});
