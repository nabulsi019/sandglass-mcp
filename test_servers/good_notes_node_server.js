// Well-behaved Node.js fixture server for Sandglass: the Node twin of
// good_notes_server.py.
//
// Exposes one tool, read_note(name), which reads <name>.txt from the
// allowed_notes/ folder next to this file and refuses anything outside it.
// It should never violate notes_readonly.yaml.
//
// No npm packages: MCP over stdio is newline-delimited JSON-RPC 2.0, and this
// server only needs four messages (initialize, notifications/initialized,
// tools/list, tools/call), so it speaks them by hand. Nothing to install.
"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");

// Anchor to this file's location, not the current working directory.
const NOTES_DIR = path.resolve(__dirname, "allowed_notes");

const TOOL = {
  name: "read_note",
  description: "Read a text note by name from the notes folder.",
  inputSchema: {
    type: "object",
    properties: { name: { type: "string", title: "Name" } },
    required: ["name"],
  },
};

// Same rules as good_notes_server.resolve_note_path.
function readNote(name) {
  const filename = name.endsWith(".txt") ? name : `${name}.txt`;
  const notePath = path.resolve(NOTES_DIR, filename);  // collapses "..", absolute names win
  if (notePath !== NOTES_DIR && !notePath.startsWith(NOTES_DIR + path.sep)) {
    throw new Error(`Rejected: '${name}' is outside the allowed notes folder`);
  }
  if (!fs.existsSync(notePath) || !fs.statSync(notePath).isFile()) {
    throw new Error(`Note not found: '${name}'`);
  }
  return fs.readFileSync(notePath, "utf8");
}

// Answer one JSON-RPC request; returns the result object or throws.
function handle(method, params) {
  switch (method) {
    case "initialize":
      return {
        protocolVersion: params.protocolVersion,  // speak whatever the client speaks
        capabilities: { tools: {} },
        serverInfo: { name: "good_notes_node_server", version: "0.1.0" },
      };
    case "ping":
      return {};
    case "tools/list":
      return { tools: [TOOL] };
    case "tools/call":
      if (params.name !== TOOL.name) throw new Error(`Unknown tool: ${params.name}`);
      try {
        const text = readNote(String((params.arguments || {}).name || ""));
        return { content: [{ type: "text", text }], isError: false };
      } catch (err) {
        return { content: [{ type: "text", text: err.message }], isError: true };
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
