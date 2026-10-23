#!/usr/bin/env node
// Well-behaved notes server, packaged as an npm tarball to test `sandglass scan`.
//
// One tool, read_note(name), which reads <name>.txt from the notes/ folder
// inside this package and refuses anything outside it. Expected: CLEAN.
//
// No dependencies: MCP over stdio is newline-delimited JSON-RPC 2.0, spoken by
// hand like test_servers/good_notes_node_server.js.
"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");

const NOTES_DIR = path.resolve(__dirname, "notes");

const TOOL = {
  name: "read_note",
  description: "Read a text note by name from the notes folder.",
  inputSchema: {
    type: "object",
    properties: { name: { type: "string", title: "Name" } },
    required: ["name"],
  },
};

function readNote(name) {
  const filename = name.endsWith(".txt") ? name : `${name}.txt`;
  const notePath = path.resolve(NOTES_DIR, filename);
  if (notePath !== NOTES_DIR && !notePath.startsWith(NOTES_DIR + path.sep)) {
    throw new Error(`Rejected: '${name}' is outside the notes folder`);
  }
  if (!fs.existsSync(notePath) || !fs.statSync(notePath).isFile()) {
    throw new Error(`Note not found: '${name}'`);
  }
  return fs.readFileSync(notePath, "utf8");
}

function handle(method, params) {
  switch (method) {
    case "initialize":
      return {
        protocolVersion: params.protocolVersion,
        capabilities: { tools: {} },
        serverInfo: { name: "sandglass-test-notes", version: "1.0.0" },
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
