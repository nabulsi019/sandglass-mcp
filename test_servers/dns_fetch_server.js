// Fixture server for Sandglass: a lookup the network sink never sees (#147).
//
// One tool, fetch_hidden(), calls fetch("https://hidden-node.example/").
// Node's fetch ignores HTTPS_PROXY, so it doesn't go through the sink: it
// looks the name up itself (glibc's resolver, /etc/resolv.conf). Before #147
// the trace only showed that a lookup happened; now the DNS recorder the
// launcher starts on 127.0.0.1:53 records the name (A and AAAA) and answers
// NXDOMAIN, so fetch fails with ENOTFOUND, which the tool returns.
//
// Expected in the sandbox under policies/templates/no_network.v1.yaml:
// VIOLATIONS, the recorder's names exactly {hidden-node.example}, one
// violation entry "domain hidden-node.example" holding every violation (the
// lookups and the lookup steps), all in the tool-call phase, and the report
// saying "looked up ..., not contacted" (check_fixtures.py's EXPECTED_DNS).
//
// No npm packages: MCP over stdio by hand, like env_report_server.js.
// hidden-node.example is a reserved name (RFC 2606): nothing is ever reached.
"use strict";

const readline = require("readline");

const TOOL = {
  name: "fetch_hidden",
  description: "Fetch https://hidden-node.example/ and return the error code.",
  inputSchema: { type: "object", properties: {} },
};

// Answer one JSON-RPC request; resolves to the result object or rejects.
async function handle(method, params) {
  switch (method) {
    case "initialize":
      return {
        protocolVersion: params.protocolVersion,  // speak whatever the client speaks
        capabilities: { tools: {} },
        serverInfo: { name: "dns_fetch_server_js", version: "0.1.0" },
      };
    case "ping":
      return {};
    case "tools/list":
      return { tools: [TOOL] };
    case "tools/call": {
      if (params.name !== TOOL.name) throw new Error(`Unknown tool: ${params.name}`);
      let text;
      try {
        const response = await fetch("https://hidden-node.example/");
        text = `status ${response.status}`;
      } catch (err) {
        text = (err.cause && err.cause.code) || err.message;  // ENOTFOUND
      }
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
  handle(msg.method, msg.params || {}).then(
    (result) => send({ jsonrpc: "2.0", id: msg.id, result }),
    (err) => send({ jsonrpc: "2.0", id: msg.id, error: { code: err.code || -32603, message: err.message } }),
  );
});
