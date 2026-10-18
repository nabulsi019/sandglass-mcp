# MCP Guard

MCP Guard is a security research tool for [Model Context Protocol](https://modelcontextprotocol.io)
servers. The goal: run an MCP server in isolation, exercise its tools, record
what it **actually does** (files, processes, network), and compare that with a
stated **policy**.

A server's tool description says what it *claims* to do. MCP Guard checks what
it *really* does.

> **Status: step 1 (setup).** There is a client that exercises a server's tools
> and a policy format that loads and validates. There is **no sandbox or
> monitoring yet**, so nothing is enforced.

## Layout

```
guard/
  client.py        Launches a server over stdio, lists tools, calls each once
  policy.py        Loads + validates a policy YAML (not enforced yet)
policies/
  notes_readonly.yaml
test_servers/      Fixture servers written for testing MCP Guard. Not real targets.
  good_notes_server.py       read_note(name): reads only from allowed_notes/
  overreach_notes_server.py  Same tool, but also reads decoy_home/.fake_credentials
  allowed_notes/             The only folder the notes servers are allowed to read
  decoy_home/                Fake "home" with an obviously fake credential file
reports/           Output (future)
```

## Setup

Requires [uv](https://docs.astral.sh/uv/). uv installs a compatible Python
(3.11+) for you if needed.

```bash
uv sync
```

## Running the servers through the client

```bash
# Well-behaved server
uv run python -m guard.client test_servers/good_notes_server.py --policy policies/notes_readonly.yaml

# Server that secretly reads outside its scope
uv run python -m guard.client test_servers/overreach_notes_server.py --policy policies/notes_readonly.yaml
```

The client calls every tool once, using `"hello"` for each string argument, so
`read_note("hello")` returns `allowed_notes/hello.txt`. `--policy` is optional.

**Both servers produce the same output.** That is intentional. The overreach
server's extra file read is invisible at the MCP protocol level. Catching it
needs OS-level observation, which is the next step.

## Policy format

```yaml
name: notes_readonly
description: Notes server may only read .txt files from its notes folder.
filesystem:
  read_allow: [test_servers/allowed_notes]   # any other file read = violation
  write_allow: []                            # no writes
network:
  allow: false                               # no connections
runtime_allow:                               # excluded from violations
  - "{python_base}"
  - "{venv}"
  - "{server_script}"
```

**Path resolution:** relative paths in a policy are resolved against the
**project root** (the folder that contains `guard/`), **not the current working
directory**. The policy means the same thing wherever you run the client from.
Absolute paths are used as-is. (The server path you pass on the command line is
an ordinary CLI argument, so that one *is* relative to your current directory.)

**`runtime_allow`** lists files the interpreter and server legitimately need just
to start: the Python installation, the virtualenv's packages, and the server's
own source file. Step 2 will record *every* file open, and Python opens hundreds
of these during imports. Anything under a `runtime_allow` path is **excluded
from violations** so the real findings stand out. These placeholders are filled
in at load time:

| Placeholder       | Meaning                                    |
|-------------------|--------------------------------------------|
| `{python_base}`   | Python installation (`sys.base_prefix`)    |
| `{venv}`          | Active virtualenv (`sys.prefix`)           |
| `{server_script}` | The server file being tested               |

## Safety rules

1. **Only run servers you wrote or have explicit permission to test.** MCP Guard
   executes the server's code. In step 1 there is no sandbox, so treat any
   server as code running with your full user permissions.
2. **Only use fake credentials.** Decoys like `test_servers/decoy_home/.fake_credentials`
   must contain obviously fake values (e.g. `FAKE_KEY_FOR_TESTING`).
3. **Never put real secrets anywhere a tested server can reach**, including the
   project folder and environment variables passed to the server.
4. **Disclose real findings privately.** If you find a real server misbehaving,
   report it privately to its maintainers (security contact or private advisory)
   and give them time to fix it before you publish anything.
