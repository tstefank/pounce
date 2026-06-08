# pounce

Ground truth for AI coding agents — what every MCP tool call actually did.

Pounce wraps any [MCP](https://modelcontextprotocol.io) server in one line and
surfaces every JSON-RPC message that flows through it. It's **observe-only**: it
watches and records, and never blocks, modifies, or injects into the stream —
the wrapped server behaves exactly as if pounce weren't there.

> **v0.1.0 (Phase 1):** the stdio shim + protocol tee. No privileges required.
> OS-level capture (files/network/processes) and intent↔effect correlation are
> on the roadmap — see [Roadmap](#roadmap).

## Install

Download a binary from the [releases page](https://github.com/tstefank/pounce/releases),
or build from source (Go 1.22+):

```sh
go build -o pounce ./cmd/pounce
```

## Usage

Wrap an MCP server — put `pounce wrap --` in front of the command you already run:

```sh
pounce wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

Pounce launches the real server, forwards stdio byte-for-byte, and logs every
JSON-RPC message to `~/.pounce/sessions/<id>.jsonl`. All pounce output goes to
stderr; stdout stays a pure protocol stream, so it drops straight into any MCP
client config as the `command`.

Then replay the tool-call timeline:

```sh
pounce view                 # most recent session
pounce view --session <id>  # a specific session id or .jsonl path
pounce view --color=never   # disable ANSI color (auto-detected by default)
```

Example output:

```
session 20260607-202936.112
command: npx -y @modelcontextprotocol/server-filesystem /tmp

22:29:36.122 ->  initialize  -> ok (secure-filesystem-server 0.2.0, protocol 2025-11-25)
22:29:36.543 ->  tools/list  -> 14 tools [create_directory, directory_tree, edit_file, …]
22:29:36.544 <-  roots/list  -> 1 roots [file:///Users/tomasz/pounce]
22:29:51.454 ->  tools/call list_allowed_directories  {}  -> ok
22:29:58.034 ->  tools/call read_text_file  {"path":"…/.mcp.json"}  -> ok

summary: 5 requests (2 tool calls, 0 errors), 1 notifications
```

### Wiring into a client

Any MCP client config works — just prepend `pounce wrap --`. For example, a
project `.mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "pounce",
      "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

## How it works

Three deliberately decoupled parts:

- **Intent source (pluggable):** captures the *declared* action — the tool call.
  The stdio tee is the first source; an HTTP/SSE proxy and a log/hook ingester
  slot in behind the same interface later.
- **OS-capture core (Phase 2):** the *actual* effect — files/exec/network,
  attributed by PID subtree.
- **Correlator (Phase 3):** joins intent ↔ effect by PID + time, and flags when
  actual behavior diverges from what a call declared.

v0.1.0 ships the intent source (stdio) only.

## Roadmap

- **Phase 1 (this release):** stdio shim + protocol tee.
- **Phase 2:** macOS OS ground truth (`eslogger` + `pktap`).
- **Phase 3:** correlation + divergence detection.
- **Phase 4:** richer TUI / optional localhost web UI.
- **Phase 5:** packaging (goreleaser, Homebrew tap, curl installer).

## License

See [LICENSE](LICENSE).
