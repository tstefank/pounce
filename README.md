# pounce

Ground truth for AI coding agents — what every MCP tool call actually did.

Pounce wraps any [MCP](https://modelcontextprotocol.io) server in one line and
surfaces every JSON-RPC message that flows through it. It's **observe-only**: it
watches and records, and never blocks, modifies, or injects into the stream —
the wrapped server behaves exactly as if pounce weren't there.

> **The MVP (Phases 1–3), zero Full Disk Access:** tool-call timeline (no
> privileges), per-process network capture (opt-in `sudo pounce daemon`, root
> only), and intent↔effect correlation with **trigger rules**. `pounce view`
> shows a verdict-first summary — each tool call with the connections it caused,
> labeled `⚠` alert (a local-only tool egressed, or a call connected somewhere it
> didn't declare) / `?` to review (a novel or unnamed destination) / `✓` expected
> — and `--all` rolls several parallel servers into one overview. The alert rules
> are specified in [TRIGGERS.md](TRIGGERS.md). File/exec capture (`eslogger`) is
> Phase 4 — see [Roadmap](#roadmap).

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

### OS ground truth (network tier, opt-in)

Phase 1 (above) is the *declared* intent — the tool calls. To also see the
*actual* per-process network activity those calls cause, run the capture daemon
once. It's an opt-in upgrade: **root, but no Full Disk Access**.

```sh
sudo pounce daemon        # privileged capture (system tcpdump on pktap)
```

With the daemon running, `pounce wrap` automatically reports its child PID
subtree to it (no flag, no privilege on the shim side) and records the
attributed connections into the same session log. No daemon running → `wrap`
behaves exactly as in Phase 1. `pounce view` then interleaves the network
events into the timeline:

```
13:01:27.809 · net  udp 172.20.10.1:53       out  curl pid 50592
13:01:28.517 · net  tcp 104.20.23.154:443    out  curl pid 50592   ← the connection a tool caused
```

The capture is observe-only and attributed by PID subtree. On current macOS the
PID comes from the system tcpdump's pktap metadata (`-k NP`); the session log
records the `tcpdump`/OS versions for provenance.

### Try the whole thing end-to-end

[`scripts/demo-e2e.sh`](scripts/demo-e2e.sh) (needs `sudo`, no FDA) runs all three
phases against [`examples/trojan-fetch-server.mjs`](examples/trojan-fetch-server.mjs)
— an MCP server whose `fetch` tool honestly fetches the URL but *also* quietly
connects to a hardcoded IP. pounce records the tool call, captures both
connections, ties the legit one back to the declared URL via DNS (`✓ expected`),
and fires a `⚠ destination mismatch` alert on the hardcoded one.

## How it works

Three deliberately decoupled parts:

- **Intent source (pluggable):** captures the *declared* action — the tool call.
  The stdio tee is the first source; an HTTP/SSE proxy and a log/hook ingester
  slot in behind the same interface later.
- **OS-capture core (Phase 2+):** the *actual* effect — network via the system
  `tcpdump` on `pktap` (Phase 2), files/exec via `eslogger` (Phase 4) —
  attributed by PID subtree.
- **Correlator + triggers (Phase 3):** joins intent ↔ effect by PID + time, names
  each destination from the server's own DNS, then applies the
  [TRIGGERS.md](TRIGGERS.md) rules — capability mismatch (a local-only tool
  egressed), destination mismatch (went somewhere it didn't declare, e.g. a
  hardcoded/exfil IP caught inside a benign call's window), novel destination, and
  more — each a finding with a severity and confidence. See
  [docs/correlation.md](docs/correlation.md) for the mechanics and caveats.

## Roadmap

- **Phase 1:** stdio shim + protocol tee. No privileges.
- **Phase 2:** network ground truth — system `tcpdump` on the `pktap` interface
  (per-process network). Root-only, **no Full Disk Access**.
- **Phase 3:** correlation + discrepancy detection, built on intent + network.
  **MVP = Phases 1–3**, and it needs zero FDA — the headline exfil demo lives here.
- **Phase 4:** `eslogger` file/exec capture (files read, processes spawned).
  Root **+ Full Disk Access**; opt-in enrichment.
- **Phase 5:** readable TUI / optional `--web` localhost UI.
- **Phase 6:** packaging (goreleaser, Homebrew tap, curl installer).

## License

See [LICENSE](LICENSE).
