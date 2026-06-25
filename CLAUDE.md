# CLAUDE.md — Pounce

## What this is
Pounce is a CLI that shows what AI coding agents and MCP servers **actually do**. It wraps any MCP server in one line and surfaces every tool call, then (in later phases) the real OS activity — files, network, processes — that each call caused. **Observe-first**: Pounce watches and records; it never blocks, modifies, or injects.

## The core idea (the differentiator)
Other tools see one half. Approval/hook tools see the **tool call** (declared intent); OS monitors see **syscalls** (actual effect, but anonymous). Pounce's value is the **join** — tying each tool call to the OS activity it caused, and flagging when actual behavior diverges from what the call declared. Keep this correlation in mind as the north star even while building the early pieces.

## Architecture
Three parts, deliberately decoupled so non-stdio sources can be added later without a rewrite:
- **Intent source (pluggable):** captures the *declared* action — the tool call. **The stdio tee is just the first plugin:** Pounce is placed in the MCP client config as the `command`, launches the *real* server as a child, and transparently tees the JSON-RPC stdio (bytes through untouched, parsing a copy). Future plugins: an HTTP/SSE reverse-proxy for non-stdio MCP servers, and a log/hook ingester for arbitrary agent runtimes (e.g. OpenClaw skills).
- **OS-capture core (constant):** the *actual* effect — network via **pktap** PID metadata (from the system tcpdump's `-k NP` text — the public DLT_PKTAP API is a dead end on macOS 26; see constraints) (Phase 2), files/exec via `eslogger` (Phase 4) — attributed by **PID subtree**, exposed as one generic OS-event type. Transport-agnostic; this is the real hook for anything running locally.
- **Correlator:** joins intent ↔ OS events by **PID + time window**; flags divergence (discrepancy = the signal). (Phase 3.) Built on network events first; `eslogger` file/exec events slot in later through the same generic OS-event interface — so write the join against the event type, not against network specifically. **The network discrepancy/alert rules — what fires, severity, suppression, confidence — are specified in `TRIGGERS.md`; build against that spec, don't improvise the rules.**

Implement the stdio tee behind a small **intent-source interface** feeding a **source-agnostic event/timeline pipeline**, so the HTTP proxy and log ingester later slot in as new sources reusing the same OS-capture core and correlator. Define that seam now; don't over-abstract it (one clean interface, not a speculative plugin framework).

### Beyond stdio (design intent — do NOT build yet)
- **HTTP/SSE MCP, local:** an HTTP reverse-proxy intent source; OS capture still attributes the local server process → full correlation.
- **Remote MCP servers:** protocol view only — no OS truth for a process you don't run on this machine. Don't pretend otherwise.
- **Arbitrary skills (OpenClaw etc.):** no protocol to tee — wrap the runtime (`pounce wrap -- <gateway cmd>`) so OS capture attributes the whole subtree; get per-skill *intent* labels from the runtime's logs/hooks.
- **Granularity:** subprocess skills → clean per-process attribution; in-process skills → only runtime-PID-level, so you need the log to label them.
- **Correlation degrades gracefully:** protocol path → per-tool-call attribution; process-tree-only → per-process/time-window. Still catches the exfil, just coarser.

### Reactions / actions (future event sink — do NOT build yet)
The event pipeline feeds **sinks**: the session-log writer (Phase 1), the correlator/discrepancy flagger (Phase 3), and later a **rules/actions sink** that matches events (e.g. a detected discrepancy) and runs a configured response.
- **Default = notify / record / route** — alert Slack/PagerDuty, hit a webhook, log, snapshot, SIEM export, run a user script. Stays observe-first: it responds to what happened without changing agent behavior.
- **"Call an MCP tool" is a first-class action type.** Pounce already speaks JSON-RPC, so reacting by invoking a tool on an (already-running) response MCP server reuses the protocol client and turns the whole MCP ecosystem into the integration library — no bespoke per-target code. Richer variant: dispatch to an **investigator agent** (itself using MCP tools) to triage a flagged event and report back — still observe/understand, not enforce. (Don't spawn a fresh server per event — call a long-lived one.)
- **Pounce observes its own reactions.** Once it invokes tools or agents, it's an actor too: log every reaction into Pounce's own timeline, keep them bounded, and keep tool-call actions strictly on the notify/investigate side — not a backdoor to enforcement.
- **Enforce / intervene** (block a call, kill a process, cut network) is a deliberate, opt-in, *later* capability kept off the core path — it crosses into control (Nightglass's lane). If ever built, frame it as *enforcement informed by ground truth*, and note that blocking only works in the **synchronous protocol intercept**; the OS layer is observational (you can't un-read a file), so OS-side "enforcement" is kill-after-detection, not prevention.
- Needs Phase-3 detection to fire on, so nothing to build now — just keep the sink/subscriber seam clean. Shape later: declarative rules (condition → action) + a generic webhook/script escape hatch.

### OS-capture: privilege model & permission tiers
Privileged capture must NOT run inside the client-launched shim — when Cursor/OpenClaw spawns `pounce wrap` it's a non-root child with no TTY, so it can't `sudo`. Split it:
- **`pounced` (privileged, started once):** runs `tcpdump`/pktap (Phase 2) and later `eslogger` (Phase 4) as root, system-wide, and does correlation. Start via `sudo pounce daemon` (power-user) or install as a root launchd `LaunchDaemon` (productized). Grant Full Disk Access once. **Lock down its Unix socket** — verify peer creds (`LOCAL_PEERCRED`); it's a root daemon taking input from unprivileged processes.
- **`pounce wrap` (unprivileged, client-launched):** protocol tee only, no sudo. Reports its child PID subtree + tool-call events to `pounced` over the local socket. One root capture stream serves all shim sessions.

**Permission tiers — ask for the least, as late as possible:**
- Protocol / tool-call timeline (Phase 1) → **nothing** (no root, no FDA).
- Network capture (pktap/tcpdump), Phase 2 → **root, but NOT FDA** (BPF is a root thing, not a TCC/file thing).
- File + exec capture (eslogger), Phase 4 → **root AND FDA**.

**Principle: never gate the first run behind a permission.** Phase 1 runs with zero privilege — land users there. OS-truth is an opt-in *upgrade* the user enables (`pounce daemon`) once they're already getting value, with a legible "why" and a link to the right System Settings pane. The headline exfil demo is mostly the network tier, so it doesn't even need FDA.

## Tech stack & conventions
- **Go**, compiled to a **single static binary** (this is the distribution wedge — keep it dependency-light; avoid CGO unless unavoidable).
- CLI via `cobra` (or stdlib `flag` if simpler). Subcommands: `wrap`, `view`.
- Standard library first; add dependencies only when they clearly earn it. (TUI comes later via Charm `bubbletea`/`lipgloss` — not yet.)
- Idiomatic Go: `gofmt`/`go vet` clean, wrap errors with `%w`, small focused packages, table-driven tests.
- Targets: **macOS-first** (darwin/arm64 + amd64); Linux in scope later. Latest stable Go.

## Suggested layout
```
cmd/pounce/         main, CLI wiring
internal/intent/    intent sources (declared tool calls); stdio tee is the first impl. HTTP proxy + log/hook ingester land here later.
internal/protocol/  JSON-RPC + MCP message parsing (shared by intent sources)
internal/store/     session log (JSONL) read/write
internal/view/      timeline rendering
internal/capture/   OS ground truth by PID subtree: pktap network (Phase 2), eslogger files/exec (Phase 4); one generic OS-event type so both feed the correlator
internal/correlate/ joins intent ↔ OS events by PID + time             (Phase 3; just stub the boundary now)
internal/actions/   rules sink: notify/record/route on detected events  (post-Phase 3; do not build yet)
```
Phase 1 implements only `intent` (stdio), `protocol`, `store`, `view`.

## Build / run / test
```
go build ./...
go run ./cmd/pounce wrap -- npx @some/mcp-server
go run ./cmd/pounce view
go test ./...
```

## Roadmap — current scope
- **Phase 1 (NOW):** stdio shim + protocol tee. No privileges. Ships on its own.
- Phase 2: network ground truth — per-process network via **pktap** (PID from the system tcpdump's `-k NP` text metadata; the binary DLT_PKTAP route is a proven dead end on macOS 26 — see Critical constraints). Root-only, **no FDA**.
- Phase 3: correlation + discrepancy detection, built on intent + network. **MVP = Phases 1–3 — and it needs zero FDA** (the headline exfil demo lives here).
- Phase 4: `eslogger` file/exec capture (files read, processes spawned). Root **+ Full Disk Access**; opt-in enrichment that drops into the existing capture interface + correlator.
- Phase 5: readable TUI / optional `--web` localhost UI. Phase 6: packaging (goreleaser, Homebrew tap, curl installer).
- **Deferred — do NOT build yet:** EndpointSecurity entitlement, NetworkExtension, Linux ptrace/eBPF, any cloud/team features.

> Stay within the current phase unless I explicitly ask to jump ahead.

## Protocol notes
- MCP stdio transport is **JSON-RPC 2.0, newline-delimited** (messages contain no embedded newlines). **Confirm the exact framing against the current MCP spec before implementing the parser** — don't assume this summary is current.
- Capture: `initialize`, `tools/list` (the server's declared tools), `tools/call` (method, params/args, id, timestamp), and responses **matched to requests by `id`**.
- Phase-1 signals worth capturing: diffing `tools/list` across time (tool-definition changes), and scanning `tools/call` args for secrets/keys/paths.

## Critical constraints (don't get these wrong)
- **Transparency is sacred.** The bytes forwarded between client and server must be **identical** — parse a *copy*, never re-serialize the forwarded stream, or you'll break the protocol. `stderr` passes through untouched.
- **Never crash the wrapped server.** On any parse or log error, record it and keep forwarding. Pounce failing must never take the server down.
- **Observe-only.** Do not block, alter, delay, or inject into the stream in these phases.
- (Phase 2) Network attribution comes from pktap's per-packet PID metadata (`pth_pid`, `pth_comm`). **PROVEN DEAD END (macOS 26):** the public libpcap API cannot enable `DLT_PKTAP` — `pcap_set_datalink(PKTAP)` is rejected and the pktap device yields only `DLT_RAW`; a pure-C libpcap probe confirmed this (not a Go/cgo bug). Apple's own tcpdump reaches the header via *private* pktap ioctls the documented API doesn't expose. **Do not re-attempt the cgo+libpcap → DLT_PKTAP route**, and note legacy pcap (`-w -`) also drops the metadata. **Decision: read attribution from the system tcpdump's text metadata** — `sudo /usr/sbin/tcpdump -i pktap -nl -k NP …`, parsing the `(<intf>, proc <name>:<pid>, …)` prefix for the PID and the IP line for the flow 5-tuple. Same kernel PID as the binary path — only parse-robustness differs. **Harden it:** pin to `/usr/sbin/tcpdump` (not Homebrew); strict anchored patterns; on any line that should carry proc/pid but doesn't match, **fail safe to "attribution unavailable"** (never guess) and count it; a startup/CI self-check spawns a known connection and asserts the pid parses, per macOS major (so drift trips CI, not users); record `tcpdump --version` + OS version in the session log. Future option — revisit **only if** the text format becomes a maintenance problem or we need Linux parity / pure-static: hand-roll `/dev/bpf` + Apple's private pktap ioctls for the inline `pktap_header` (substantial, fragile across OS versions; not now). (Phase 4) `eslogger` needs `sudo` + Full Disk Access; if/when Linux ptrace lands, `runtime.LockOSThread` the tracer goroutine.

## Session log
`~/.pounce/sessions/<id>.jsonl` — one event per line (parsed JSON-RPC messages plus a small metadata header). `view` reads this back.
