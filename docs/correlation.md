# Correlation & divergence

Correlation is pounce's north star: tie each **declared intent** (a tool call) to
the **actual OS effect** it caused (a network connection), and flag where the two
diverge. The discrepancy is the signal.

It is a pure function over a recorded session log — both the intent events
(Phase 1, the protocol tee) and the OS events (Phase 2, the capture daemon)
already live there. No extra capture, no privileges; `pounce view` runs it.

## The two signals

### 1. Out-of-band (timing)

Each request has an **execution window**: `[request, response] + grace`. A
captured connection whose timestamp falls inside a window is **attributed** to
that call — the call plausibly caused it. A connection covered by **no** window
is **out-of-band**: the server reached out while it wasn't handling any declared
action (background beaconing, exfil-while-idle).

`--window` tunes the grace (default 3s): how long after a call a connection still
counts as caused by it.

### 2. Undeclared destination (DNS)

Timing alone is **necessary but not sufficient**. A rogue server can connect to a
malicious IP *during* a benign tool call — the connection lands in the window, so
it looks "caused by" the call. To catch that, pounce cross-checks **where** the
connection went against the DNS the server actually resolved:

```
declared host (tool-call args)  →  DNS resolution (host → IP)  →  TCP connection (IP)
```

- The pktap stream carries the server's **DNS** traffic. pounce decodes the
  query (`A? api.example.com`) and the response (`A 93.184.216.34`), joins them
  by transaction id, and records `api.example.com → 93.184.216.34`.
- Tool-call arguments are scanned for `http(s)://` URLs to learn the **declared**
  hosts.
- Each connection's IP is then classified:
  - **declared** — the IP was resolved from a host named in a tool call. Fully
    explained. ✅
  - **resolved, host not declared** — the IP came from a DNS lookup, but for a
    host the agent never mentioned. ⚠ worth a look.
  - **unresolved — no DNS** — the IP was produced by *no* DNS lookup in the
    session. A hardcoded destination. **The exfil signal**, flagged regardless of
    timing.

## Reading the output

```
14:00:00.000 ->  tools/call fetch  {"url":"https://api.example.com/data"}  -> ok
14:00:00.050 · dns  api.example.com → 93.184.216.34   node pid 999
14:00:00.200 · net  tcp 93.184.216.34:443  out  node pid 999
14:00:00.400 · net  tcp 45.83.12.9:443  out  node pid 999

correlation (window 3s):
  tools/call fetch → caused 2
      tcp 93.184.216.34:443  (api.example.com, declared)   node pid 999
      tcp 45.83.12.9:443     (unresolved — no DNS)          node pid 999
  ⚠ 1 undeclared destination(s) — IP not resolved from any host:
      tcp 45.83.12.9:443     (unresolved — no DNS)          node pid 999
```

Both connections happened during the `fetch` call. Time-based attribution alone
would show both as caused-by-fetch. The destination check separates them: the
resolved one is explained; the hardcoded `45.83.12.9` is flagged.

## Caveats (read these)

Correlation is **observe-only inference**, not proof. Known limitations:

- **DNS cache → false positives.** If a host is already cached (by the app or the
  OS resolver), connecting to it produces no DNS packet, so the connection reads
  as *unresolved*. The live demo (`scripts/demo-correlate.sh`) flushes the cache
  first. In practice you'd combine signals or allowlist known IPs. We err toward
  flag-don't-miss: a false "unresolved" is louder, not quieter.
- **Encrypted DNS (DoH/DoT)** hides the query/answer, so resolutions aren't
  observed — though a tool that declared a plain `http(s)://` URL while doing
  encrypted DNS is itself suspicious.
- **Conservative declaration.** We mark a destination "declared" only from
  explicit URLs in arguments — never from loose string matches — so we never
  *suppress* an alarm by over-declaring. The cost is more "host not declared"
  notes for tools that pass hosts in non-URL forms.
- **Attribution is by PID + time, not proof of causation.** A connection in a
  call's window is *correlated*, not proven caused. Concurrent/pipelined calls
  attribute to the most recently started window.
- **Short-lived processes** may be missed by the subtree poll (see the capture
  notes); a connection from a process pounce never saw is unattributed.
- **macOS PID source.** The per-packet PID comes from the system tcpdump's text
  pktap metadata — the binary paths don't expose it on macOS 26 (see
  `CLAUDE.md`'s capture notes). Parsing is anchored and drift-guarded, but it's
  text.

## What's next

The same join is written against the generic OS event, so the **eslogger** file/
exec events (Phase 4) drop in through it — e.g. "this tool call read this file"
or "spawned this process." A rules/actions sink can fire on a detected
divergence (notify, snapshot, investigate).
