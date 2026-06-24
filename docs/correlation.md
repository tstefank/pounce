# Correlation & triggers

Correlation is pounce's north star: tie each **declared intent** (a tool call) to
the **actual OS effect** it caused (a network connection), then let the **trigger
rules** decide what diverged and how loudly to say so. The discrepancy is the
signal.

This is a pure function over a recorded session log — both the intent events
(Phase 1, the protocol tee) and the OS events (Phase 2, the capture daemon)
already live there. No extra capture, no privileges; `pounce view` runs it.

Two layers:

1. **Correlation** (`internal/correlate`) — the substrate: attribute each
   connection to a tool call by PID + time, and name its destination from the
   DNS the server actually resolved.
2. **Triggers** (`internal/triggers`) — the rules: turn each attributed
   connection into a **finding** with a *type*, *severity*, and *confidence*. The
   rule set, severities, suppression, and confidence model are specified in
   [`TRIGGERS.md`](../TRIGGERS.md); this doc explains how they're implemented.

## Layer 1 — the correlation substrate

### Attribution (timing)

Each request has an **execution window**: `[request, response] + grace`. A
captured connection whose timestamp falls inside a window is **attributed** to
that call. A connection covered by **no** window is **out-of-band** (the server
reached out while not handling any declared action). `--window` tunes the grace
(default 3s).

When several calls are open at once, a connection is attributed to the call whose
arguments **named its destination** if any did (`ByDeclaredHost`); otherwise to
the most recently started open call, and the join is marked `Ambiguous` (it feeds
confidence, below).

### Naming the destination (DNS)

You see IPs; arguments declare names. The pktap stream carries the server's own
**DNS** traffic — pounce decodes the query (`A? api.example.com`) and answer
(`A 93.184.216.34`), joins them by transaction id, and records
`api.example.com → 93.184.216.34`. Tool-call arguments are scanned for
`http(s)://` URLs to learn the **declared** hosts.

```
declared host (tool-call args)  →  DNS resolution (host → IP)  →  TCP connection (IP)
```

## Layer 2 — the trigger rules

Each attributed connection is evaluated, highest signal first (see
[`TRIGGERS.md`](../TRIGGERS.md) for the full rationale). The first rule that
matches wins:

| # | Trigger | Fires when | Severity |
|---|---------|-----------|----------|
| 3a | **Cloud metadata endpoint** | destination is `169.254.169.254` (SSRF-class) | High |
| — | *scope filter* | destination is private / loopback / link-local | Info |
| 1 | **Capability mismatch** | a local-only tool (built-in prior, e.g. `read_file`, or a learned never-egressing tool) made any connection | High |
| 2 | **Destination mismatch** | the call named a host but the connection went elsewhere (compared at registrable domain / eTLD+1; the declared host's own resolved IPs count as legit) | High |
| 4 | **Novel destination** | a call that declared no host reached a registrable domain unseen for this `(server, tool)` | Medium |
| 3b | **Raw IP, no DNS** | a connection to a public IP with no preceding lookup | Medium |
| 5 | **Expected** | known/declared host, expected egress | Info |

**Severity → how it surfaces.** `pounce view` renders each connection by severity
and leads with a one-line verdict naming the rules that fired:

- **⚠ High** → an *alert* (red). The headline catch.
- **? Medium** → *to review* (yellow). Dimmed when it stays in the timeline rather
  than pushing (see confidence and learning).
- **✓ Info** → *expected* (green). Silent in the verdict.

### Confidence

`confidence = attribution_certainty × naming_certainty`:

- attribution: named-by-the-call `1.0`, single open call `0.8`, ambiguous
  (several open, timing-only) `0.5`, out-of-band `0.3`.
- naming: a resolved/named destination `1.0`, a raw IP `0.6`.

A **High** finding always surfaces as an alert (a capability or destination
mismatch is certain even when the IP is unnamed). A **Medium** finding only
*pushes* (counts as "to review") when it's confident (`≥ 0.5`) and not soft —
otherwise it sits in the timeline. This is the "don't cry wolf on a shaky join"
discipline.

### Dedupe

Findings are collapsed to **one per (tool call, destination)** — not one per
connection — keying on the registrable domain when the destination is named
(several IPs of one domain count once) and on the IP otherwise. `pounce view`
shows the collapsed count as `×N`. This is the fatigue rule: a tool that reaches
one new domain ten times is one finding, not ten.

### Learning (the per-`(server, tool)` profile)

Novelty (#4) and the learned half of capability mismatch (#1) need a baseline of
where each `(server, tool)` normally goes. `pounce wrap` folds every completed,
captured session into `~/.pounce/profile.json`:

- **Order-independent.** Each fact (a tool was seen, it egressed, it reached a
  domain) records the *earliest session id* that established it. Queries compare
  against strictly-earlier sessions, so learning a session never suppresses that
  session's own debut destinations — only genuinely-prior ones form the baseline.
- **Cold-start.** A `(server, tool)`'s first session is its *learning window*:
  novelty there is **provisional** (shown `?` "(learning)", not pushed) so day-one
  doesn't flood. Capability mismatch still fires from day one (it needs no
  baseline).
- **Mute, not allow.** The seen-domain set suppresses repeat notifications — it
  never permits traffic. Pounce observes; it does not block (the TRIGGERS.md
  invariant).

## Reading the output

```
node trojan-fetch-server.mjs  20260623-120000.000-1
⚠ 1 alert — destination mismatch

  tools/call fetch  {"url":"https://example.com"}
     ✓ tcp 93.184.216.34:443  declared example.com
     ⚠ tcp 1.1.1.1:443  declared example.com — connected to 1.1.1.1 (no DNS)

1 tool call · 2 connections · 1 alert    (--timeline for the full log)
```

Both connections happened during the `fetch` call, so timing alone would call
both "caused by fetch". The destination check separates them: `93.184.216.34` is
exactly the host the call declared (✓ expected); the hardcoded `1.1.1.1` is not
`example.com` and had no lookup — a **destination mismatch** alert.

## Caveats (read these)

Correlation is **observe-only inference**, not proof. Known limitations:

- **DNS cache → soft false positives.** A host already cached (app or OS resolver)
  produces no DNS packet, so a connection to it reads as a raw IP (Medium, often
  low-confidence). The live demo (`scripts/demo-correlate.sh`) flushes the cache
  first. We err toward flag-don't-miss, but rank an unnamed IP below a named
  mismatch precisely because it could be a cached legitimate lookup.
- **Encrypted DNS (DoH/DoT)** hides the query/answer, so resolutions aren't
  observed — though a tool that declared a plain `http(s)://` URL while doing
  encrypted DNS is itself suspicious.
- **Conservative declaration.** A destination is "declared" only from explicit
  URLs in arguments — never loose string matches — so we never *suppress* an alarm
  by over-declaring. The cost is that hosts passed in non-URL forms aren't
  credited as declared.
- **Attribution is by PID + time, not proof of causation.** Concurrent/pipelined
  calls attribute to the named or most-recently-started window; that uncertainty
  is reflected in confidence.
- **Short-lived processes** may be missed by the subtree poll; a connection from a
  process pounce never saw is unattributed.
- **macOS PID source.** The per-packet PID comes from the system tcpdump's text
  pktap metadata — the binary paths don't expose it on macOS 26 (see `CLAUDE.md`).
  Parsing is anchored and drift-guarded, but it's text.

## What's next

The trigger engine reads the generic OS event, so **eslogger** file/exec events
(Phase 4) drop in through it — e.g. a `read_file` that also opened a socket, or a
tool that spawned a process. A rules/actions sink can fire on a finding (notify,
snapshot, investigate) — strictly on the notify/investigate side, never blocking
(see `CLAUDE.md`).
