# Pounce — Network Trigger Logic (Phase 3)

What fires an alert, given network ground truth (pktap → PID) correlated to declared tool calls. This is the substrate for the alerting hero: push a "catch" into a notification / chat channel.

> **Observe-first invariant:** every rule here gates a *notification*, never traffic. Nothing is blocked or allowed — the connections have already happened; triggers only decide what's worth surfacing. The "seen" set below is a **mute/acknowledge** list, not an **allow** list.

---

## Core model

A trigger evaluates one event: **a new outbound connection attributed to a tool call.**

- Anchor on **connection establishment** (first packet to a new 5-tuple), not per-packet. Reused / keep-alive connections are not new events.
- The unit of evaluation is the intent↔effect pair: `(tool call X on server S, tool T, args A, time t) → (connection C: dest IP:port, name?, t')`.
- Output is a **finding** with a *type*, *severity*, and *confidence* — routed to push / soft / silent.

---

## Substrate (inputs)

- **Intent** (from the stdio tee): tool name `T`, server `S`, arguments `A`, timestamp, call id.
- **Effect** (from pktap `-k NP`): destination IP + port, direction, PID, timestamp.
- **Enabler — DNS association.** You see IPs; args declare names. Resolve by watching the *process's own* DNS lookups in the same capture (UDP/TCP 53): it looked up `api.weather.com → 1.2.3.4`, then connected to `1.2.3.4` → name that connection. Required for the destination-mismatch trigger.
  - **Caveat:** DoH/DoT or a warm system cache means no visible query → mark the connection **name-unknown** and fall back to IP-level rules. A connection to a raw IP with *no* preceding lookup is itself a weak signal (see Trigger 3).
- **Scope filter.** Classify each destination as **public** vs **private/loopback** (`127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, link-local). Private/loopback → Info (not exfil); egress rules target public destinations.

---

## Central data structure: per-(server, tool) network profile

One learned structure feeds Triggers 1, 2, and 4:

- **Does this `(S, T)` egress?** (has it ever opened a connection) — feeds capability mismatch.
- **To which registrable domains (eTLD+1)?** — feeds destination mismatch + novelty.
- **Acknowledged set** — domains the user has marked "seen" (mutes repeats). A *mute/acknowledge* set, NOT an allow-list: it suppresses notifications, it does not permit traffic.

Build this well and the triggers are thin conditions on top.

---

## Triggers (highest signal first)

### 1. Capability mismatch — *a local-only tool made a connection*. Severity: **High**
A tool whose nature implies no egress (`read_file`, `list_directory`, `get_time`) opened any connection.
- **Day-1:** a small **built-in prior** — fs/util tool-name patterns default to no-egress.
- **Learned:** a per-`(S,T)` baseline that has *never* egressed across prior calls now egressing = anomaly (covers custom/unknown tools the prior misses).
- No arg parsing needed. This is the headline alert, and it fires from day one.

### 2. Destination mismatch — *declared host ≠ actual host*. Severity: **High**
Args name a destination (e.g. `fetch({url})`) but the (DNS-named) connection goes elsewhere.
- Compare at **registrable-domain (eTLD+1)** level, not exact host.
- Treat the declared host's **own resolved IP set** as legitimate (handles CDNs / redirects — otherwise these fire constantly).
- Requires DNS association + per-tool arg extraction (which arg holds the destination).

### 3. Destination properties — *egregious regardless of novelty*. Severity: **High** (or Medium)
Stand-alone red flags on the destination itself:
- **Cloud metadata endpoint** (`169.254.169.254`) — SSRF-class; an agent hitting this is almost always wrong. High.
- **Known-bad / threat-intel host** (optional feed).
- **Raw IP with no preceding DNS** — possible hardcoded C2. Medium.

### 4. Novel destination — *new domain for this `(S, T)`, not acknowledged*. Severity: **Medium**
The workhorse that catches what 1–3 miss (a network-legit tool reaching somewhere new). First connection to an unseen registrable domain for that `(S,T)`. Suppressed once acknowledged. Softened during the initial learning window (see Fatigue).

### 5. Everything else — known host, expected egress, private/loopback. Severity: **Info**
Silent record in the timeline. Never a push.

---

## Severity → action

"Alert on divergence/novelty, never on raw activity," made concrete:

- **High** → push immediately (notification / chat channel).
- **Medium** → push per user sensitivity; **softened during the initial learning window** so day-1 doesn't flood while the baseline fills.
- **Info** → timeline only, silent.

---

## Fatigue control (the hero lives or dies here)

- Acknowledged-destination set mutes repeats.
- **Dedupe:** one finding per `(tool call, new destination)` — not per packet.
- **Cold-start:** capability mismatch (#1) fires from day one (needs no baseline); novelty (#4) is soft during the learning window — so you catch the egregious thing immediately without a first-run flood.

---

## Confidence (attribution isn't perfect)

Which tool call caused which connection can be ambiguous (concurrent / pipelined calls, keep-alive reuse).

- Attribute a *new* connection to the call active at **SYN time**; reused connections are not new findings.
- `confidence = attribution_certainty × naming_certainty`.
- **Low-confidence findings land in the timeline, not a push.** Same discipline as "fail safe to attribution unavailable" — don't cry wolf on a shaky join.

---

## MVP cut

Ship **#1 (capability mismatch) + #2 (destination mismatch) + #4 (novelty)** on the per-`(S,T)` profile, with High→push / Medium→soft / Info→silent. That's the full hero. Trigger #3's richer heuristics and any volume / exfil-shape detection are later.

---

## Open design choices

- **Baseline scope:** per-server vs per-`(server, tool)` — tighter signal vs more cold-start.
- **Learning-window policy:** how long; alert-but-mark-provisional vs stay silent on novelty during it.

---

## Invariant (restated, because it's the positioning)

Triggers gate **notifications, not traffic**. The acknowledged/seen set is a *mute* list, not an *allow* list. Pounce observes; it does not permit or block. If enforcement is ever added, that's a separate, opt-in product — and the same per-`(S,T)` profile would become an allow-list there. Not here.
