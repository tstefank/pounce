// Package triggers evaluates correlated connections against the network alert
// rules in TRIGGERS.md, turning each observed connection into a finding with a
// type, severity, and confidence.
//
// Observe-first invariant: a finding gates a *notification*, never traffic. The
// connections have already happened; triggers only decide what is worth
// surfacing. The learned profile's "seen" set (see profile.go) is a
// mute/acknowledge list, not an allow-list.
//
// Rules, highest signal first (see TRIGGERS.md for the rationale):
//
//	#1 capability mismatch  — a local-only tool egressed at all        (High)
//	#2 destination mismatch — declared host ≠ the actual destination   (High)
//	#3 destination property — cloud-metadata IP (High) / raw IP no DNS (Medium)
//	#4 novel destination    — new registrable domain for this (S,T)    (Medium)
//	#5 everything else       — known/declared/private                  (Info)
package triggers

import (
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"pounce/internal/capture"
	"pounce/internal/correlate"
	"pounce/internal/store"
)

// Severity orders findings by how loudly they should surface: High → push,
// Medium → review (softened during a tool's learning window), Info → silent.
type Severity int

const (
	Info Severity = iota
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "high"
	case Medium:
		return "medium"
	default:
		return "info"
	}
}

// Type names the rule that fired.
type Type string

const (
	CapabilityMismatch  Type = "capability mismatch"
	DestinationMismatch Type = "destination mismatch"
	MetadataEndpoint    Type = "cloud metadata endpoint"
	RawIPNoDNS          Type = "raw IP, no DNS"
	NovelDestination    Type = "novel destination"
	Expected            Type = "expected"
)

// metadataIP is the IMDS endpoint shared by the major clouds. An agent reaching
// it is almost always an SSRF, so it is a stand-alone High regardless of novelty.
const metadataIP = "169.254.169.254"

// Finding is one evaluated connection — or, after dedupe, one
// (tool call, destination): Count is how many connections it represents.
type Finding struct {
	Conn        correlate.Conn
	Count       int // connections collapsed into this finding (≥1)
	Type        Type
	Severity    Severity
	Confidence  float64 // attribution_certainty × naming_certainty, 0..1
	Tool        string  // owning tool ("" if out-of-band)
	Server      string  // server identity (for the per-(S,T) profile)
	Domain      string  // registrable domain (eTLD+1) of the destination, if named
	Detail      string  // human-readable reason
	Provisional bool    // severity softened: the (S,T) is in its learning window
}

// Pushes reports whether the finding should escalate (vs. sit silently in the
// timeline). High always pushes; Medium pushes only once warm and confident —
// the fatigue discipline: don't cry wolf on a shaky join or during cold-start.
func (f Finding) Pushes() bool {
	switch f.Severity {
	case High:
		return true
	case Medium:
		return !f.Provisional && f.Confidence >= confidenceFloor
	default:
		return false
	}
}

// confidenceFloor is the cutoff below which a Medium finding stays in the
// timeline rather than pushing — "low-confidence findings don't push."
const confidenceFloor = 0.5

// CallFindings groups a tool call with the findings for the connections it caused.
type CallFindings struct {
	Method   string
	Tool     string
	Args     string
	Findings []Finding
}

// Report is the trigger evaluation of a whole session.
type Report struct {
	Window     time.Duration
	Server     string
	HasCapture bool // OS capture was active (distinguishes "clean" from "no data")
	Calls      []CallFindings
	OutOfBand  []Finding
}

// All returns every finding, attributed and out-of-band.
func (r Report) All() []Finding {
	var out []Finding
	for _, c := range r.Calls {
		out = append(out, c.Findings...)
	}
	return append(out, r.OutOfBand...)
}

// Top returns the highest severity present, or Info if there are no findings.
func (r Report) Top() Severity {
	top := Info
	for _, f := range r.All() {
		if f.Severity > top {
			top = f.Severity
		}
	}
	return top
}

// Counts returns the number of High findings and surfacing (non-soft) Medium
// findings — what the verdict line reports as "alerts" and "to review".
func (r Report) Counts() (high, review int) {
	for _, f := range r.All() {
		switch {
		case f.Severity == High:
			high++
		case f.Severity == Medium && f.Pushes():
			review++
		}
	}
	return high, review
}

// Evaluate correlates the session and classifies every connection against the
// trigger rules. profile may be nil — then the learned rules (#4 novelty and the
// learned half of #1) are skipped and only the day-one rules apply.
func Evaluate(s *store.Session, window time.Duration, profile *Profile) Report {
	r := correlate.Correlate(s, window)
	server := ServerID(s)
	asOf := s.Header.ID // novelty/learning are judged against strictly-earlier sessions
	rep := Report{Window: r.Window, Server: server, HasCapture: len(s.OSEvents) > 0}

	// host → resolved IPs, so destination-mismatch can treat a declared host's
	// own IP set as legitimate (handles CDNs/redirects).
	host2ips := map[string][]string{}
	for _, e := range s.OSEvents {
		if e.Op == capture.OpResolve && e.Resolve != nil {
			h := strings.ToLower(e.Resolve.Host)
			host2ips[h] = append(host2ips[h], e.Resolve.IPs...)
		}
	}

	for _, l := range r.Links {
		// Keep every tool call (even with no connections) so the profile learns
		// that a tool was *seen* — the learned capability rule needs "observed
		// before, never egressed". Drop only non-tool boilerplate that caused
		// nothing (initialize/tools/list).
		if l.Tool == "" && len(l.Connections) == 0 {
			continue
		}
		cf := CallFindings{Method: l.Method, Tool: l.Tool, Args: l.Args}
		// Dedupe to one finding per (tool call, destination) — TRIGGERS.md's
		// fatigue rule: not one per connection. Repeats to the same destination
		// within a call collapse, incrementing Count.
		seen := map[string]int{}
		for _, c := range l.Connections {
			f := evalConn(c, l, server, asOf, host2ips, profile, true)
			if i, ok := seen[destKey(f)]; ok {
				cf.Findings[i].Count++
				continue
			}
			seen[destKey(f)] = len(cf.Findings)
			cf.Findings = append(cf.Findings, f)
		}
		rep.Calls = append(rep.Calls, cf)
	}
	oob := map[string]int{}
	for _, c := range r.OutOfBand {
		// No owning call: #1/#2/#4 can't apply, only destination properties (#3).
		f := evalConn(c, correlate.Link{}, server, asOf, host2ips, profile, false)
		if i, ok := oob[destKey(f)]; ok {
			rep.OutOfBand[i].Count++
			continue
		}
		oob[destKey(f)] = len(rep.OutOfBand)
		rep.OutOfBand = append(rep.OutOfBand, f)
	}
	return rep
}

// destKey identifies a finding's destination for dedupe: the registrable domain
// when named (so several IPs of one domain collapse), else the raw IP.
func destKey(f Finding) string {
	if f.Domain != "" {
		return "d:" + f.Domain
	}
	return "i:" + ipOf(f.Conn.Remote())
}

// evalConn applies the rules to one connection in priority order. asOf is the
// id of the session being evaluated, so the learned rules compare against
// strictly-earlier sessions.
func evalConn(c correlate.Conn, l correlate.Link, server, asOf string, host2ips map[string][]string, profile *Profile, attributed bool) Finding {
	ip := ipOf(c.Remote())
	f := Finding{
		Conn:       c,
		Count:      1,
		Type:       Expected,
		Severity:   Info,
		Confidence: confidence(c, attributed),
		Tool:       l.Tool,
		Server:     server,
	}
	if c.Resolved {
		f.Domain = registrable(c.Host)
	}

	// #3a. Cloud metadata endpoint — checked before the scope filter because the
	// IMDS address is itself link-local. SSRF-class; almost always wrong. High.
	if ip == metadataIP {
		f.Type, f.Severity = MetadataEndpoint, High
		f.Detail = "cloud metadata endpoint (" + ip + ") — SSRF-class"
		return f
	}
	// Scope filter: private/loopback/link-local is not egress → Info.
	if isPrivate(ip) {
		f.Detail = "private/loopback"
		return f
	}

	// #1 (built-in prior). A tool whose name implies local-only work egressing at
	// all is the headline capability mismatch, and it fires from day one. (No-op
	// for "" tools, i.e. out-of-band connections.)
	if localOnly(l.Tool) {
		f.Type, f.Severity = CapabilityMismatch, High
		f.Detail = "local-only tool reached the network"
		return f
	}

	// #2. The call named a destination. The connection either went there
	// (expected — never "novel", it was declared), positively went elsewhere
	// (mismatch, High), or can't be confirmed (name-unknown with no IP evidence,
	// e.g. DoH / warm cache) — in which case it falls through to the IP-level
	// rules rather than asserting a mismatch on zero evidence.
	if len(l.DeclaredHosts) > 0 {
		switch declaredVerdict(c, ip, l.DeclaredHosts, host2ips) {
		case destDiverged:
			f.Type, f.Severity = DestinationMismatch, High
			declared := strings.Join(l.DeclaredHosts, ", ")
			if f.Domain != "" {
				f.Detail = "declared " + declared + " — connected to " + f.Domain
			} else {
				f.Detail = "declared " + declared + " — connected to " + ip + " (no DNS)"
			}
			return f
		case destMatch:
			if c.Host != "" {
				f.Detail = "declared " + c.Host
			} else {
				f.Detail = "declared " + strings.Join(l.DeclaredHosts, ", ")
			}
			return f
		}
		// destUnconfirmed: fall through to #3b.
	}

	// #1 (learned). A tool that declared no destination, was observed in an
	// earlier session, and has never egressed — now connecting out. Skipped for
	// declaring tools: those are network tools by nature, and a declared match
	// already returned above.
	if len(l.DeclaredHosts) == 0 && profile.NeverEgressed(server, l.Tool, asOf) {
		f.Type, f.Severity = CapabilityMismatch, High
		f.Detail = "tool has never egressed before — now connecting out"
		return f
	}

	// #4. Novel destination — for a call that declared no host (the workhorse
	// where declared-vs-actual can't be compared): first connection to an unseen
	// registrable domain for this (S,T). Medium, softened while cold.
	if profile != nil && len(l.DeclaredHosts) == 0 && c.Resolved && l.Tool != "" && f.Domain != "" && !profile.Known(server, l.Tool, f.Domain, asOf) {
		f.Type, f.Severity = NovelDestination, Medium
		f.Provisional = profile.Cold(server, l.Tool, asOf)
		f.Detail = "first connection to " + f.Domain + " for this tool"
		return f
	}

	// #3b. Raw IP with no preceding DNS — possible hardcoded C2. Medium.
	if !c.Resolved {
		f.Type, f.Severity = RawIPNoDNS, Medium
		f.Detail = "raw IP with no DNS lookup"
		return f
	}

	// #5. Everything else — a known/resolved host, expected egress. Info.
	f.Detail = c.Host
	return f
}

// declaredVerdict classifies a connection against the hosts the call declared.
type declaredVerdictResult int

const (
	destUnconfirmed declaredVerdictResult = iota // name-unknown and no declared-IP evidence
	destMatch                                    // consistent with a declared host
	destDiverged                                 // positively went somewhere else
)

func declaredVerdict(c correlate.Conn, ip string, declared []string, host2ips map[string][]string) declaredVerdictResult {
	if c.ByDeclaredHost {
		return destMatch
	}
	declaredIPs := map[string]bool{}
	declaredDomains := map[string]bool{}
	for _, h := range declared {
		h = strings.ToLower(h)
		if d := registrable(h); d != "" {
			declaredDomains[d] = true
		}
		for _, dip := range host2ips[h] {
			declaredIPs[dip] = true
		}
	}
	if declaredIPs[ip] {
		return destMatch // an IP of a declared host (handles CDNs / cached lookups)
	}
	if c.Resolved {
		if d := registrable(c.Host); d != "" {
			if declaredDomains[d] {
				return destMatch // same registrable domain (CDN subdomain etc.)
			}
			return destDiverged // named, and not a declared domain
		}
	}
	// Name-unknown: a divergence only if we know the declared host's IPs and this
	// isn't one of them; otherwise we can't tell (DoH / warm cache) — unconfirmed.
	if len(declaredIPs) > 0 {
		return destDiverged
	}
	return destUnconfirmed
}

// confidence = attribution_certainty × naming_certainty, per TRIGGERS.md.
func confidence(c correlate.Conn, attributed bool) float64 {
	attr := 0.8 // attributed to a single active call by timing
	switch {
	case !attributed:
		attr = 0.3 // out-of-band: no call to pin it to
	case c.ByDeclaredHost:
		attr = 1.0 // the call named this destination
	case c.Ambiguous:
		attr = 0.5 // several calls open; timing-only
	}
	naming := 1.0
	if !c.Resolved {
		naming = 0.6 // a raw IP we couldn't name
	}
	return attr * naming
}

// localToolRe matches tool names anchored by a filesystem/local noun (file,
// directory, path) or a clear local utility (time, env, cwd). Tokens are
// segment-bounded so "postal" is not read as "post". The prior is deliberately
// narrow — it would rather miss a local tool (the learned baseline catches it)
// than flag a network tool. A file-ish name with no network signal but a remote
// nature (e.g. GitHub's get_file_contents) is a known blind spot.
var localToolRe = regexp.MustCompile(`(?i)(^|[_-])(file|files|directory|directories|dir|dirs|folder|folders|path|paths|filesystem|fs|time|date|clock|timezone|env|environment|cwd|pwd|getcwd|hostname|whoami|uptime|disk|memory|uname|sysinfo)([_-]|s?$)`)

// networkToolRe matches names that imply egress is expected, so the prior stays
// silent on them. Tokens are segment-bounded (so "api" matches "api"/"get_api"
// but not "apidoc") and include common API-resource nouns, not just transports.
var networkToolRe = regexp.MustCompile(`(?i)(^|[_-])(http|https|url|uri|fetch|web|download|upload|request|api|curl|wget|socket|browse|crawl|scrape|email|mail|smtp|imap|slack|discord|webhook|remote|sync|publish|send|post|graphql|rpc|grpc|repo|repos|repository|repositories|issue|issues|pull|commit|commits|branch|branches|gist|gists|map|maps|place|places|geocode|weather|forecast|channel|channels|message|messages|notify)([_-]|s?$)`)

// localOnly applies the built-in capability prior: a tool whose name implies
// local-only work and carries no network signal. Conservative on purpose.
func localOnly(tool string) bool {
	if tool == "" || networkToolRe.MatchString(tool) {
		return false
	}
	return localToolRe.MatchString(tool)
}

// registrable returns the registrable domain (eTLD+1) of host, or "" for an IP
// or unparseable host. eTLD+1 (not exact host) is the comparison unit so a CDN
// subdomain of a declared host is not flagged as a mismatch.
func registrable(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// isPrivate reports whether ip is private, loopback, link-local, or unspecified
// — destinations the egress rules treat as Info rather than exfil.
func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false // unparseable → treat as public so we never hide it
	}
	return p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() ||
		p.IsLinkLocalMulticast() || p.IsUnspecified()
}

// ServerID returns a stable identity for the wrapped server: its self-reported
// name from initialize, falling back to the launched command. It keys the
// per-(server, tool) profile across sessions.
func ServerID(s *store.Session) string {
	for _, e := range s.Events {
		if e.Msg == nil {
			continue
		}
		if init, ok := e.Msg.AsInitializeResult(); ok && init.ServerInfo.Name != "" {
			return init.ServerInfo.Name
		}
	}
	if s.Header.Command != "" {
		return s.Header.Command
	}
	return "unknown"
}

// ipOf returns the host part of a "host:port" endpoint (handles IPv6).
func ipOf(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		return hostport[:i]
	}
	return hostport
}
