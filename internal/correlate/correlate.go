// Package correlate joins declared intent (tool calls) to observed OS effects
// (network connections) and flags divergence — pounce's north star, where the
// discrepancy is the signal. Two independent checks:
//
//   - Timing: a connection during a call's execution window is attributed to it;
//     one in no window is "out-of-band" (the server reached out while idle).
//   - Destination: a connection's IP is cross-checked against the DNS the server
//     actually resolved. An IP that no DNS lookup produced is an "undeclared
//     destination" (a hardcoded/exfil IP), even if it lands inside a call's
//     window — so a rogue server connecting to a malicious IP under cover of a
//     benign tool call is still caught.
//
// The join is written against the generic OS event, so eslogger file/exec events
// (Phase 4) slot in through the same path.
package correlate

import (
	"regexp"
	"strings"
	"time"

	"pounce/internal/capture"
	"pounce/internal/intent"
	"pounce/internal/protocol"
	"pounce/internal/store"
)

// DefaultWindow is the grace added after a request's response (and the fallback
// span when no response was captured) when deciding whether a connection
// belongs to a call's execution.
const DefaultWindow = 3 * time.Second

// urlHostRe extracts hosts from URL-looking values in tool-call arguments. We
// deliberately only trust explicit URLs (not bare strings) so we never mark a
// destination "declared" — and thereby suppress an alarm — on a loose match.
var urlHostRe = regexp.MustCompile(`https?://([A-Za-z0-9.\-]+)`)

// Conn is one observed connection plus its destination analysis.
type Conn struct {
	Event    capture.Event
	Host     string // host the destination IP was resolved from ("" if none)
	Resolved bool   // the IP appeared in a DNS answer in this session
	Declared bool   // Host was named in a tool call's arguments
}

// Remote returns the connection's remote endpoint.
func (c Conn) Remote() string {
	if c.Event.Net != nil {
		return c.Event.Net.Remote
	}
	return ""
}

// Link ties one request to the connections that occurred during its execution.
type Link struct {
	CallTS      time.Time
	Method      string // JSON-RPC method, e.g. "tools/call"
	Tool        string // tool name, for tools/call
	Args        string // raw tool arguments, for tools/call
	Connections []Conn
}

// Result is the correlation of a whole session.
type Result struct {
	Window    time.Duration
	Links     []Link // requests with the connections they caused, in order
	OutOfBand []Conn // connections during no request's execution window
}

// Attributed reports how many connections were tied to a request.
func (r Result) Attributed() int {
	n := 0
	for _, l := range r.Links {
		n += len(l.Connections)
	}
	return n
}

// UndeclaredDestinations returns every connection whose IP no DNS lookup
// produced — the hardcoded/exfil-IP signal, regardless of timing.
func (r Result) UndeclaredDestinations() []Conn {
	var out []Conn
	for _, l := range r.Links {
		for _, c := range l.Connections {
			if !c.Resolved {
				out = append(out, c)
			}
		}
	}
	for _, c := range r.OutOfBand {
		if !c.Resolved {
			out = append(out, c)
		}
	}
	return out
}

type window struct {
	idx        int
	start, end time.Time
}

// Correlate joins the session's requests to its OS events and analyzes each
// connection's destination against the DNS the server resolved.
func Correlate(s *store.Session, w time.Duration) Result {
	if w <= 0 {
		w = DefaultWindow
	}
	res := Result{Window: w}

	// Destination intelligence: which IPs did the server actually resolve, and
	// from which host; which hosts were declared in tool-call arguments.
	ip2host := map[string]string{}
	for _, e := range s.OSEvents {
		if e.Op == capture.OpResolve && e.Resolve != nil {
			for _, ip := range e.Resolve.IPs {
				ip2host[ip] = e.Resolve.Host
			}
		}
	}
	declared := map[string]bool{}

	// Build execution windows from client->server requests, gathering declared
	// hosts as we go.
	respTime := map[string]time.Time{}
	for _, e := range s.Events {
		if e.Msg == nil || e.Dir != intent.ServerToClient {
			continue
		}
		if e.Msg.Kind() == protocol.KindResponse {
			if k := e.Msg.IDKey(); k != "" {
				respTime[k] = e.TS
			}
		}
	}

	var wins []window
	for _, e := range s.Events {
		if e.Msg == nil || e.Dir != intent.ClientToServer || e.Msg.Kind() != protocol.KindRequest {
			continue
		}
		start := e.TS
		end := start.Add(w)
		if rt, ok := respTime[e.Msg.IDKey()]; ok {
			end = rt.Add(w)
		}
		link := Link{CallTS: start, Method: e.Msg.Method}
		if tc, ok := e.Msg.AsToolCall(); ok {
			link.Tool = tc.Name
			link.Args = string(tc.Arguments)
			for _, h := range hostsIn(link.Args) {
				declared[h] = true
			}
		}
		res.Links = append(res.Links, link)
		wins = append(wins, window{idx: len(res.Links) - 1, start: start, end: end})
	}

	for _, oe := range s.OSEvents {
		if oe.Op != capture.OpConnect {
			continue // resolves are evidence, not connections to correlate
		}
		c := classify(oe, ip2host, declared)
		best := -1
		for i := range wins {
			if oe.TS.Before(wins[i].start) || oe.TS.After(wins[i].end) {
				continue
			}
			if best < 0 || wins[i].start.After(wins[best].start) {
				best = i
			}
		}
		if best < 0 {
			res.OutOfBand = append(res.OutOfBand, c)
			continue
		}
		li := wins[best].idx
		res.Links[li].Connections = append(res.Links[li].Connections, c)
	}
	return res
}

// classify analyzes a connection's destination against resolved/declared hosts.
func classify(e capture.Event, ip2host map[string]string, declared map[string]bool) Conn {
	c := Conn{Event: e}
	ip := ipOf(c.Remote())
	if host, ok := ip2host[ip]; ok {
		c.Host = host
		c.Resolved = true
		c.Declared = declared[strings.ToLower(host)]
	}
	return c
}

// hostsIn returns the hosts of URL-looking values in tool-call arguments.
func hostsIn(args string) []string {
	var hs []string
	for _, m := range urlHostRe.FindAllStringSubmatch(args, -1) {
		hs = append(hs, strings.ToLower(m[1]))
	}
	return hs
}

// ipOf returns the host part of a "host:port" endpoint (handles IPv6).
func ipOf(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		return hostport[:i]
	}
	return hostport
}
