package correlate

import (
	"encoding/json"
	"testing"
	"time"

	"pounce/internal/capture"
	"pounce/internal/intent"
	"pounce/internal/protocol"
	"pounce/internal/store"
)

func at(ms int) time.Time {
	return time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC).Add(time.Duration(ms) * time.Millisecond)
}

// req builds a tools/call request event at time t.
func req(id, tool string, t time.Time) intent.Event {
	raw := `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `"}}`
	msgs, _ := protocol.ParseLine([]byte(raw))
	m := msgs[0]
	return intent.Event{TS: t, Dir: intent.ClientToServer, Raw: json.RawMessage(raw), Msg: &m}
}

// resp builds the matching response event at time t.
func resp(id string, t time.Time) intent.Event {
	raw := `{"jsonrpc":"2.0","id":` + id + `,"result":{}}`
	msgs, _ := protocol.ParseLine([]byte(raw))
	m := msgs[0]
	return intent.Event{TS: t, Dir: intent.ServerToClient, Raw: json.RawMessage(raw), Msg: &m}
}

func conn(remote string, t time.Time) capture.Event {
	return capture.Event{TS: t, Op: capture.OpConnect, PID: 42, Proc: "srv",
		Net: &capture.NetFlow{Proto: "tcp", Remote: remote, Dir: "out"}}
}

func TestCorrelate_AttributesConnectionToActiveCall(t *testing.T) {
	s := &store.Session{
		Events: []intent.Event{
			req("1", "fetch", at(0)),
			resp("1", at(500)),
		},
		// connection happens during execution [0, 500]
		OSEvents: []capture.Event{conn("93.184.216.34:443", at(200))},
	}
	r := Correlate(s, DefaultWindow)

	if len(r.Links) != 1 || len(r.Links[0].Connections) != 1 {
		t.Fatalf("expected 1 attributed connection, got links=%+v", r.Links)
	}
	if r.Links[0].Tool != "fetch" {
		t.Errorf("tool = %q, want fetch", r.Links[0].Tool)
	}
	if len(r.OutOfBand) != 0 {
		t.Errorf("expected no out-of-band, got %d", len(r.OutOfBand))
	}
}

func TestCorrelate_FlagsOutOfBandConnection(t *testing.T) {
	s := &store.Session{
		Events: []intent.Event{
			req("1", "read_file", at(0)),
			resp("1", at(100)),
		},
		// connection long after the call finished (+grace) -> out-of-band
		OSEvents: []capture.Event{conn("evil.example:443", at(60_000))},
	}
	r := Correlate(s, DefaultWindow)

	if r.Attributed() != 0 {
		t.Errorf("expected 0 attributed, got %d", r.Attributed())
	}
	if len(r.OutOfBand) != 1 || r.OutOfBand[0].Remote() != "evil.example:443" {
		t.Fatalf("expected the connection flagged out-of-band, got %+v", r.OutOfBand)
	}
}

// resolve builds a DNS-resolution OS event (host -> ips).
func resolveEvent(host string, t time.Time, ips ...string) capture.Event {
	return capture.Event{TS: t, Op: capture.OpResolve, PID: 42, Proc: "node",
		Resolve: &capture.Resolve{Host: host, IPs: ips}}
}

// TestCorrelate_DestinationDivergence is the teeth: a connection to an IP no DNS
// produced is flagged even when it lands inside a call's window.
func TestCorrelate_DestinationDivergence(t *testing.T) {
	s := &store.Session{
		Events: []intent.Event{
			fetchReq("1", "https://example.com/data", at(0)),
			resp("1", at(800)),
		},
		OSEvents: []capture.Event{
			resolveEvent("example.com", at(50), "93.184.216.34"),
			conn("93.184.216.34:443", at(100)), // declared host's resolved IP
			conn("45.83.12.9:443", at(300)),    // hardcoded IP, no DNS — exfil
		},
	}
	r := Correlate(s, DefaultWindow)

	und := r.UndeclaredDestinations()
	if len(und) != 1 || und[0].Remote() != "45.83.12.9:443" {
		t.Fatalf("expected the hardcoded IP flagged undeclared, got %+v", und)
	}

	// Find the example.com connection: resolved AND declared.
	var found bool
	for _, l := range r.Links {
		for _, c := range l.Connections {
			if c.Remote() == "93.184.216.34:443" {
				found = true
				if !c.Resolved || c.Host != "example.com" || !c.Declared {
					t.Errorf("example.com conn analysis wrong: %+v", c)
				}
			}
		}
	}
	if !found {
		t.Error("the declared connection was not attributed")
	}
}

// fetchReq builds a tools/call with a URL argument.
func fetchReq(id, url string, t time.Time) intent.Event {
	raw := `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"` + url + `"}}}`
	msgs, _ := protocol.ParseLine([]byte(raw))
	m := msgs[0]
	return intent.Event{TS: t, Dir: intent.ClientToServer, Raw: json.RawMessage(raw), Msg: &m}
}

func TestCorrelate_OverlappingCallsPickMostRecent(t *testing.T) {
	// Two calls whose windows overlap; a connection in the overlap is attributed
	// to the most recently started call.
	s := &store.Session{
		Events: []intent.Event{
			req("1", "a", at(0)),
			req("2", "b", at(100)),
			resp("1", at(400)),
			resp("2", at(500)),
		},
		OSEvents: []capture.Event{conn("x:443", at(200))}, // inside both [0,..] and [100,..]
	}
	r := Correlate(s, DefaultWindow)

	var bConns int
	for _, l := range r.Links {
		if l.Tool == "b" {
			bConns = len(l.Connections)
		}
	}
	if bConns != 1 {
		t.Errorf("connection should attribute to the most recent call 'b', got %d", bConns)
	}
}

func TestCorrelate_NoResponseUsesFallbackWindow(t *testing.T) {
	s := &store.Session{
		Events: []intent.Event{req("1", "slow", at(0))}, // no response captured
		// within the fallback window [0, 0+window]
		OSEvents: []capture.Event{conn("y:443", at(1000))},
	}
	r := Correlate(s, DefaultWindow)
	if r.Attributed() != 1 {
		t.Errorf("connection within fallback window should attribute, got %d", r.Attributed())
	}
}
