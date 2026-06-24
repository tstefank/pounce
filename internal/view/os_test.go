package view

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"pounce/internal/capture"
	"pounce/internal/intent"
	"pounce/internal/store"
	"pounce/internal/triggers"
)

func at(sec int) time.Time {
	return time.Date(2026, 6, 10, 12, 0, sec, 0, time.UTC)
}

// reqAt / respAt build a tools/call request and its response at fixed times so
// connections can be placed inside the call's execution window.
func reqAt(tool, args string, ts time.Time) intent.Event {
	e := ev(intent.ClientToServer, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`)
	e.TS = ts
	return e
}

func respAt(ts time.Time) intent.Event {
	e := ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	e.TS = ts
	return e
}

func connAt(ts time.Time, remote string) capture.Event {
	return capture.Event{TS: ts, Op: capture.OpConnect, PID: 9, Proc: "node",
		Net: &capture.NetFlow{Proto: "tcp", Remote: remote, Dir: "out"}}
}

func resolveAt(ts time.Time, host string, ips ...string) capture.Event {
	return capture.Event{TS: ts, Op: capture.OpResolve, PID: 9, Proc: "node",
		Resolve: &capture.Resolve{Host: host, IPs: ips}}
}

// TestSummaryAlert checks the headline: a fetch that honestly hits its declared
// host *and* dials an undeclared raw IP fires a High destination-mismatch alert,
// with the legit connection marked ✓ and the divergent one ⚠.
func TestSummaryAlert(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "t", Command: "srv"},
		Events: []intent.Event{
			reqAt("fetch", `{"url":"https://api.example.com"}`, at(0)),
			respAt(at(2)),
		},
		OSEvents: []capture.Event{
			resolveAt(at(1), "api.example.com", "1.2.3.4"),
			connAt(at(1), "1.2.3.4:443"),    // the declared host
			connAt(at(1), "45.83.12.9:443"), // the exfil IP
		},
	}
	var buf bytes.Buffer
	Summary(&buf, s, false, 0, nil)
	out := buf.String()

	if !strings.Contains(out, "⚠ 1 alert — destination mismatch") {
		t.Errorf("missing alert verdict:\n%s", out)
	}
	if !strings.Contains(out, "✓ tcp 1.2.3.4:443  declared api.example.com") {
		t.Errorf("declared connection not shown as expected:\n%s", out)
	}
	if !strings.Contains(out, "⚠ tcp 45.83.12.9:443") || !strings.Contains(out, "connected to 45.83.12.9 (no DNS)") {
		t.Errorf("divergent connection not flagged:\n%s", out)
	}
	if !strings.Contains(out, "1 tool call · 2 connections · 1 alert") {
		t.Errorf("footer wrong:\n%s", out)
	}
}

// TestSummaryCapabilityMismatch: a local-only tool (read_file) that egresses is
// a High capability mismatch from day one, no profile needed.
func TestSummaryCapabilityMismatch(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "t", Command: "srv"},
		Events: []intent.Event{
			reqAt("read_file", `{"path":"/etc/hosts"}`, at(0)),
			respAt(at(2)),
		},
		OSEvents: []capture.Event{connAt(at(1), "8.8.8.8:443")},
	}
	var buf bytes.Buffer
	Summary(&buf, s, false, 0, nil)
	out := buf.String()

	if !strings.Contains(out, "⚠ 1 alert — capability mismatch") {
		t.Errorf("missing capability-mismatch verdict:\n%s", out)
	}
	if !strings.Contains(out, "⚠ tcp 8.8.8.8:443") || !strings.Contains(out, "local-only tool reached the network") {
		t.Errorf("capability mismatch not rendered:\n%s", out)
	}
}

// TestSummaryClean: a connection to the declared host's resolved IP is no
// divergence.
func TestSummaryClean(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "t", Command: "srv"},
		Events: []intent.Event{
			reqAt("fetch", `{"url":"https://ok.example"}`, at(0)),
			respAt(at(2)),
		},
		OSEvents: []capture.Event{
			resolveAt(at(1), "ok.example", "9.9.9.9"),
			connAt(at(1), "9.9.9.9:443"),
		},
	}
	var buf bytes.Buffer
	Summary(&buf, s, false, 0, nil)
	out := buf.String()

	if !strings.Contains(out, "✓ no divergence") {
		t.Errorf("expected clean verdict:\n%s", out)
	}
	if strings.Contains(out, "⚠") {
		t.Errorf("clean session must not show an alert:\n%s", out)
	}
}

// TestSummaryNovelToReview: once a tool is warm (seen in an earlier session), a
// connection to a new registrable domain is a Medium "to review".
func TestSummaryNovelToReview(t *testing.T) {
	p := triggers.NewProfile()
	// Prior session establishes `query` as a warm, egressing tool (good.com).
	prior := &store.Session{
		Header: store.Header{ID: "20260101-000000.000-1", Command: "srv"},
		Events: []intent.Event{reqAt("query", `{}`, at(0)), respAt(at(2))},
		OSEvents: []capture.Event{
			resolveAt(at(1), "api.good.com", "3.3.3.3"),
			connAt(at(1), "3.3.3.3:443"),
		},
	}
	p.Learn(prior.Header.ID, triggers.Evaluate(prior, 0, p))

	// Now `query` reaches a never-seen domain → Medium, pushes (warm).
	cur := &store.Session{
		Header: store.Header{ID: "20260202-000000.000-1", Command: "srv"},
		Events: []intent.Event{reqAt("query", `{}`, at(0)), respAt(at(2))},
		OSEvents: []capture.Event{
			resolveAt(at(1), "telemetry.vendor.net", "2.2.2.2"),
			connAt(at(1), "2.2.2.2:443"),
		},
	}
	var buf bytes.Buffer
	Summary(&buf, cur, false, 0, p)
	out := buf.String()

	if !strings.Contains(out, "? 1 to review — novel destination") {
		t.Errorf("missing review verdict:\n%s", out)
	}
	if !strings.Contains(out, "? tcp 2.2.2.2:443") || !strings.Contains(out, "first connection to vendor.net for this tool") {
		t.Errorf("novel destination not rendered:\n%s", out)
	}
	if !strings.Contains(out, "1 to review") {
		t.Errorf("footer missing review count:\n%s", out)
	}
}

// TestRoster checks the --all overview: a header count, a verdict marker per
// session, and flagged sessions expand to show their findings (so a count is
// never shown without its list).
func TestRoster(t *testing.T) {
	flagged := &store.Session{
		Header: store.Header{ID: "s-flagged", Command: "trojan"},
		Events: []intent.Event{reqAt("read_file", `{"path":"/x"}`, at(0)), respAt(at(2))},
		// a local-only tool egressing → High capability mismatch
		OSEvents: []capture.Event{connAt(at(1), "8.8.8.8:443")},
	}
	clean := &store.Session{
		Header: store.Header{ID: "s-clean", Command: "honest"},
		Events: []intent.Event{reqAt("fetch", `{"url":"https://ok.example"}`, at(0)), respAt(at(2))},
		OSEvents: []capture.Event{
			resolveAt(at(1), "ok.example", "9.9.9.9"),
			connAt(at(1), "9.9.9.9:443"),
		},
	}

	var buf bytes.Buffer
	Roster(&buf, []*store.Session{flagged, clean}, false, 0, nil)
	out := buf.String()

	if !strings.Contains(out, "1 of 2 sessions with findings to review") {
		t.Errorf("missing header count:\n%s", out)
	}
	// The flagged session must expand its finding (never a bare count).
	if !strings.Contains(out, "8.8.8.8:443") || !strings.Contains(out, "local-only tool reached the network") {
		t.Errorf("flagged session did not list its finding:\n%s", out)
	}
	if !strings.Contains(out, "s-clean") {
		t.Errorf("clean session missing:\n%s", out)
	}
}

// TestTimelineInterleavesOSEvents checks that OS events are merged into the
// protocol timeline in timestamp order and rendered with their destination.
func TestTimelineInterleavesOSEvents(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "test", Command: "srv"},
		Events: []intent.Event{
			reqAt("fetch", `{}`, at(1)),
			respAt(at(3)),
		},
		OSEvents: []capture.Event{
			connAt(at(2), "93.184.216.34:443"),
		},
	}
	// The lone connection has its own pid/proc for the attribution assertion.
	s.OSEvents[0].PID = 4242
	s.OSEvents[0].Proc = "curl"

	var buf bytes.Buffer
	Timeline(&buf, s, false, 0, nil)
	out := buf.String()

	if !strings.Contains(out, "net") || !strings.Contains(out, "tcp 93.184.216.34:443") {
		t.Errorf("OS connect not rendered with destination:\n%s", out)
	}
	if !strings.Contains(out, "curl pid 4242") {
		t.Errorf("OS event missing process attribution:\n%s", out)
	}
	if !strings.Contains(out, "1 OS events") {
		t.Errorf("summary missing OS event count:\n%s", out)
	}

	callIdx := strings.Index(out, "tools/call")
	netIdx := strings.Index(out, "· net")
	if callIdx < 0 || netIdx < 0 || netIdx < callIdx {
		t.Errorf("OS event not ordered after the preceding tool call:\n%s", out)
	}
}
