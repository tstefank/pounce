package view

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"pounce/internal/capture"
	"pounce/internal/intent"
	"pounce/internal/store"
)

func at(sec int) time.Time {
	return time.Date(2026, 6, 10, 12, 0, sec, 0, time.UTC)
}

// TestSummaryVerdictAndGrouping checks the default view: a verdict line and each
// tool call's connections labeled ✓ (explained) / ⚠ (undeclared).
func TestSummaryVerdictAndGrouping(t *testing.T) {
	mkReq := func() intent.Event {
		e := ev(intent.ClientToServer, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://api.example.com"}}}`)
		e.TS = at(0)
		return e
	}
	mkResp := func() intent.Event {
		e := ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		e.TS = at(2)
		return e
	}
	s := &store.Session{
		Header: store.Header{ID: "t", Command: "srv"},
		Events: []intent.Event{mkReq(), mkResp()},
		OSEvents: []capture.Event{
			{TS: at(1), Op: capture.OpResolve, PID: 9, Proc: "node", Resolve: &capture.Resolve{Host: "api.example.com", IPs: []string{"1.2.3.4"}}},
			{TS: at(1), Op: capture.OpConnect, PID: 9, Proc: "node", Net: &capture.NetFlow{Proto: "tcp", Remote: "1.2.3.4:443", Dir: "out"}},
			{TS: at(1), Op: capture.OpConnect, PID: 9, Proc: "node", Net: &capture.NetFlow{Proto: "tcp", Remote: "45.83.12.9:443", Dir: "out"}},
		},
	}
	var buf bytes.Buffer
	Summary(&buf, s, false, 0)
	out := buf.String()

	if !strings.Contains(out, "⚠ 1 undeclared connection") {
		t.Errorf("missing verdict:\n%s", out)
	}
	if !strings.Contains(out, "✓ tcp 1.2.3.4:443  api.example.com") {
		t.Errorf("declared connection not shown as explained:\n%s", out)
	}
	if !strings.Contains(out, "⚠ tcp 45.83.12.9:443  undeclared") {
		t.Errorf("undeclared connection not flagged:\n%s", out)
	}
	if !strings.Contains(out, "1 tool call · 2 connections · 1 flagged") {
		t.Errorf("footer wrong:\n%s", out)
	}
}

// TestRoster checks the --all overview: a header count, a verdict marker per
// session, and flagged sessions expand to show their undeclared connections (so
// a "(N undeclared)" count is never shown without its list).
func TestRoster(t *testing.T) {
	flagged := &store.Session{
		Header: store.Header{ID: "s-flagged", Command: "trojan"},
		OSEvents: []capture.Event{
			{Op: capture.OpConnect, PID: 1, Proc: "node", Net: &capture.NetFlow{Proto: "tcp", Remote: "1.1.1.1:443", Dir: "out"}},
		},
	}
	clean := &store.Session{
		Header: store.Header{ID: "s-clean", Command: "honest"},
		// a connection resolved from a host → not flagged
		OSEvents: []capture.Event{
			{Op: capture.OpResolve, PID: 2, Proc: "node", Resolve: &capture.Resolve{Host: "ok.example", IPs: []string{"9.9.9.9"}}},
			{Op: capture.OpConnect, PID: 2, Proc: "node", Net: &capture.NetFlow{Proto: "tcp", Remote: "9.9.9.9:443", Dir: "out"}},
		},
	}

	var buf bytes.Buffer
	Roster(&buf, []*store.Session{flagged, clean}, false, 0)
	out := buf.String()

	if !strings.Contains(out, "⚠ 1 of 2 sessions flagged") {
		t.Errorf("missing header count:\n%s", out)
	}
	// The flagged session must expand its undeclared connection.
	if !strings.Contains(out, "1.1.1.1:443  undeclared") {
		t.Errorf("flagged session did not list its undeclared connection:\n%s", out)
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
			func() intent.Event {
				e := ev(intent.ClientToServer, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch"}}`)
				e.TS = at(1)
				return e
			}(),
			func() intent.Event {
				e := ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":1,"result":{}}`)
				e.TS = at(3)
				return e
			}(),
		},
		OSEvents: []capture.Event{
			{TS: at(2), Op: capture.OpConnect, PID: 4242, Proc: "curl",
				Net: &capture.NetFlow{Proto: "tcp", Remote: "93.184.216.34:443", Dir: "out"}},
		},
	}

	var buf bytes.Buffer
	Timeline(&buf, s, false, 0)
	out := buf.String()

	// The OS connect line must appear, with the remote destination and process.
	if !strings.Contains(out, "net") || !strings.Contains(out, "tcp 93.184.216.34:443") {
		t.Errorf("OS connect not rendered with destination:\n%s", out)
	}
	if !strings.Contains(out, "curl pid 4242") {
		t.Errorf("OS event missing process attribution:\n%s", out)
	}
	if !strings.Contains(out, "1 OS events") {
		t.Errorf("summary missing OS event count:\n%s", out)
	}

	// Ordering: the connect (t=2) must fall between the request (t=1) and the
	// response fold (t=3) — i.e. after "fetch", before the request's line ends?
	// Simpler: the net line index is after the tools/call line index.
	callIdx := strings.Index(out, "tools/call")
	netIdx := strings.Index(out, "· net")
	if callIdx < 0 || netIdx < 0 || netIdx < callIdx {
		t.Errorf("OS event not ordered after the preceding tool call:\n%s", out)
	}
}
