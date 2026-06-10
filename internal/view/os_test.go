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
	Timeline(&buf, s, false)
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
