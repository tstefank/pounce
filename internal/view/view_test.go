package view

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tstefank/pounce/internal/intent"
	"github.com/tstefank/pounce/internal/protocol"
	"github.com/tstefank/pounce/internal/store"
)

// ev builds an Event from a raw JSON-RPC frame, parsing it the way the store
// does on read.
func ev(dir intent.Direction, raw string) intent.Event {
	msgs, err := protocol.ParseLine([]byte(raw))
	if err != nil || len(msgs) == 0 {
		panic("bad test frame: " + raw)
	}
	m := msgs[0]
	return intent.Event{
		TS:     time.Date(2026, 6, 7, 22, 0, 0, 0, time.UTC),
		Source: "stdio",
		Dir:    dir,
		Raw:    json.RawMessage(raw),
		Msg:    &m,
	}
}

// TestTimelineDirectionAwareMatching reproduces the real capture where the
// client's `initialize` and the server's `roots/list` both use id 0. The
// matcher must pair each request with the response from the opposite direction,
// not collide on the shared id.
func TestTimelineDirectionAwareMatching(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "test", Command: "srv"},
		Events: []intent.Event{
			ev(intent.ClientToServer, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`),
			ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"srv","version":"1.2"}}}`),
			ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":0,"method":"roots/list"}`),
			ev(intent.ClientToServer, `{"jsonrpc":"2.0","id":0,"result":{"roots":[{"uri":"file:///work"}]}}`),
		},
	}

	var buf bytes.Buffer
	Timeline(&buf, s, false)
	out := buf.String()

	// initialize must show the server info from the server's response, not the
	// roots result.
	if !strings.Contains(out, "initialize  -> ok (srv 1.2, protocol 2025-11-25)") {
		t.Errorf("initialize line wrong or cross-matched:\n%s", out)
	}
	// roots/list must show the roots from the client's response.
	if !strings.Contains(out, "roots/list  -> 1 roots [file:///work]") {
		t.Errorf("roots/list line missing roots:\n%s", out)
	}
	// Neither request should report "(no response)".
	if strings.Contains(out, "(no response)") {
		t.Errorf("a request failed to match its response:\n%s", out)
	}
}

func TestTimelineToolCallAndError(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "test", Command: "srv"},
		Events: []intent.Event{
			ev(intent.ClientToServer, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`),
			ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Access denied"}}`),
		},
	}
	var buf bytes.Buffer
	Timeline(&buf, s, false)
	out := buf.String()

	if !strings.Contains(out, "tools/call read_file") || !strings.Contains(out, `"path":"/etc/hosts"`) {
		t.Errorf("tool call not rendered with args:\n%s", out)
	}
	if !strings.Contains(out, "-> ERROR [-32000] Access denied") {
		t.Errorf("error outcome not rendered:\n%s", out)
	}
	if !strings.Contains(out, "1 requests (1 tool calls, 1 errors)") {
		t.Errorf("summary wrong:\n%s", out)
	}
}

// TestTimelineOrphanResponse: a response whose request wasn't captured must
// still be shown rather than silently dropped.
// TestTimelineColor checks that ANSI codes are emitted only when color is on.
func TestTimelineColor(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "test", Command: "srv"},
		Events: []intent.Event{
			ev(intent.ClientToServer, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`),
			ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":1,"result":{}}`),
		},
	}

	var plain, colored bytes.Buffer
	Timeline(&plain, s, false)
	Timeline(&colored, s, true)

	if strings.Contains(plain.String(), "\x1b[") {
		t.Errorf("plain output should contain no ANSI escapes:\n%q", plain.String())
	}
	if !strings.Contains(colored.String(), "\x1b[") {
		t.Errorf("colored output should contain ANSI escapes:\n%q", colored.String())
	}
}

func TestTimelineOrphanResponse(t *testing.T) {
	s := &store.Session{
		Header: store.Header{ID: "test", Command: "srv"},
		Events: []intent.Event{
			ev(intent.ServerToClient, `{"jsonrpc":"2.0","id":99,"result":{"roots":[{"uri":"file:///x"}]}}`),
		},
	}
	var buf bytes.Buffer
	Timeline(&buf, s, false)
	out := buf.String()
	if !strings.Contains(out, "(response id 99)") || !strings.Contains(out, "file:///x") {
		t.Errorf("orphan response not surfaced:\n%s", out)
	}
}
