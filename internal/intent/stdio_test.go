package intent

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tstefank/pounce/internal/protocol"
)

// fixedClock returns a constant time so events are deterministic.
func fixedClock() time.Time { return time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC) }

// collect drains an event channel into a slice until it is closed.
func collect(ch <-chan Event, dst *[]Event, wg *sync.WaitGroup) {
	defer wg.Done()
	for e := range ch {
		*dst = append(*dst, e)
	}
}

func TestStdioForwardsBytesUnchanged(t *testing.T) {
	// `cat` echoes stdin to stdout, so it stands in for an MCP server: every
	// "client->server" frame comes back as a "server->client" frame, and the
	// forwarded output must be byte-identical to the input.
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`,
		"", // trailing newline
	}, "\n")

	var out bytes.Buffer
	src := &StdioSource{
		Command: []string{"cat"},
		In:      strings.NewReader(input),
		Out:     &out,
		Err:     &bytes.Buffer{},
		Now:     fixedClock,
	}

	events := make(chan Event, 64)
	var got []Event
	var wg sync.WaitGroup
	wg.Add(1)
	go collect(events, &got, &wg)

	if err := src.Run(context.Background(), events); err != nil {
		t.Fatalf("Run: %v", err)
	}
	close(events)
	wg.Wait()

	if out.String() != input {
		t.Errorf("forwarded bytes differ from input.\n got: %q\nwant: %q", out.String(), input)
	}
	if d := src.Dropped(); d != 0 {
		t.Errorf("dropped %d events; channel should have been large enough", d)
	}

	// Three messages each direction (cat echoes everything back) = 6 events.
	var c2s, s2c int
	for _, e := range got {
		switch e.Dir {
		case ClientToServer:
			c2s++
		case ServerToClient:
			s2c++
		}
		if e.ParseErr != "" {
			t.Errorf("unexpected parse error: %s", e.ParseErr)
		}
	}
	if c2s != 3 || s2c != 3 {
		t.Errorf("direction counts = c2s:%d s2c:%d, want 3/3", c2s, s2c)
	}

	// Find the tools/call on the client->server side and check it parsed.
	var sawToolCall bool
	for _, e := range got {
		if e.Dir != ClientToServer || e.Msg == nil {
			continue
		}
		if tc, ok := e.Msg.AsToolCall(); ok {
			sawToolCall = true
			if tc.Name != "read_file" {
				t.Errorf("tool name = %q, want read_file", tc.Name)
			}
		}
	}
	if !sawToolCall {
		t.Error("never observed the tools/call message")
	}
}

func TestStdioRecordsUnparseableFrame(t *testing.T) {
	input := "this is not json\n"

	var out bytes.Buffer
	src := &StdioSource{
		Command: []string{"cat"},
		In:      strings.NewReader(input),
		Out:     &out,
		Err:     &bytes.Buffer{},
		Now:     fixedClock,
	}
	events := make(chan Event, 16)
	var got []Event
	var wg sync.WaitGroup
	wg.Add(1)
	go collect(events, &got, &wg)

	if err := src.Run(context.Background(), events); err != nil {
		t.Fatalf("Run: %v", err)
	}
	close(events)
	wg.Wait()

	// Bytes still forwarded unchanged even though they aren't valid JSON-RPC.
	if out.String() != input {
		t.Errorf("forwarded bytes differ: %q vs %q", out.String(), input)
	}
	var sawErr bool
	for _, e := range got {
		if e.ParseErr != "" && e.RawText == "this is not json" {
			sawErr = true
		}
	}
	if !sawErr {
		t.Error("expected an event recording the unparseable frame")
	}
}

// TestStdioBatchFramePerMessageRaw verifies that a legacy JSON-RPC batch array
// is split into one Event per message, each carrying its OWN message JSON in
// Raw — not the whole array. Otherwise store.Read (which reconstructs Msg from
// Raw) would collapse every batch element back to the first.
func TestStdioBatchFramePerMessageRaw(t *testing.T) {
	// A batch with a request and a notification (distinct id/kind).
	input := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","method":"notifications/x"}]` + "\n"

	src := &StdioSource{
		Command: []string{"cat"},
		In:      strings.NewReader(input),
		Out:     &bytes.Buffer{},
		Err:     &bytes.Buffer{},
		Now:     fixedClock,
	}
	events := make(chan Event, 16)
	var got []Event
	var wg sync.WaitGroup
	wg.Add(1)
	go collect(events, &got, &wg)
	if err := src.Run(context.Background(), events); err != nil {
		t.Fatalf("Run: %v", err)
	}
	close(events)
	wg.Wait()

	// Look at one direction's two events (cat echoes, so pick client->server).
	var c2s []Event
	for _, e := range got {
		if e.Dir == ClientToServer {
			c2s = append(c2s, e)
		}
	}
	if len(c2s) != 2 {
		t.Fatalf("batch should split into 2 events, got %d", len(c2s))
	}

	// Each event's Raw must reparse to exactly one message of the right kind —
	// simulating what store.Read does on read-back.
	reparse := func(e Event) protocol.Message {
		msgs, err := protocol.ParseLine(e.Raw)
		if err != nil || len(msgs) != 1 {
			t.Fatalf("Raw should hold exactly one message, got %d (err=%v): %s", len(msgs), err, e.Raw)
		}
		return msgs[0]
	}
	m0, m1 := reparse(c2s[0]), reparse(c2s[1])
	if m0.Kind() != protocol.KindRequest || m0.Method != "tools/call" || m0.IDKey() != "1" {
		t.Errorf("first batch element wrong: kind=%s method=%s id=%s", m0.Kind(), m0.Method, m0.IDKey())
	}
	if m1.Kind() != protocol.KindNotification || m1.Method != "notifications/x" {
		t.Errorf("second batch element wrong: kind=%s method=%s", m1.Kind(), m1.Method)
	}
}

// TestRawForSingleFrameIsExact: a single-message frame stores the exact bytes.
func TestRawForSingleFrameIsExact(t *testing.T) {
	frame := []byte(`{"jsonrpc":"2.0","id":5,"method":"x"}`)
	msgs, err := protocol.ParseLine(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got := rawFor(frame, msgs, 0); string(got) != string(frame) {
		t.Errorf("single frame Raw = %s, want exact %s", got, frame)
	}
}

func TestStdioExitCodePropagates(t *testing.T) {
	// `false` exits non-zero with no I/O; Run must surface that error.
	src := &StdioSource{
		Command: []string{"false"},
		In:      strings.NewReader(""),
		Out:     &bytes.Buffer{},
		Err:     &bytes.Buffer{},
		Now:     fixedClock,
	}
	events := make(chan Event, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	var got []Event
	go collect(events, &got, &wg)

	err := src.Run(context.Background(), events)
	close(events)
	wg.Wait()

	if err == nil {
		t.Fatal("expected non-nil exit error from `false`")
	}
}
