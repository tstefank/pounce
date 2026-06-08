package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"pounce/internal/intent"
)

func TestWriteReadRoundTrip(t *testing.T) {
	// Redirect ~/.pounce to a temp dir for this test.
	t.Setenv("HOME", t.TempDir())

	start := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	h := Header{
		ID:        NewID(start),
		PounceVer: "test",
		StartedAt: start,
		Command:   "npx",
		Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
	}

	w, err := Create(h)
	if err != nil {
		t.Fatal(err)
	}

	events := []intent.Event{
		{
			TS:     start.Add(1 * time.Millisecond),
			Source: "stdio",
			Dir:    intent.ClientToServer,
			Raw:    json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`),
		},
		{
			TS:     start.Add(2 * time.Millisecond),
			Source: "stdio",
			Dir:    intent.ServerToClient,
			Raw:    json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`),
		},
		{
			TS:       start.Add(3 * time.Millisecond),
			Source:   "stdio",
			Dir:      intent.ServerToClient,
			RawText:  "this is not json",
			ParseErr: "not a JSON-RPC frame",
		},
	}
	for _, e := range events {
		if err := w.WriteEvent(e); err != nil {
			t.Fatalf("write event: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	sess, err := Read(w.Path())
	if err != nil {
		t.Fatal(err)
	}
	if sess.Header.ID != h.ID || sess.Header.Command != "npx" {
		t.Errorf("header round-trip wrong: %+v", sess.Header)
	}
	if len(sess.Header.Args) != 3 {
		t.Errorf("header args round-trip wrong: %+v", sess.Header.Args)
	}
	if len(sess.Events) != 3 {
		t.Fatalf("got %d events, want 3", len(sess.Events))
	}

	// First event's Msg should be reconstructed from Raw.
	first := sess.Events[0]
	if first.Msg == nil {
		t.Fatal("expected Msg reconstructed from Raw")
	}
	if first.Msg.Method != "tools/call" {
		t.Errorf("method = %q", first.Msg.Method)
	}
	tc, ok := first.Msg.AsToolCall()
	if !ok || tc.Name != "read_file" {
		t.Errorf("tool call not reconstructed: %v %+v", ok, tc)
	}

	// The unparseable event keeps its RawText and has no Msg.
	bad := sess.Events[2]
	if bad.Msg != nil {
		t.Error("expected nil Msg for unparseable event")
	}
	if bad.RawText != "this is not json" || bad.ParseErr == "" {
		t.Errorf("raw text/parse err lost: %+v", bad)
	}
}

// TestWriteEventFlushesImmediately guards the live-view property: an event must
// be readable from disk before the writer is closed, since `pounce view` is run
// against sessions whose wrapped process is still running.
func TestWriteEventFlushesImmediately(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	start := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	w, err := Create(Header{ID: NewID(start), PounceVer: "test", StartedAt: start, Command: "cat"})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if err := w.WriteEvent(intent.Event{
		TS:     start,
		Source: "stdio",
		Dir:    intent.ClientToServer,
		Raw:    json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`),
	}); err != nil {
		t.Fatal(err)
	}

	// Read WITHOUT closing the writer first — the event must already be on disk.
	sess, err := Read(w.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.Events) != 1 {
		t.Fatalf("event not flushed before Close: got %d events, want 1", len(sess.Events))
	}
	if sess.Events[0].Msg == nil || sess.Events[0].Msg.Method != "tools/call" {
		t.Errorf("unexpected event read back: %+v", sess.Events[0])
	}
}

func TestResolveAndLatest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// No sessions yet.
	if _, err := Resolve(""); err == nil {
		t.Error("expected error when no sessions exist")
	}

	// Create two sessions; Latest must pick the chronologically newer id.
	older := Header{ID: "20260607-120000.000", PounceVer: "t", StartedAt: time.Now(), Command: "a"}
	newer := Header{ID: "20260607-130000.000", PounceVer: "t", StartedAt: time.Now(), Command: "b"}
	for _, h := range []Header{older, newer} {
		w, err := Create(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
	}

	latest, err := Latest()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(latest) != "20260607-130000.000.jsonl" {
		t.Errorf("latest = %q, want newer session", latest)
	}

	// Resolve by bare id.
	p, err := Resolve("20260607-120000.000")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "20260607-120000.000.jsonl" {
		t.Errorf("resolve by id = %q", p)
	}
}
