// Package store persists a wrap session as a newline-delimited JSON (JSONL)
// log under ~/.pounce/sessions/<id>.jsonl.
//
// The first line is a Header record; every subsequent line is an Event record.
// Records are tagged with a "kind" field so the reader can tell them apart and
// so the format can grow new record kinds (e.g. OS-capture events in Phase 2)
// without breaking older readers.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tstefank/pounce/internal/intent"
	"github.com/tstefank/pounce/internal/protocol"
)

// recordKind tags each JSONL line.
type recordKind string

const (
	kindHeader recordKind = "header"
	kindEvent  recordKind = "event"
)

// Header is the first line of a session log: metadata about the wrap run.
type Header struct {
	Kind      recordKind `json:"kind"`
	ID        string     `json:"id"`
	PounceVer string     `json:"pounce_version"`
	StartedAt time.Time  `json:"started_at"`
	Command   string     `json:"command"`
	Args      []string   `json:"args"`
}

// envelope is the on-disk shape of an event line. The intent.Event is embedded
// flat; "kind" distinguishes it from a header.
type envelope struct {
	Kind recordKind `json:"kind"`
	intent.Event
}

// SessionsDir returns ~/.pounce/sessions, creating it if needed.
func SessionsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	dir := filepath.Join(home, ".pounce", "sessions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create sessions dir: %w", err)
	}
	return dir, nil
}

// NewID builds a session id from a start time. The caller passes the time so
// the value is deterministic and testable.
func NewID(start time.Time) string {
	return start.UTC().Format("20060102-150405.000")
}

// Writer appends records to a session log.
type Writer struct {
	f    *os.File
	bw   *bufio.Writer
	enc  *json.Encoder
	path string
}

// Create opens a new session log file for the given header, writing the header
// as the first line.
func Create(h Header) (*Writer, error) {
	dir, err := SessionsDir()
	if err != nil {
		return nil, err
	}
	h.Kind = kindHeader
	path := filepath.Join(dir, h.ID+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create session file: %w", err)
	}
	w := &Writer{f: f, bw: bufio.NewWriter(f), path: path}
	w.enc = json.NewEncoder(w.bw)
	w.enc.SetEscapeHTML(false) // keep ">" etc. readable in the log
	if err := w.enc.Encode(h); err != nil {
		f.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}
	return w, nil
}

// Path returns the file path being written.
func (w *Writer) Path() string { return w.path }

// WriteEvent appends one event record and flushes it to disk immediately.
//
// We flush per event (rather than relying on the bufio buffer filling up or
// Close) so that `view` reflects a live session in real time — an observability
// tool that only shows activity after the wrapped process exits would be
// useless while an agent is still running. MCP traffic is low-volume, so the
// extra write syscall per message is negligible.
func (w *Writer) WriteEvent(e intent.Event) error {
	if err := w.enc.Encode(envelope{Kind: kindEvent, Event: e}); err != nil {
		return err
	}
	return w.bw.Flush()
}

// Close flushes and closes the file.
func (w *Writer) Close() error {
	if err := w.bw.Flush(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

// Session is a fully-read session log.
type Session struct {
	Header Header
	Events []intent.Event
}

// Read loads and parses a session log from path. Malformed lines are skipped
// (a recording artifact should never make a session unreadable).
func Read(path string) (*Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var s Session
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		// Peek at the kind tag.
		var probe struct {
			Kind recordKind `json:"kind"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			continue
		}
		switch probe.Kind {
		case kindHeader:
			_ = json.Unmarshal(line, &s.Header)
		case kindEvent:
			var env envelope
			if err := json.Unmarshal(line, &env); err != nil {
				continue
			}
			ev := env.Event
			// Reconstruct the parsed Msg from Raw so readers get full
			// classification without persisting unexported state.
			if msgs, perr := protocol.ParseLine(ev.Raw); perr == nil && len(msgs) > 0 {
				m := msgs[0]
				ev.Msg = &m
			}
			s.Events = append(s.Events, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	return &s, nil
}

// Latest returns the path of the most recent session log, or "" if none exist.
func Latest() (string, error) {
	dir, err := SessionsDir()
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	// IDs are timestamp-prefixed, so lexical sort == chronological sort.
	sort.Strings(names)
	return filepath.Join(dir, names[len(names)-1]), nil
}

// Resolve turns a --session value (empty, an id, or a path) into a file path.
func Resolve(session string) (string, error) {
	if session == "" {
		path, err := Latest()
		if err != nil {
			return "", err
		}
		if path == "" {
			return "", fmt.Errorf("no sessions found in ~/.pounce/sessions")
		}
		return path, nil
	}
	// A path (absolute, relative, or anything ending in .jsonl) is used as-is.
	if strings.ContainsRune(session, os.PathSeparator) || strings.HasSuffix(session, ".jsonl") {
		return session, nil
	}
	dir, err := SessionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, session+".jsonl"), nil
}
