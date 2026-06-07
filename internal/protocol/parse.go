package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ParseLine parses one newline-delimited stdio frame into its JSON-RPC
// message(s).
//
// A frame is normally a single JSON object. The deprecated 2024-11-05 transport
// also permitted a JSON array (a batch) of messages on one line, so we accept
// that too rather than reject traffic from an older peer. Blank/whitespace-only
// lines yield (nil, nil) — they are not an error.
//
// The input must not contain a trailing newline (the scanner strips it). Per
// spec a frame contains no embedded newlines; we do not enforce that here, we
// just parse what JSON allows.
func ParseLine(line []byte) ([]Message, error) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, nil
	}

	switch trimmed[0] {
	case '[':
		var batch []Message
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, fmt.Errorf("parse batch: %w", err)
		}
		return batch, nil
	case '{':
		var msg Message
		if err := json.Unmarshal(trimmed, &msg); err != nil {
			return nil, fmt.Errorf("parse object: %w", err)
		}
		return []Message{msg}, nil
	default:
		return nil, fmt.Errorf("not a JSON-RPC frame: starts with %q", trimmed[0])
	}
}
