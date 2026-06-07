// Package protocol parses the JSON-RPC 2.0 messages used by the MCP stdio
// transport. The transport is newline-delimited: each line is one JSON-RPC
// request, response, or notification, and messages contain no embedded newlines
// (MCP spec 2025-06-18, "Transports/stdio").
//
// Parsing here is always done on a *copy* of the stream. Pounce never
// re-serializes forwarded bytes; this package only inspects.
package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Kind classifies a JSON-RPC message by which fields are present.
type Kind string

const (
	KindRequest      Kind = "request"      // has method and id
	KindNotification Kind = "notification" // has method, no id
	KindResponse     Kind = "response"     // has result or error, and id
	KindUnknown      Kind = "unknown"      // doesn't match JSON-RPC shape
)

// RPCError is the error object of a JSON-RPC response.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Message is a single parsed JSON-RPC message.
//
// ID is kept as a raw token because JSON-RPC permits string, number, or null,
// and we must compare requests to responses without lossy conversion. Params,
// Result, and Error are kept raw so we never re-encode and can store them
// verbatim.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`

	// hasID records whether an "id" key was present at all (distinct from an id
	// whose value is null), which is how we tell a notification from a request.
	hasID bool
}

// Kind reports the message classification.
func (m Message) Kind() Kind {
	switch {
	case m.Method != "" && m.hasID:
		return KindRequest
	case m.Method != "" && !m.hasID:
		return KindNotification
	case m.hasID && (m.Result != nil || m.Error != nil):
		return KindResponse
	default:
		return KindUnknown
	}
}

// IDKey returns a stable string key for matching responses to requests, or ""
// if the message has no id. Whitespace inside the raw token is normalized away
// so 1 and " 1 " compare equal.
func (m Message) IDKey() string {
	if !m.hasID {
		return ""
	}
	return string(bytes.Join(bytes.Fields(m.ID), nil))
}

// UnmarshalJSON records field presence (notably "id") while decoding.
func (m *Message) UnmarshalJSON(data []byte) error {
	// Decode into a shadow type to get normal field handling...
	type alias Message
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*m = Message(a)

	// ...then probe for the presence of the "id" key specifically.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	_, m.hasID = probe["id"]
	return nil
}

func (e *RPCError) String() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}
