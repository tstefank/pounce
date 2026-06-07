// Package intent defines the seam between a source of *declared* actions (tool
// calls) and the source-agnostic pipeline that records and renders them.
//
// The stdio tee (StdioSource) is the first and only implementation in Phase 1.
// Later sources — an HTTP/SSE reverse proxy, an agent log/hook ingester — slot
// in behind the same Source interface and emit the same Events, so the store
// and view layers never change.
package intent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tstefank/pounce/internal/protocol"
)

// Direction records which way a message was traveling.
type Direction string

const (
	// ClientToServer is a message the MCP client sent toward the server
	// (requests, notifications, and the client's responses to server requests).
	ClientToServer Direction = "client->server"
	// ServerToClient is a message the server sent back toward the client.
	ServerToClient Direction = "server->client"
)

// Event is one observed JSON-RPC message, normalized across sources.
//
// Raw holds the JSON of the parsed *copy* of a single message — never the bytes
// forwarded between client and server (those pass through untouched). It is
// stored as embedded JSON so the session log stays human-readable. If a frame
// could not be parsed as JSON, Raw is empty, RawText carries the offending text
// verbatim, and ParseErr explains why. Msg is the parsed view of Raw, derived
// (nil when ParseErr is set); it is not persisted directly but reconstructed on
// read.
type Event struct {
	TS       time.Time         `json:"ts"`
	Source   string            `json:"source"` // e.g. "stdio"
	Dir      Direction         `json:"dir"`
	Raw      json.RawMessage   `json:"raw,omitempty"`
	RawText  string            `json:"raw_text,omitempty"`
	Msg      *protocol.Message `json:"-"`
	ParseErr string            `json:"parse_err,omitempty"`
}

// Source produces Events. Run blocks until the source is exhausted (e.g. the
// wrapped process exits) or ctx is cancelled, sending each observed message to
// out. Implementations must never let an observation error stop the underlying
// data flow they are teeing — they record the error on the Event and continue.
type Source interface {
	Name() string
	Run(ctx context.Context, out chan<- Event) error
}
