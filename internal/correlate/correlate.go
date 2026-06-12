// Package correlate joins declared intent (tool calls) to observed OS effects
// (network connections) by PID + time window, and flags divergence — a
// connection that no declared action explains. This is pounce's north star: the
// discrepancy is the signal.
//
// The join is written against the generic OS event, not network specifically,
// so eslogger file/exec events (Phase 4) slot in through the same path.
package correlate

import (
	"time"

	"pounce/internal/capture"
	"pounce/internal/intent"
	"pounce/internal/protocol"
	"pounce/internal/store"
)

// DefaultWindow is the grace added after a request's response (and the fallback
// span when no response was captured) when deciding whether a connection
// belongs to a call's execution.
const DefaultWindow = 3 * time.Second

// Link ties one request to the OS events that occurred during its execution.
type Link struct {
	CallTS      time.Time
	Method      string // JSON-RPC method, e.g. "tools/call"
	Tool        string // tool name, for tools/call
	Args        string // raw tool arguments, for tools/call
	Connections []capture.Event
}

// Result is the correlation of a whole session.
type Result struct {
	Window    time.Duration
	Links     []Link          // requests with the OS events they caused, in order
	OutOfBand []capture.Event // OS events during no request's execution window
}

// Attributed reports how many OS events were tied to a request.
func (r Result) Attributed() int {
	n := 0
	for _, l := range r.Links {
		n += len(l.Connections)
	}
	return n
}

// window is a request's execution span and a back-reference to its Link.
type window struct {
	idx        int
	start, end time.Time
}

// Correlate joins the session's requests to its OS events. A connection is
// attributed to the most recently started request whose execution window
// contains it; one covered by no window is out-of-band (the divergence signal).
func Correlate(s *store.Session, w time.Duration) Result {
	if w <= 0 {
		w = DefaultWindow
	}
	res := Result{Window: w}

	// A client->server request is answered by a server->client response with the
	// same id; its response time bounds the execution window.
	respTime := map[string]time.Time{}
	for _, e := range s.Events {
		if e.Msg == nil || e.Dir != intent.ServerToClient {
			continue
		}
		if e.Msg.Kind() == protocol.KindResponse {
			if k := e.Msg.IDKey(); k != "" {
				respTime[k] = e.TS
			}
		}
	}

	var wins []window
	for _, e := range s.Events {
		if e.Msg == nil || e.Dir != intent.ClientToServer || e.Msg.Kind() != protocol.KindRequest {
			continue
		}
		start := e.TS
		end := start.Add(w) // fallback when no response was captured
		if rt, ok := respTime[e.Msg.IDKey()]; ok {
			end = rt.Add(w) // execution window + grace for late first packets
		}
		link := Link{CallTS: start, Method: e.Msg.Method}
		if tc, ok := e.Msg.AsToolCall(); ok {
			link.Tool = tc.Name
			link.Args = string(tc.Arguments)
		}
		res.Links = append(res.Links, link)
		wins = append(wins, window{idx: len(res.Links) - 1, start: start, end: end})
	}

	for _, oe := range s.OSEvents {
		best := -1
		for i := range wins {
			if oe.TS.Before(wins[i].start) || oe.TS.After(wins[i].end) {
				continue
			}
			if best < 0 || wins[i].start.After(wins[best].start) {
				best = i
			}
		}
		if best < 0 {
			res.OutOfBand = append(res.OutOfBand, oe)
			continue
		}
		li := wins[best].idx
		res.Links[li].Connections = append(res.Links[li].Connections, oe)
	}
	return res
}
