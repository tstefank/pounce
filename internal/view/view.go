// Package view renders a recorded session log as a human-readable timeline.
package view

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tstefank/pounce/internal/intent"
	"github.com/tstefank/pounce/internal/protocol"
	"github.com/tstefank/pounce/internal/store"
)

// argSummaryMax caps how much of a tool call's arguments is shown inline.
const argSummaryMax = 80

// Timeline writes a tool-call timeline for the session to w.
func Timeline(w io.Writer, s *store.Session) {
	h := s.Header
	cmd := h.Command
	if len(h.Args) > 0 {
		cmd += " " + strings.Join(h.Args, " ")
	}
	fmt.Fprintf(w, "session %s\n", h.ID)
	fmt.Fprintf(w, "command: %s\n", cmd)
	fmt.Fprintf(w, "started: %s\n", h.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "events:  %d\n\n", len(s.Events))

	// Index responses by id so each request can show its outcome. Responses
	// flow server->client and carry the matching request id.
	respByID := map[string]protocol.Message{}
	for _, e := range s.Events {
		if e.Msg == nil {
			continue
		}
		if e.Msg.Kind() == protocol.KindResponse {
			if k := e.Msg.IDKey(); k != "" {
				respByID[k] = *e.Msg
			}
		}
	}

	var (
		requests  int
		notifs    int
		toolCalls int
		errors    int
	)

	for _, e := range s.Events {
		ts := e.TS.Format("15:04:05.000")
		arrow := dirArrow(e.Dir)

		if e.Msg == nil {
			// Unparseable frame — still surface it.
			fmt.Fprintf(w, "%s %s  ?? unparsed: %s\n", ts, arrow, oneLine(e.RawText, argSummaryMax))
			continue
		}
		m := e.Msg

		switch m.Kind() {
		case protocol.KindRequest:
			requests++
			line := fmt.Sprintf("%s %s  %s", ts, arrow, m.Method)
			if tc, ok := m.AsToolCall(); ok {
				toolCalls++
				line = fmt.Sprintf("%s %s  %s %s", ts, arrow, m.Method, tc.Name)
				if len(tc.Arguments) > 0 {
					line += "  " + oneLine(string(tc.Arguments), argSummaryMax)
				}
			}
			// Attach the matched response outcome, if any.
			if resp, ok := respByID[m.IDKey()]; ok {
				if resp.Error != nil {
					errors++
					line += "  -> ERROR " + resp.Error.String()
				} else {
					line += "  -> ok"
				}
			} else {
				line += "  -> (no response)"
			}
			fmt.Fprintln(w, line)

		case protocol.KindNotification:
			notifs++
			fmt.Fprintf(w, "%s %s  %s (notification)\n", ts, arrow, m.Method)

		case protocol.KindResponse:
			// Responses are folded into their request line above; skip here so
			// the timeline reads as request-centric. (tools/list is worth
			// surfacing on its own, below.)
			if tools, ok := m.AsToolList(); ok {
				names := make([]string, 0, len(tools))
				for _, t := range tools {
					names = append(names, t.Name)
				}
				sort.Strings(names)
				fmt.Fprintf(w, "%s %s  tools/list result: %d tools [%s]\n",
					ts, arrow, len(tools), oneLine(strings.Join(names, ", "), argSummaryMax))
			}

		default:
			fmt.Fprintf(w, "%s %s  (unknown message)\n", ts, arrow)
		}
	}

	fmt.Fprintf(w, "\nsummary: %d requests (%d tool calls, %d errors), %d notifications\n",
		requests, toolCalls, errors, notifs)
}

func dirArrow(d intent.Direction) string {
	switch d {
	case intent.ClientToServer:
		return "->"
	case intent.ServerToClient:
		return "<-"
	default:
		return "--"
	}
}

// oneLine collapses whitespace and truncates s to max runes with an ellipsis.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
