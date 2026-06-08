// Package view renders a recorded session log as a human-readable timeline.
package view

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"pounce/internal/intent"
	"pounce/internal/protocol"
	"pounce/internal/store"
)

// argSummaryMax caps how much of a tool call's arguments is shown inline.
const argSummaryMax = 80

// styler wraps text in ANSI SGR codes when enabled, and is a no-op otherwise so
// the same rendering code serves both colored terminals and plain pipes.
type styler struct{ on bool }

func (s styler) paint(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s styler) dim(t string) string    { return s.paint("90", t) }   // gray
func (s styler) method(t string) string { return s.paint("1;34", t) } // bold blue
func (s styler) tool(t string) string   { return s.paint("1;33", t) } // bold yellow
func (s styler) ok(t string) string     { return s.paint("32", t) }   // green
func (s styler) errc(t string) string   { return s.paint("1;31", t) } // bold red

func (s styler) arrow(d intent.Direction) string {
	switch d {
	case intent.ClientToServer:
		return s.paint("36", "->") // cyan: toward server
	case intent.ServerToClient:
		return s.paint("35", "<-") // magenta: toward client
	default:
		return "--"
	}
}

// Timeline writes a tool-call timeline for the session to w. When color is true
// the output is decorated with ANSI escape codes.
func Timeline(w io.Writer, s *store.Session, color bool) {
	st := styler{on: color}

	h := s.Header
	cmd := h.Command
	if len(h.Args) > 0 {
		cmd += " " + strings.Join(h.Args, " ")
	}
	fmt.Fprintf(w, "session %s\n", st.method(h.ID))
	fmt.Fprintf(w, "command: %s\n", cmd)
	fmt.Fprintf(w, "started: %s\n", h.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "events:  %d\n\n", len(s.Events))

	// Match responses to requests direction-aware: a request is answered by a
	// response traveling the *opposite* way, and JSON-RPC ids are only unique
	// per sender — the client's `initialize` and the server's `roots/list` can
	// both be id 0. So a server->client response answers a client->server
	// request, and vice versa. Keying by id alone would collide.
	respFromServer := map[string]protocol.Message{} // answers client->server requests
	respFromClient := map[string]protocol.Message{} // answers server->client requests
	reqFromClient := map[string]bool{}
	reqFromServer := map[string]bool{}
	for _, e := range s.Events {
		if e.Msg == nil {
			continue
		}
		k := e.Msg.IDKey()
		if k == "" {
			continue
		}
		switch e.Msg.Kind() {
		case protocol.KindResponse:
			if e.Dir == intent.ServerToClient {
				respFromServer[k] = *e.Msg
			} else {
				respFromClient[k] = *e.Msg
			}
		case protocol.KindRequest:
			if e.Dir == intent.ClientToServer {
				reqFromClient[k] = true
			} else {
				reqFromServer[k] = true
			}
		}
	}

	matchResponse := func(req *protocol.Message, dir intent.Direction) (protocol.Message, bool) {
		k := req.IDKey()
		if dir == intent.ClientToServer {
			r, ok := respFromServer[k]
			return r, ok
		}
		r, ok := respFromClient[k]
		return r, ok
	}

	orphanResponse := func(resp *intent.Event) bool {
		k := resp.Msg.IDKey()
		if resp.Dir == intent.ServerToClient {
			return !reqFromClient[k] // answers a client->server request
		}
		return !reqFromServer[k]
	}

	var (
		requests  int
		notifs    int
		toolCalls int
		errors    int
	)

	for i := range s.Events {
		e := s.Events[i]
		ts := st.dim(e.TS.Format("15:04:05.000"))
		arrow := st.arrow(e.Dir)

		if e.Msg == nil {
			fmt.Fprintf(w, "%s %s  %s\n", ts, arrow, st.errc("?? unparsed: "+oneLine(e.RawText, argSummaryMax)))
			continue
		}
		m := e.Msg

		switch m.Kind() {
		case protocol.KindRequest:
			requests++
			line := fmt.Sprintf("%s %s  %s", ts, arrow, st.method(m.Method))
			if tc, ok := m.AsToolCall(); ok {
				toolCalls++
				line = fmt.Sprintf("%s %s  %s %s", ts, arrow, st.method(m.Method), st.tool(tc.Name))
				if len(tc.Arguments) > 0 {
					line += "  " + st.dim(oneLine(string(tc.Arguments), argSummaryMax))
				}
			}
			if resp, ok := matchResponse(m, e.Dir); ok {
				if resp.Error != nil {
					errors++
					line += "  " + st.errc("-> ERROR "+resp.Error.String())
				} else {
					line += "  " + st.ok("-> "+summarizeResult(m.Method, resp))
				}
			} else {
				line += "  " + st.dim("-> (no response)")
			}
			fmt.Fprintln(w, line)

		case protocol.KindNotification:
			notifs++
			fmt.Fprintf(w, "%s %s  %s %s\n", ts, arrow, st.method(m.Method), st.dim("(notification)"))

		case protocol.KindResponse:
			// Responses are normally folded into their request line above. Only
			// print one standalone if its request wasn't captured in this log,
			// so nothing is silently hidden.
			if orphanResponse(&e) {
				fmt.Fprintf(w, "%s %s  %s %s\n", ts, arrow,
					st.dim(fmt.Sprintf("(response id %s)", m.IDKey())), st.ok(summarizeResult("", *m)))
			}

		default:
			fmt.Fprintf(w, "%s %s  %s\n", ts, arrow, st.dim("(unknown message)"))
		}
	}

	fmt.Fprintf(w, "\nsummary: %d requests (%d tool calls, %s), %d notifications\n",
		requests, toolCalls, errorsLabel(st, errors), notifs)
}

// errorsLabel colors the error count red when nonzero.
func errorsLabel(st styler, n int) string {
	label := fmt.Sprintf("%d errors", n)
	if n > 0 {
		return st.errc(label)
	}
	return label
}

// summarizeResult renders a one-line summary of a (non-error) response result,
// specialized by the request method when known.
func summarizeResult(method string, resp protocol.Message) string {
	switch method {
	case protocol.MethodToolsList:
		if tools, ok := resp.AsToolList(); ok {
			names := make([]string, 0, len(tools))
			for _, t := range tools {
				names = append(names, t.Name)
			}
			sort.Strings(names)
			return fmt.Sprintf("%d tools [%s]", len(tools), oneLine(strings.Join(names, ", "), argSummaryMax))
		}
	case protocol.MethodRootsList:
		if roots, ok := resp.AsRootList(); ok {
			return fmt.Sprintf("%d roots [%s]", len(roots), oneLine(joinRoots(roots), argSummaryMax))
		}
	case protocol.MethodInitialize:
		if init, ok := resp.AsInitializeResult(); ok {
			si := init.ServerInfo
			if si.Name != "" {
				return fmt.Sprintf("ok (%s %s, protocol %s)", si.Name, si.Version, init.ProtocolVersion)
			}
			return fmt.Sprintf("ok (protocol %s)", init.ProtocolVersion)
		}
	}
	// Unknown method (e.g. an orphan response) — try the richest summary we can.
	if roots, ok := resp.AsRootList(); ok {
		return fmt.Sprintf("%d roots [%s]", len(roots), oneLine(joinRoots(roots), argSummaryMax))
	}
	if tools, ok := resp.AsToolList(); ok {
		return fmt.Sprintf("%d tools", len(tools))
	}
	return "ok"
}

func joinRoots(roots []protocol.Root) string {
	uris := make([]string, 0, len(roots))
	for _, r := range roots {
		uris = append(uris, r.URI)
	}
	return strings.Join(uris, ", ")
}

// oneLine collapses whitespace and truncates s to max runes with an ellipsis.
// Truncation is rune-aware so multi-byte UTF-8 is never split mid-character.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}
