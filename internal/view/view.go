// Package view renders a recorded session log as a human-readable timeline.
package view

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"pounce/internal/capture"
	"pounce/internal/correlate"
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
func (s styler) remote(t string) string { return s.paint("1;36", t) } // bold cyan: network destination

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
// the output is decorated with ANSI escape codes. window is the correlation
// window (<=0 uses correlate.DefaultWindow).
func Timeline(w io.Writer, s *store.Session, color bool, window time.Duration) {
	st := styler{on: color}

	h := s.Header
	cmd := h.Command
	if len(h.Args) > 0 {
		cmd += " " + strings.Join(h.Args, " ")
	}
	fmt.Fprintf(w, "session %s\n", st.method(h.ID))
	fmt.Fprintf(w, "command: %s\n", cmd)
	fmt.Fprintf(w, "started: %s\n", h.StartedAt.Format(time.RFC3339))
	if s.Capture != nil {
		fmt.Fprintf(w, "capture: %s (%s, %s)\n",
			st.dim(s.Capture.Mode), st.dim(s.Capture.Tcpdump), st.dim(s.Capture.OS))
	}
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
		osEvents  int
	)

	renderProto := func(e intent.Event) {
		ts := st.dim(e.TS.Format("15:04:05.000"))
		arrow := st.arrow(e.Dir)

		if e.Msg == nil {
			fmt.Fprintf(w, "%s %s  %s\n", ts, arrow, st.errc("?? unparsed: "+oneLine(e.RawText, argSummaryMax)))
			return
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
				if toolErr, isToolErr := resp.ToolError(); resp.Error != nil {
					errors++
					line += "  " + st.errc("-> ERROR "+resp.Error.String())
				} else if m.Method == protocol.MethodToolsCall && isToolErr {
					// A successful JSON-RPC response that nonetheless reports the
					// tool failed (result.isError == true).
					errors++
					line += "  " + st.errc("-> tool error: "+oneLine(toolErr, argSummaryMax))
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

	renderOS := func(e capture.Event) {
		osEvents++
		fmt.Fprintln(w, renderOSEvent(st, e))
	}

	// Merge protocol and OS events into one time-ordered timeline. Each slice is
	// already in chronological order, so a linear merge suffices.
	i, j := 0, 0
	for i < len(s.Events) || j < len(s.OSEvents) {
		if i >= len(s.Events) {
			renderOS(s.OSEvents[j])
			j++
		} else if j >= len(s.OSEvents) || !s.OSEvents[j].TS.Before(s.Events[i].TS) {
			renderProto(s.Events[i])
			i++
		} else {
			renderOS(s.OSEvents[j])
			j++
		}
	}

	summary := fmt.Sprintf("\nsummary: %d requests (%d tool calls, %s), %d notifications",
		requests, toolCalls, errorsLabel(st, errors), notifs)
	if len(s.OSEvents) > 0 {
		summary += fmt.Sprintf(", %d OS events", osEvents)
	}
	fmt.Fprintln(w, summary)

	renderCorrelation(w, st, s, window)
}

// renderCorrelation shows the intent↔effect join: which tool call caused which
// connections, and — the divergence signal — connections that no active call
// explains. Shown only when OS events were captured.
func renderCorrelation(w io.Writer, st styler, s *store.Session, window time.Duration) {
	if len(s.OSEvents) == 0 {
		return
	}
	r := correlate.Correlate(s, window)
	fmt.Fprintf(w, "\ncorrelation %s:\n", st.dim(fmt.Sprintf("(window %s)", r.Window)))

	attributed := false
	for _, l := range r.Links {
		if len(l.Connections) == 0 {
			continue
		}
		attributed = true
		label := st.method(l.Method)
		if l.Tool != "" {
			label += " " + st.tool(l.Tool)
		}
		fmt.Fprintf(w, "  %s %s\n", label, st.dim(fmt.Sprintf("→ caused %d", len(l.Connections))))
		for _, c := range l.Connections {
			proto, remote, who := connParts(c)
			fmt.Fprintf(w, "      %s %s  %s\n", proto, st.ok(remote), st.dim(who))
		}
	}
	if !attributed {
		fmt.Fprintf(w, "  %s\n", st.dim("(no connections attributed to a tool call)"))
	}
	if len(r.OutOfBand) > 0 {
		fmt.Fprintf(w, "  %s\n", st.errc(fmt.Sprintf("⚠ %d out-of-band — no active tool call:", len(r.OutOfBand))))
		for _, c := range r.OutOfBand {
			proto, remote, who := connParts(c)
			fmt.Fprintf(w, "      %s %s  %s\n", proto, st.errc(remote), st.dim(who))
		}
	}
}

// connParts splits an OS connect event into display fields.
func connParts(c capture.Event) (proto, remote, who string) {
	if c.Net != nil {
		proto, remote = c.Net.Proto, c.Net.Remote
	}
	return proto, remote, fmt.Sprintf("%s pid %d", c.Proc, c.PID)
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

// renderOSEvent formats one OS ground-truth event for the timeline. A "· net"
// marker and a distinct color set OS rows apart from the protocol arrows.
func renderOSEvent(st styler, e capture.Event) string {
	ts := st.dim(e.TS.Format("15:04:05.000"))
	who := st.dim(fmt.Sprintf("%s pid %d", e.Proc, e.PID))
	switch e.Op {
	case capture.OpConnect:
		proto, remote, dir := "", "", ""
		if e.Net != nil {
			proto, remote, dir = e.Net.Proto, e.Net.Remote, e.Net.Dir
		}
		return fmt.Sprintf("%s %s  %s %s  %s  %s",
			ts, st.dim("· net"), proto, st.remote(remote), st.dim(dir), who)
	default:
		return fmt.Sprintf("%s %s  %s", ts, st.dim("· os"), who)
	}
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
