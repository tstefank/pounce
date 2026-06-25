// Package view renders a recorded session log as a human-readable timeline.
package view

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"pounce/internal/capture"
	"pounce/internal/intent"
	"pounce/internal/protocol"
	"pounce/internal/store"
	"pounce/internal/triggers"
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
func (s styler) warn(t string) string   { return s.paint("33", t) }   // yellow: review
func (s styler) errc(t string) string   { return s.paint("1;31", t) } // bold red: alert
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

// Summary writes a verdict-first, grouped view: a one-line verdict driven by the
// trigger rules (TRIGGERS.md), then each tool call with the connections it
// caused — each labeled by severity (⚠ alert / ? review / ✓ expected) — then a
// compact footer. `--timeline` (Timeline) gives the full chronological log.
func Summary(w io.Writer, s *store.Session, color bool, window time.Duration, profile *triggers.Profile) {
	st := styler{on: color}
	h := s.Header
	cmd := h.Command
	if len(h.Args) > 0 {
		cmd += " " + strings.Join(h.Args, " ")
	}
	fmt.Fprintf(w, "%s  %s\n", cmd, st.dim(h.ID))

	rep := triggers.Evaluate(s, window, profile)
	fmt.Fprintln(w, verdictLine(st, rep))
	fmt.Fprintln(w)

	calls, conns := 0, 0
	for _, cf := range rep.Calls {
		label := st.method(cf.Method)
		if cf.Tool != "" {
			calls++
			label = st.method(cf.Method) + " " + st.tool(cf.Tool)
		}
		args := ""
		if cf.Args != "" {
			args = "  " + st.dim(oneLine(cf.Args, 60))
		}
		if len(cf.Findings) == 0 {
			fmt.Fprintf(w, "  %s%s  %s\n", label, args, st.dim("(no network)"))
			continue
		}
		fmt.Fprintf(w, "  %s%s\n", label, args)
		for _, f := range cf.Findings {
			conns += f.Count
			fmt.Fprintf(w, "     %s\n", findingLine(st, f))
		}
	}
	if len(rep.OutOfBand) > 0 {
		fmt.Fprintf(w, "  %s\n", st.dim("out-of-band — no active tool call:"))
		for _, f := range rep.OutOfBand {
			conns += f.Count
			fmt.Fprintf(w, "     %s\n", findingLine(st, f))
		}
	}

	high, review := rep.Counts()
	footer := fmt.Sprintf("%d tool call%s · %d connection%s", calls, plural(calls), conns, plural(conns))
	if high > 0 {
		footer += fmt.Sprintf(" · %d alert%s", high, plural(high))
	}
	if review > 0 {
		footer += fmt.Sprintf(" · %d to review", review)
	}
	fmt.Fprintf(w, "\n%s\n", st.dim(footer+"    (--timeline for the full log)"))
}

// Roster renders a one-line verdict per session (newest first) — the overview
// for several wrapped servers running at once. Sessions with findings expand to
// show them (never a bare count without its list).
func Roster(w io.Writer, sessions []*store.Session, color bool, window time.Duration, profile *triggers.Profile) {
	st := styler{on: color}
	if len(sessions) == 0 {
		fmt.Fprintln(w, st.dim("no sessions in ~/.pounce/sessions"))
		return
	}

	type row struct {
		s       *store.Session
		notable []triggers.Finding
		mark    string
		high    int
		review  int
	}
	var rows []row
	flagged := 0
	for _, s := range sessions {
		rep := triggers.Evaluate(s, window, profile)
		high, review := rep.Counts()
		if high > 0 || review > 0 {
			flagged++
		}
		rows = append(rows, row{s: s, notable: notableFindings(rep), mark: sessionMark(st, rep), high: high, review: review})
	}

	if flagged > 0 {
		fmt.Fprintf(w, "%s\n\n", st.warn(fmt.Sprintf("%d of %d session%s with findings to review", flagged, len(rows), plural(len(rows)))))
	} else {
		fmt.Fprintf(w, "%s\n\n", st.ok(fmt.Sprintf("✓ %d session%s, no divergence", len(rows), plural(len(rows)))))
	}

	for _, rw := range rows {
		cmd := rw.s.Header.Command
		if len(rw.s.Header.Args) > 0 {
			cmd += " " + strings.Join(rw.s.Header.Args, " ")
		}
		count := ""
		if label := findingsCountLabel(st, rw.high, rw.review); label != "" {
			count = "  " + label
		}
		fmt.Fprintf(w, "%s %s  %s%s\n", rw.mark, oneLine(cmd, 56), st.dim(rw.s.Header.ID), count)
		const showMax = 3
		for i, f := range rw.notable {
			if i == showMax {
				fmt.Fprintf(w, "     %s\n", st.dim(fmt.Sprintf("… and %d more", len(rw.notable)-showMax)))
				break
			}
			fmt.Fprintf(w, "     %s\n", findingLine(st, f))
		}
	}
	fmt.Fprintf(w, "\n%s\n", st.dim(fmt.Sprintf("%d session%s · %d to review    (pounce view --session <id> for one)", len(rows), plural(len(rows)), flagged)))
}

// verdictLine is the one-line summary at the top: the highest-severity signal
// present, named by the rules that fired.
func verdictLine(st styler, rep triggers.Report) string {
	if !rep.HasCapture {
		return st.dim("· no OS capture (run `sudo pounce daemon` to see the connections each call caused)")
	}
	high, review := rep.Counts()
	switch {
	case high > 0:
		return st.errc(fmt.Sprintf("⚠ %d alert%s — %s", high, plural(high), typesPhrase(rep, triggers.High)))
	case review > 0:
		return st.warn(fmt.Sprintf("? %d to review — %s", review, typesPhrase(rep, triggers.Medium)))
	default:
		return st.ok("✓ no divergence")
	}
}

// typesPhrase lists the distinct finding types at a severity (pushing ones, for
// Medium), e.g. "capability mismatch, destination mismatch".
func typesPhrase(rep triggers.Report, sev triggers.Severity) string {
	seen := map[triggers.Type]bool{}
	var order []string
	for _, f := range rep.All() {
		include := f.Severity == sev
		if sev == triggers.Medium {
			include = include && f.Pushes()
		}
		if include && !seen[f.Type] {
			seen[f.Type] = true
			order = append(order, string(f.Type))
		}
	}
	return strings.Join(order, ", ")
}

// notableFindings returns the findings worth surfacing in the roster: alerts and
// pushing (warm, confident) review findings.
func notableFindings(rep triggers.Report) []triggers.Finding {
	var out []triggers.Finding
	for _, f := range rep.All() {
		if f.Severity == triggers.High || (f.Severity == triggers.Medium && f.Pushes()) {
			out = append(out, f)
		}
	}
	return out
}

// sessionMark returns the marker glyph for a session's overall status.
func sessionMark(st styler, rep triggers.Report) string {
	high, review := rep.Counts()
	switch {
	case high > 0:
		return st.errc("⚠")
	case review > 0:
		return st.warn("?")
	case !rep.HasCapture:
		return st.dim("·")
	default:
		return st.ok("✓")
	}
}

// findingsCountLabel summarizes a session's findings as "(N alerts, M to review)".
func findingsCountLabel(st styler, high, review int) string {
	var parts []string
	if high > 0 {
		parts = append(parts, st.errc(fmt.Sprintf("%d alert%s", high, plural(high))))
	}
	if review > 0 {
		parts = append(parts, st.warn(fmt.Sprintf("%d to review", review)))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// findingMark returns the severity glyph for a finding. A Medium that does not
// push (provisional during learning, or low-confidence) is dimmed — it's in the
// log but not an active concern.
func findingMark(st styler, f triggers.Finding) string {
	switch f.Severity {
	case triggers.High:
		return st.errc("⚠")
	case triggers.Medium:
		if f.Pushes() {
			return st.warn("?")
		}
		return st.dim("?")
	default:
		return st.ok("✓")
	}
}

// findingLine renders one connection-finding: severity mark, destination, reason.
func findingLine(st styler, f triggers.Finding) string {
	proto := ""
	if f.Conn.Event.Net != nil {
		proto = f.Conn.Event.Net.Proto
	}
	dest := proto + " " + f.Conn.Remote()
	switch f.Severity {
	case triggers.High:
		dest = st.errc(dest)
	case triggers.Medium:
		dest = st.warn(dest)
	default:
		dest = st.ok(dest)
	}
	detail := f.Detail
	// Annotations only explain why a Medium stays soft; a High alert shows clean.
	if f.Provisional {
		detail += " (learning)"
	} else if f.Severity == triggers.Medium && f.Confidence < 0.5 {
		detail += " (low confidence)"
	}
	line := fmt.Sprintf("%s %s  %s", findingMark(st, f), dest, st.dim(detail))
	if f.Count > 1 {
		line += st.dim(fmt.Sprintf("  (×%d)", f.Count))
	}
	return line
}

// findingLineWithProc is findingLine plus the attributed process, for the
// timeline's correlation section.
func findingLineWithProc(st styler, f triggers.Finding) string {
	who := st.dim(fmt.Sprintf("%s pid %d", f.Conn.Event.Proc, f.Conn.Event.PID))
	return findingLine(st, f) + "  " + who
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Timeline writes a tool-call timeline for the session to w. When color is true
// the output is decorated with ANSI escape codes. window is the correlation
// window (<=0 uses correlate.DefaultWindow).
func Timeline(w io.Writer, s *store.Session, color bool, window time.Duration, profile *triggers.Profile) {
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

	renderCorrelation(w, st, s, window, profile)
}

// renderCorrelation shows the intent↔effect join evaluated against the trigger
// rules: the verdict, which tool call caused which connections (each with its
// finding), and any out-of-band connections. Shown only when OS events exist.
func renderCorrelation(w io.Writer, st styler, s *store.Session, window time.Duration, profile *triggers.Profile) {
	if len(s.OSEvents) == 0 {
		return
	}
	rep := triggers.Evaluate(s, window, profile)
	fmt.Fprintf(w, "\ncorrelation %s:\n", st.dim(fmt.Sprintf("(window %s)", rep.Window)))
	fmt.Fprintf(w, "  %s\n", verdictLine(st, rep))

	attributed := false
	for _, cf := range rep.Calls {
		if len(cf.Findings) == 0 {
			continue
		}
		attributed = true
		label := st.method(cf.Method)
		if cf.Tool != "" {
			label += " " + st.tool(cf.Tool)
		}
		fmt.Fprintf(w, "  %s %s\n", label, st.dim(fmt.Sprintf("→ caused %d", len(cf.Findings))))
		for _, f := range cf.Findings {
			fmt.Fprintf(w, "      %s\n", findingLineWithProc(st, f))
		}
	}
	if !attributed && len(rep.OutOfBand) == 0 {
		fmt.Fprintf(w, "  %s\n", st.dim("(no connections attributed to a tool call)"))
	}
	if len(rep.OutOfBand) > 0 {
		fmt.Fprintf(w, "  %s\n", st.dim(fmt.Sprintf("○ %d out-of-band — no active tool call:", len(rep.OutOfBand))))
		for _, f := range rep.OutOfBand {
			fmt.Fprintf(w, "      %s\n", findingLineWithProc(st, f))
		}
	}
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
	case capture.OpResolve:
		host, ips := "", ""
		if e.Resolve != nil {
			host = e.Resolve.Host
			ips = strings.Join(e.Resolve.IPs, ", ")
		}
		return fmt.Sprintf("%s %s  %s %s  %s",
			ts, st.dim("· dns"), host, st.dim("→ "+ips), who)
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
