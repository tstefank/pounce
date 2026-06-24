package triggers

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"pounce/internal/capture"
	"pounce/internal/intent"
	"pounce/internal/protocol"
	"pounce/internal/store"
)

func tAt(sec int) time.Time { return time.Date(2026, 6, 23, 12, 0, sec, 0, time.UTC) }

func evAt(dir intent.Direction, raw string, ts time.Time) intent.Event {
	msgs, err := protocol.ParseLine([]byte(raw))
	if err != nil || len(msgs) == 0 {
		panic("bad test frame: " + raw)
	}
	m := msgs[0]
	return intent.Event{TS: ts, Source: "stdio", Dir: dir, Raw: json.RawMessage(raw), Msg: &m}
}

// callSession builds a session with a single tools/call (request at t=0,
// response at t=5) plus the given OS events. The 3s default window covers t<=8.
func callSession(id, tool, args string, os ...capture.Event) *store.Session {
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, args)
	return &store.Session{
		Header: store.Header{ID: id, Command: "srv"},
		Events: []intent.Event{
			evAt(intent.ClientToServer, req, tAt(0)),
			evAt(intent.ServerToClient, `{"jsonrpc":"2.0","id":1,"result":{}}`, tAt(5)),
		},
		OSEvents: os,
	}
}

func resolveEv(ts time.Time, host string, ips ...string) capture.Event {
	return capture.Event{TS: ts, Op: capture.OpResolve, PID: 9, Proc: "node",
		Resolve: &capture.Resolve{Host: host, IPs: ips}}
}

func connectEv(ts time.Time, remote string) capture.Event {
	return capture.Event{TS: ts, Op: capture.OpConnect, PID: 9, Proc: "node",
		Net: &capture.NetFlow{Proto: "tcp", Remote: remote, Dir: "out"}}
}

// findFor returns the finding whose connection has the given remote endpoint.
func findFor(t *testing.T, rep Report, remote string) Finding {
	t.Helper()
	for _, f := range rep.All() {
		if f.Conn.Remote() == remote {
			return f
		}
	}
	t.Fatalf("no finding for %s in report %+v", remote, rep)
	return Finding{}
}

// TestTriggers covers each rule on a representative connection.
func TestTriggers(t *testing.T) {
	tests := []struct {
		name    string
		session *store.Session
		remote  string
		want    Type
		sev     Severity
	}{
		{
			name: "capability mismatch: local-only tool egressed",
			session: callSession("s", "read_file", `{"path":"/etc/hosts"}`,
				connectEv(tAt(1), "8.8.8.8:443")),
			remote: "8.8.8.8:443", want: CapabilityMismatch, sev: High,
		},
		{
			name: "destination mismatch: declared host, connected to an unlooked-up IP",
			session: callSession("s", "fetch", `{"url":"https://api.example.com/x"}`,
				resolveEv(tAt(1), "api.example.com", "1.2.3.4"),
				connectEv(tAt(2), "1.2.3.4:443"),     // legit
				connectEv(tAt(2), "45.83.12.9:443")), // the exfil IP
			remote: "45.83.12.9:443", want: DestinationMismatch, sev: High,
		},
		{
			name: "expected: connection to the declared host's resolved IP",
			session: callSession("s", "fetch", `{"url":"https://api.example.com/x"}`,
				resolveEv(tAt(1), "api.example.com", "1.2.3.4"),
				connectEv(tAt(2), "1.2.3.4:443")),
			remote: "1.2.3.4:443", want: Expected, sev: Info,
		},
		{
			name: "expected: CDN subdomain shares the declared registrable domain",
			session: callSession("s", "fetch", `{"url":"https://api.example.com/x"}`,
				resolveEv(tAt(1), "cdn.example.com", "5.6.6.6"),
				connectEv(tAt(2), "5.6.6.6:443")),
			remote: "5.6.6.6:443", want: Expected, sev: Info,
		},
		{
			name: "cloud metadata endpoint beats the scope filter",
			session: callSession("s", "do_thing", `{}`,
				connectEv(tAt(1), "169.254.169.254:80")),
			remote: "169.254.169.254:80", want: MetadataEndpoint, sev: High,
		},
		{
			name: "private/loopback destination is Info",
			session: callSession("s", "do_thing", `{}`,
				connectEv(tAt(1), "10.0.0.5:5432")),
			remote: "10.0.0.5:5432", want: Expected, sev: Info,
		},
		{
			name: "raw IP, no DNS, no declared host: Medium",
			session: callSession("s", "do_thing", `{}`,
				connectEv(tAt(1), "203.0.113.7:443")),
			remote: "203.0.113.7:443", want: RawIPNoDNS, sev: Medium,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := Evaluate(tc.session, 0, nil)
			f := findFor(t, rep, tc.remote)
			if f.Type != tc.want || f.Severity != tc.sev {
				t.Errorf("got %q/%v, want %q/%v (detail: %s)", f.Type, f.Severity, tc.want, tc.sev, f.Detail)
			}
		})
	}
}

// TestConfidence checks attribution_certainty × naming_certainty.
func TestConfidence(t *testing.T) {
	// A connection the call named by URL → attribution 1.0, named 1.0 → 1.0.
	rep := Evaluate(callSession("s", "fetch", `{"url":"https://api.example.com"}`,
		resolveEv(tAt(1), "api.example.com", "1.2.3.4"),
		connectEv(tAt(2), "1.2.3.4:443")), 0, nil)
	if f := findFor(t, rep, "1.2.3.4:443"); f.Confidence != 1.0 {
		t.Errorf("declared-host connection confidence = %v, want 1.0", f.Confidence)
	}

	// An out-of-band raw IP → attribution 0.3, naming 0.6 → 0.18, and must not push.
	oob := callSession("s", "do_thing", `{}`, connectEv(tAt(30), "203.0.113.7:443")) // t=30 is past the window
	repO := Evaluate(oob, 0, nil)
	f := findFor(t, repO, "203.0.113.7:443")
	if f.Confidence > 0.2 {
		t.Errorf("out-of-band raw IP confidence = %v, want ~0.18", f.Confidence)
	}
	if f.Pushes() {
		t.Errorf("low-confidence finding must not push: %+v", f)
	}
}

// TestNoveltyAndLearning exercises the persisted-profile rules (#4 novelty and
// the learned half of #1) across two ordered sessions.
func TestNoveltyAndLearning(t *testing.T) {
	p := &Profile{Tools: map[string]*toolStat{}, Learned: map[string]bool{}}

	// Session 1 (earliest id): `query` connects to alpha.com for the first time.
	s1 := callSession("20260101-000000.000-1", "query", `{}`,
		resolveEv(tAt(1), "api.alpha.com", "1.1.1.1"),
		connectEv(tAt(2), "1.1.1.1:443"))
	rep1 := Evaluate(s1, 0, p)
	f1 := findFor(t, rep1, "1.1.1.1:443")
	if f1.Type != NovelDestination || f1.Severity != Medium {
		t.Fatalf("alpha should be novel Medium, got %q/%v", f1.Type, f1.Severity)
	}
	if !f1.Provisional || f1.Pushes() {
		t.Errorf("first session is cold: novelty must be provisional and not push, got %+v", f1)
	}
	p.Learn(s1.Header.ID, rep1)

	// Session 2 (later id): alpha is now known (suppressed); beta is novel and,
	// since `query` is warm, it pushes.
	s2 := callSession("20260202-000000.000-1", "query", `{}`,
		resolveEv(tAt(1), "api.alpha.com", "1.1.1.1"),
		connectEv(tAt(2), "1.1.1.1:443"),
		resolveEv(tAt(1), "api.beta.com", "2.2.2.2"),
		connectEv(tAt(2), "2.2.2.2:443"))
	rep2 := Evaluate(s2, 0, p)

	if f := findFor(t, rep2, "1.1.1.1:443"); f.Type != Expected {
		t.Errorf("alpha should now be known/Expected, got %q (%s)", f.Type, f.Detail)
	}
	fb := findFor(t, rep2, "2.2.2.2:443")
	if fb.Type != NovelDestination || fb.Severity != Medium {
		t.Errorf("beta should be novel Medium, got %q/%v", fb.Type, fb.Severity)
	}
	if fb.Provisional || !fb.Pushes() {
		t.Errorf("warm novelty should push and not be provisional, got %+v", fb)
	}

	// Viewing s1 again must STILL flag alpha as novel (its own debut) — order
	// independence: learning s1 did not suppress s1's own novelty.
	if f := findFor(t, Evaluate(s1, 0, p), "1.1.1.1:443"); f.Type != NovelDestination {
		t.Errorf("re-viewing the debut session must keep alpha novel, got %q", f.Type)
	}
}

// TestLearnedCapabilityMismatch: a tool observed before that never egressed,
// now connecting out, is a High capability mismatch even without the prior.
func TestLearnedCapabilityMismatch(t *testing.T) {
	p := &Profile{Tools: map[string]*toolStat{}, Learned: map[string]bool{}}

	// Session 1: `lookup` is called but makes no connection (a local tool, as far
	// as we've seen). The built-in prior doesn't recognize the name.
	s1 := callSession("20260101-000000.000-1", "lookup", `{}`)
	p.Learn(s1.Header.ID, Evaluate(s1, 0, p))
	if localOnly("lookup") {
		t.Fatal("precondition: 'lookup' must not match the built-in prior")
	}

	// Session 2: `lookup` now egresses → learned capability mismatch.
	s2 := callSession("20260202-000000.000-1", "lookup", `{}`,
		connectEv(tAt(1), "198.51.100.9:443"))
	f := findFor(t, Evaluate(s2, 0, p), "198.51.100.9:443")
	if f.Type != CapabilityMismatch || f.Severity != High {
		t.Errorf("expected learned capability mismatch High, got %q/%v (%s)", f.Type, f.Severity, f.Detail)
	}
}

func TestLocalOnly(t *testing.T) {
	local := []string{
		"read_file", "read_text_file", "list_directory", "list_allowed_directories",
		"get_file_info", "directory_tree", "write_file", "move_file", "get_time",
		"create_directory", "search_files", "list_directory_with_sizes", "get_timezone",
		// network-looking *substrings* that aren't whole segments must stay local:
		"list_apidoc_files", "read_postscript_files",
	}
	network := []string{
		"fetch", "http_get", "search_web", "brave_web_search", "send_email",
		"download_file", "post_message", "", "sync_repo",
		// real networked MCP tools the verb-only prior used to misclassify as local:
		"create_issue", "list_repositories", "search_repositories", "maps_search_places",
		"list_commits", "get_repository", "create_pull_request", "list_branches",
	}
	for _, tool := range local {
		if !localOnly(tool) {
			t.Errorf("localOnly(%q) = false, want true", tool)
		}
	}
	for _, tool := range network {
		if localOnly(tool) {
			t.Errorf("localOnly(%q) = true, want false", tool)
		}
	}
}

// TestDedupe: multiple connections to the same registrable domain within one
// call collapse to a single finding (TRIGGERS.md fatigue rule), Count counts them.
func TestDedupe(t *testing.T) {
	s := callSession("s", "query", `{}`,
		resolveEv(tAt(1), "cdn1.alpha.com", "1.1.1.1"),
		resolveEv(tAt(1), "cdn2.alpha.com", "2.2.2.2"),
		connectEv(tAt(2), "1.1.1.1:443"),
		connectEv(tAt(2), "2.2.2.2:443"))
	rep := Evaluate(s, 0, NewProfile())
	if n := len(rep.Calls); n != 1 || len(rep.Calls[0].Findings) != 1 {
		t.Fatalf("expected 1 call with 1 deduped finding, got %d calls / %v", n, rep.Calls)
	}
	f := rep.Calls[0].Findings[0]
	if f.Domain != "alpha.com" || f.Count != 2 {
		t.Errorf("expected one alpha.com finding with Count 2, got domain=%q count=%d", f.Domain, f.Count)
	}
}

// TestDoHFallback: a call that declares a host but whose DNS isn't observed
// (DoH / warm cache) must fall back to the IP-level rule (raw-IP Medium), not
// assert a High destination mismatch on zero naming evidence.
func TestDoHFallback(t *testing.T) {
	s := callSession("s", "fetch", `{"url":"https://example.com"}`,
		connectEv(tAt(2), "93.184.216.34:443")) // no resolve event captured
	f := findFor(t, Evaluate(s, 0, nil), "93.184.216.34:443")
	if f.Type != RawIPNoDNS || f.Severity != Medium {
		t.Errorf("declared host with no DNS should fall back to raw-IP Medium, got %q/%v (%s)", f.Type, f.Severity, f.Detail)
	}
}

// TestLearnedCapabilityDefersToDeclared: the learned capability rule must not
// fire when the connection went exactly to the host the call declared.
func TestLearnedCapabilityDefersToDeclared(t *testing.T) {
	p := NewProfile()
	// `grab` (not matched by the prior) seen earlier with no connection.
	s1 := callSession("20260101-000000.000-1", "grab", `{"url":"https://api.example.com"}`)
	p.Learn(s1.Header.ID, Evaluate(s1, 0, p))
	if localOnly("grab") {
		t.Fatal("precondition: 'grab' must not match the built-in prior")
	}
	// Now it connects to its own declared host's resolved IP → Expected, not a
	// learned capability mismatch.
	s2 := callSession("20260202-000000.000-1", "grab", `{"url":"https://api.example.com"}`,
		resolveEv(tAt(1), "api.example.com", "1.2.3.4"),
		connectEv(tAt(2), "1.2.3.4:443"))
	f := findFor(t, Evaluate(s2, 0, p), "1.2.3.4:443")
	if f.Type != Expected {
		t.Errorf("connection to the declared host must be Expected, got %q (%s)", f.Type, f.Detail)
	}
}

// TestIDOrdering: same-millisecond siblings (different pids) are concurrent —
// neither is "earlier" — so one can't suppress the other's novelty.
func TestIDOrdering(t *testing.T) {
	a, b := "20260101-120000.000-500", "20260101-120000.000-1500"
	if earlier(a, b) || earlier(b, a) {
		t.Errorf("same-ms siblings must be concurrent: earlier(a,b)=%v earlier(b,a)=%v", earlier(a, b), earlier(b, a))
	}
	if !earlier("20260101-120000.000-9999", "20260101-120001.000-1") {
		t.Error("an earlier timestamp must order earlier regardless of pid width")
	}
}

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"api.example.com":          "example.com",
		"cdn.assets.example.co.uk": "example.co.uk",
		"example.com":              "example.com",
		"1.2.3.4":                  "",
		"":                         "",
	}
	for in, want := range cases {
		if got := registrable(in); got != want {
			t.Errorf("registrable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsPrivate(t *testing.T) {
	private := []string{"10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.0.1", "::1"}
	public := []string{"8.8.8.8", "203.0.113.7", "1.1.1.1", "garbage", ""}
	for _, ip := range private {
		if !isPrivate(ip) {
			t.Errorf("isPrivate(%q) = false, want true", ip)
		}
	}
	for _, ip := range public {
		if isPrivate(ip) {
			t.Errorf("isPrivate(%q) = true, want false", ip)
		}
	}
}
