package capture

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// systemTcpdump is the system tcpdump. The doc is explicit: pin to the system
// binary for pktap; a Homebrew build may lack pktap support.
const systemTcpdump = "/usr/sbin/tcpdump"

// seenCap bounds the per-connection dedup set so a long-lived daemon doesn't
// grow without limit. When exceeded the set is cleared (a connection may then
// re-emit once — acceptable).
const seenCap = 1 << 15

// pktapLineRe anchors a tcpdump pktap record line: a timestamp, then the
// parenthesized process metadata (possibly empty), then the packet. Anchoring
// at the start and capturing the metadata group strictly means we attribute
// only when the structure matches exactly — and notice when it doesn't (drift).
var pktapLineRe = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}\.\d+ \(([^)]*)\) (.*)$`)

// parseResult classifies a line so the caller can fail safe and measure drift.
type parseResult int

const (
	parseSkip         parseResult = iota // continuation/non-IP/legitimately-no-proc: ignore quietly
	parseOK                              // a fully attributed connection
	parseUnattributed                    // looked like an attributable record but no PID parsed → drift signal
)

// PktapSource observes per-process network activity via the system tcpdump on
// the pktap pseudo-interface. It parses each packet's text metadata (the only
// source that carries the kernel PID on macOS — see CLAUDE.md), normalizes
// endpoints to local/remote, and emits one Event per connection (deduped by
// 5-tuple).
//
// It runs inside the privileged daemon, so tcpdump inherits root — no sudo here.
type PktapSource struct {
	Path    string            // tcpdump path; defaults to the pinned system binary
	Now     func() time.Time  // defaults to time.Now
	IsLocal func(string) bool // reports whether an IP is one of ours; defaults to local interfaces

	seen         map[string]bool
	unattributed atomic.Int64
}

// Name implements Source.
func (s *PktapSource) Name() string { return "pktap" }

// Unattributed reports how many record lines looked like attributable
// connections but yielded no PID — a drift indicator, not a normal condition.
func (s *PktapSource) Unattributed() int64 { return s.unattributed.Load() }

// Run launches tcpdump and emits a deduped connection Event per new flow until
// ctx is cancelled or tcpdump exits.
func (s *PktapSource) Run(ctx context.Context, out chan<- Event) error {
	path := s.Path
	if path == "" {
		path = systemTcpdump
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.IsLocal == nil {
		local := LocalIPSet()
		s.IsLocal = func(ip string) bool { return local[ip] }
	}
	s.seen = map[string]bool{}

	// -i pktap,all : every interface with per-packet metadata
	// -k NP        : include process Name and PID metadata
	// -nn          : no name/port resolution (keep it numeric and fast)
	// -l           : line-buffered so we see packets promptly
	cmd := exec.CommandContext(ctx, path, "-i", "pktap,all", "-k", "NP", "-nn", "-l")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pktap: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("pktap: start tcpdump: %w", err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		ev, key, res := s.parseLine(sc.Text())
		switch res {
		case parseUnattributed:
			s.unattributed.Add(1)
		case parseOK:
			if s.seen[key] {
				continue
			}
			if len(s.seen) >= seenCap {
				s.seen = map[string]bool{}
			}
			s.seen[key] = true
			ev.TS = s.Now()
			select {
			case out <- ev:
			default: // never block capture
			}
		}
	}
	return cmd.Wait()
}

// parseLine strictly parses one tcpdump pktap line. It returns parseOK with an
// attributed Event, parseUnattributed for a record line that should have
// carried a PID but didn't (we never guess), or parseSkip for continuations,
// non-IP frames, and packets that legitimately have no process (empty "()").
func (s *PktapSource) parseLine(line string) (Event, string, parseResult) {
	// Continuation/hex-dump lines are indented; ignore quietly.
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return Event{}, "", parseSkip
	}

	m := pktapLineRe.FindStringSubmatch(line)
	if m == nil {
		// A record line (starts with a timestamp) that doesn't match our anchored
		// shape means the format may have drifted — fail safe and flag it.
		if isTimestamped(line) {
			return Event{}, "", parseUnattributed
		}
		return Event{}, "", parseSkip
	}
	meta, rest := m[1], m[2]

	nf, ipok := parseIPLine(rest, s.IsLocal)
	if !ipok {
		return Event{}, "", parseSkip // non-IP frame (ARP, ethertype, …): not ours
	}

	pid, proc, found := parseProcMeta(meta)
	if !found {
		if meta == "" {
			return Event{}, "", parseSkip // empty "()": kernel/outbound with no proc — legitimate
		}
		// Metadata was present but we couldn't extract a PID: drift.
		return Event{}, "", parseUnattributed
	}

	key := nf.Proto + "|" + strconv.Itoa(pid) + "|" + nf.Local + "|" + nf.Remote
	return Event{Op: OpConnect, PID: pid, Proc: proc, Net: &nf}, key, parseOK
}

// isTimestamped reports whether line begins HH:MM:SS.<frac> (a tcpdump record,
// as opposed to a hex-dump continuation).
func isTimestamped(line string) bool {
	return len(line) >= 12 && line[2] == ':' && line[5] == ':' && line[8] == '.'
}

// parseProcMeta extracts the attributing process from the metadata content
// (between the parentheses). eproc (the effective process) wins when present.
// found is false for empty or unparseable metadata.
func parseProcMeta(meta string) (pid int, proc string, found bool) {
	if meta == "" {
		return 0, "", false
	}
	procPid, eprocPid := -1, -1
	var procName, eprocName string
	for _, tok := range strings.Split(meta, ", ") {
		if name, ok := strings.CutPrefix(tok, "eproc "); ok {
			if n, p, ok := splitNamePID(name); ok {
				eprocName, eprocPid = n, p
			}
		} else if name, ok := strings.CutPrefix(tok, "proc "); ok {
			if n, p, ok := splitNamePID(name); ok {
				procName, procPid = n, p
			}
		}
	}
	if eprocPid >= 0 {
		return eprocPid, eprocName, true
	}
	if procPid >= 0 {
		return procPid, procName, true
	}
	return 0, "", false
}

// splitNamePID splits "Google Chrome He:1605" into name and pid, parsing the pid
// from the last colon so process names containing spaces survive intact.
func splitNamePID(s string) (name string, pid int, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], p, true
}

// parseIPLine parses the packet portion (after the metadata) into a normalized
// NetFlow. It accepts IPv4 ("IP ") and IPv6 ("IP6 "). ok is false for non-IP.
func parseIPLine(rest string, isLocal func(string) bool) (NetFlow, bool) {
	var payload string
	switch {
	case strings.HasPrefix(rest, "IP "):
		payload = rest[3:]
	case strings.HasPrefix(rest, "IP6 "):
		payload = rest[4:]
	default:
		return NetFlow{}, false
	}

	gt := strings.Index(payload, " > ")
	if gt < 0 {
		return NetFlow{}, false
	}
	aStr := payload[:gt]
	r := payload[gt+3:]
	var bStr, detail string
	if c := strings.Index(r, ": "); c >= 0 {
		bStr, detail = r[:c], r[c+2:]
	} else {
		bStr = strings.TrimRight(r, ":")
	}

	aHost, aPort, aok := splitDotPort(aStr)
	bHost, bPort, bok := splitDotPort(bStr)
	if !aok || !bok {
		return NetFlow{}, false
	}

	nf := NetFlow{Proto: "udp", Bytes: parseLength(detail)}
	if strings.Contains(detail, "Flags [") {
		nf.Proto = "tcp"
	}

	a := aHost + ":" + aPort
	b := bHost + ":" + bPort
	switch {
	case isLocal(aHost):
		nf.Dir, nf.Local, nf.Remote = "out", a, b
	case isLocal(bHost):
		nf.Dir, nf.Local, nf.Remote = "in", b, a
	default:
		nf.Local, nf.Remote = a, b // neither local: best effort
	}
	return nf, true
}

// splitDotPort splits "192.168.1.16.63188" (or an IPv6 "2603::1.443") into host
// and numeric port at the last dot.
func splitDotPort(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", "", false
	}
	if _, err := strconv.Atoi(s[i+1:]); err != nil {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// parseLength extracts the trailing "length N" byte count, or 0 if absent.
func parseLength(detail string) int {
	i := strings.LastIndex(detail, "length ")
	if i < 0 {
		return 0
	}
	field := detail[i+len("length "):]
	end := 0
	for end < len(field) && field[end] >= '0' && field[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(field[:end])
	return n
}

// LocalIPSet returns this host's IP addresses (plus loopback) for local/remote
// classification. Unprivileged.
func LocalIPSet() map[string]bool {
	set := map[string]bool{"127.0.0.1": true, "::1": true}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return set
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			set[ipnet.IP.String()] = true
		}
	}
	return set
}
