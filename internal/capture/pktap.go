package capture

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// systemTcpdump is the system tcpdump. The doc is explicit: use the system
// binary for pktap; a Homebrew build may lack pktap support.
const systemTcpdump = "/usr/sbin/tcpdump"

// seenCap bounds the per-connection dedup set so a long-lived daemon doesn't
// grow without limit. When exceeded the set is cleared (a connection may then
// re-emit once — acceptable).
const seenCap = 1 << 15

// PktapSource observes per-process network activity via the system tcpdump on
// the pktap pseudo-interface. It parses each packet, normalizes endpoints to
// local/remote, and emits one Event per connection (deduped by 5-tuple) so the
// timeline shows "process connected to remote", not every packet.
//
// It runs inside the privileged daemon, so tcpdump inherits root — no sudo here.
type PktapSource struct {
	Path    string            // tcpdump path; defaults to the system binary
	Now     func() time.Time  // defaults to time.Now
	IsLocal func(string) bool // reports whether an IP is one of ours; defaults to local interfaces
	seen    map[string]bool
}

// Name implements Source.
func (s *PktapSource) Name() string { return "pktap" }

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
		ev, key, ok := s.parseLine(sc.Text())
		if !ok || s.seen[key] {
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
	return cmd.Wait()
}

// parseLine parses one tcpdump pktap line (produced with -k NP). ok is false for
// lines that aren't attributable IP packets: hex-dump continuations, non-IP
// frames, and packets with no process metadata. key is the connection dedup key.
func (s *PktapSource) parseLine(line string) (ev Event, key string, ok bool) {
	// Continuation/hex-dump lines are indented; real records start with the
	// timestamp digit. Skip anything that doesn't.
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return Event{}, "", false
	}

	pid, proc, ok := parseProcMeta(line)
	if !ok {
		return Event{}, "", false // no attributable process (e.g. "()")
	}

	nf, ok := s.parsePacket(line)
	if !ok {
		return Event{}, "", false // non-IP frame
	}

	key = nf.Proto + "|" + strconv.Itoa(pid) + "|" + nf.Local + "|" + nf.Remote
	return Event{Op: OpConnect, PID: pid, Proc: proc, Net: &nf}, key, true
}

// parseProcMeta extracts the attributing process from the "(proc …, eproc …)"
// metadata group. eproc (the effective process) wins when present. ok is false
// when no process is named (an empty "()").
func parseProcMeta(line string) (pid int, proc string, ok bool) {
	lp := strings.IndexByte(line, '(')
	if lp < 0 {
		return 0, "", false
	}
	rp := strings.IndexByte(line[lp:], ')')
	if rp < 0 {
		return 0, "", false
	}
	meta := line[lp+1 : lp+rp]
	if meta == "" {
		return 0, "", false
	}

	procPid, eprocPid := -1, -1
	var procName, eprocName string
	for _, tok := range strings.Split(meta, ", ") {
		if name, found := strings.CutPrefix(tok, "eproc "); found {
			if n, p, ok := splitNamePID(name); ok {
				eprocName, eprocPid = n, p
			}
		} else if name, found := strings.CutPrefix(tok, "proc "); found {
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

// parsePacket parses the IP portion of a line into a normalized NetFlow. ok is
// false for non-IP frames (ARP, ethertype, etc.).
func (s *PktapSource) parsePacket(line string) (NetFlow, bool) {
	i := strings.Index(line, " IP ")
	if i < 0 {
		return NetFlow{}, false
	}
	pkt := line[i+4:] // "A > B: detail"
	gt := strings.Index(pkt, " > ")
	if gt < 0 {
		return NetFlow{}, false
	}
	aStr := pkt[:gt]
	rest := pkt[gt+3:]
	var bStr, detail string
	if c := strings.Index(rest, ": "); c >= 0 {
		bStr, detail = rest[:c], rest[c+2:]
	} else {
		bStr = strings.TrimRight(rest, ":")
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
	case s.IsLocal(aHost):
		nf.Dir, nf.Local, nf.Remote = "out", a, b
	case s.IsLocal(bHost):
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
