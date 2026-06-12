// Package capture is the OS-capture core: it runs privileged observers
// (network via the system tcpdump on pktap; files/exec via eslogger, later) and
// attributes their system-wide events to a session's PID subtree.
//
// It is transport-agnostic and observe-only — it never blocks or alters the
// activity it watches. Per the privilege model (see CLAUDE.md), this package
// runs inside the privileged `pounced` daemon, never inside the unprivileged
// `pounce wrap` shim.
package capture

import "time"

// Op classifies an OS-level observation. Phase 2 starts with the network tier;
// file/exec ops join with the eslogger source.
type Op string

const (
	OpConnect Op = "connect" // a network packet/flow attributed to a process
	OpResolve Op = "resolve" // a DNS resolution: a host name mapped to IPs
)

// Resolve holds the host->IPs mapping of a DNS resolution, so the correlator can
// check whether a later connection's IP actually came from a declared host.
type Resolve struct {
	Host string   `json:"host,omitempty"`
	IPs  []string `json:"ips,omitempty"`
}

// NetFlow holds the network-tier details of an event, sourced from pktap
// per-packet metadata. Endpoints are normalized to local/remote (rather than
// src/dst as seen on the wire) so the destination of interest — the exfil
// target — is always Remote regardless of packet direction.
type NetFlow struct {
	Proto  string `json:"proto,omitempty"`  // "tcp" | "udp"
	Local  string `json:"local,omitempty"`  // local endpoint host:port
	Remote string `json:"remote,omitempty"` // remote endpoint host:port
	Dir    string `json:"dir,omitempty"`    // "out" | "in" | ""
	Bytes  int    `json:"bytes,omitempty"`  // packet length, if known
}

// Event is one OS-level observation, carrying the originating process so the
// Monitor can attribute it to a session by PID subtree. Raw preserves the
// source line for forensics and debugging.
type Event struct {
	TS      time.Time `json:"ts"`
	Op      Op        `json:"op"`
	PID     int       `json:"pid"`
	Proc    string    `json:"proc,omitempty"`    // process name from the source
	Net     *NetFlow  `json:"net,omitempty"`     // for OpConnect
	Resolve *Resolve  `json:"resolve,omitempty"` // for OpResolve
	Raw     string    `json:"raw,omitempty"`
}
