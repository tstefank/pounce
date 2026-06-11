// Package ipc is the local-socket protocol between the unprivileged `pounce
// wrap` shim and the privileged `pounced` daemon.
//
// The shim connects, registers its session (id + root PID), then reads a stream
// of attributed OS events the daemon sends back for that session. Messages are
// newline-delimited JSON (json.Encoder/Decoder handle framing). The daemon
// verifies peer credentials on every connection (see PeerCred) — it is a root
// process accepting input from unprivileged callers.
package ipc

import (
	"net"
	"os"

	"pounce/internal/capture"
)

// DefaultSocket is the daemon's well-known socket path. The daemon (root)
// creates it; the shim connects to it.
const DefaultSocket = "/var/run/pounce.sock"

// MsgType discriminates protocol messages.
type MsgType string

const (
	// MsgRegister: shim -> daemon, once, first. Carries SessionID + RootPID.
	MsgRegister MsgType = "register"
	// MsgOSEvent: daemon -> shim, streamed. Carries one attributed Event.
	MsgOSEvent MsgType = "osevent"
	// MsgCaptureInfo: daemon -> shim, once after register. Capture provenance.
	MsgCaptureInfo MsgType = "capture_info"
)

// CaptureInfo records how OS events were captured, for the session log — so a
// later format/tooling drift is diagnosable.
type CaptureInfo struct {
	Tcpdump string `json:"tcpdump,omitempty"` // system tcpdump --version
	OS      string `json:"os,omitempty"`      // macOS product version
	Mode    string `json:"mode,omitempty"`    // capture mechanism, e.g. "pktap text -k NP"
}

// Message is one line on the wire.
type Message struct {
	Type      MsgType        `json:"type"`
	SessionID string         `json:"session_id,omitempty"`
	RootPID   int            `json:"root_pid,omitempty"`
	Event     *capture.Event `json:"event,omitempty"`
	Capture   *CaptureInfo   `json:"capture,omitempty"`
}

// Listen creates the daemon's Unix socket, removing any stale one, and makes it
// connectable by unprivileged clients (peer-cred verification is the real gate,
// not file permissions).
func Listen(path string) (*net.UnixListener, error) {
	_ = os.Remove(path)
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	// 0666 so a non-root shim can connect; PeerCred gates who is trusted.
	_ = os.Chmod(path, 0o666)
	return ln, nil
}

// Dial connects to the daemon socket.
func Dial(path string) (*net.UnixConn, error) {
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	return net.DialUnix("unix", nil, addr)
}
