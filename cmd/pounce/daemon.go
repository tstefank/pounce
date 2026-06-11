package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"pounce/internal/capture"
	"pounce/internal/ipc"
)

func newDaemonCmd() *cobra.Command {
	var (
		socket string
		print  bool
	)
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the privileged OS-capture daemon (pounced)",
		Long: `daemon runs the privileged capture core: it observes per-process network
activity (system tcpdump on pktap) and attributes it to the PID subtree of each
registered wrap session, streaming the results back over a local socket.

Run it once, as root:

  sudo pounce daemon

Network capture needs root but NOT Full Disk Access. Without root the daemon
still serves the socket but captures nothing (useful for testing the wiring).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(socket, print)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", ipc.DefaultSocket, "unix socket path")
	cmd.Flags().BoolVar(&print, "print", false, "also print attributed events to stderr")
	return cmd
}

func runDaemon(socket string, print bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mon := capture.NewMonitor()

	// capInfo is non-nil only when capture is actually active, so the session
	// log records provenance only for sessions whose OS events are real.
	var capInfo *ipc.CaptureInfo

	// Start the network capture source unless we lack privilege.
	if os.Geteuid() == 0 {
		srcCh := make(chan capture.Event, 1024)
		src := &capture.PktapSource{}
		go func() {
			err := src.Run(ctx, srcCh)
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "pounced: pktap source stopped: %v\n", err)
			}
			if n := src.Unattributed(); n > 0 {
				fmt.Fprintf(os.Stderr, "pounced: %d record lines could not be attributed (possible tcpdump format drift)\n", n)
			}
		}()
		go mon.Run(ctx, srcCh)
		info := captureProvenance()
		capInfo = &info
		fmt.Fprintf(os.Stderr, "pounced: network capture active (pktap); %s on %s\n", info.Tcpdump, info.OS)
	} else {
		fmt.Fprintln(os.Stderr, "pounced: not root — capturing nothing; socket-only (run via `sudo pounce daemon` for capture)")
		go mon.Run(ctx, make(chan capture.Event)) // keeps the poll ticker alive
	}

	ln, err := ipc.Listen(socket)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socket, err)
	}
	defer os.Remove(socket)
	fmt.Fprintf(os.Stderr, "pounced: listening on %s\n", socket)

	// Close the listener on shutdown to unblock Accept.
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			fmt.Fprintf(os.Stderr, "pounced: accept: %v\n", err)
			continue
		}
		go handleConn(ctx, conn, mon, capInfo, print)
	}
}

// handleConn services one shim session: verify the peer, read its registration,
// then stream attributed OS events back until the shim disconnects.
func handleConn(ctx context.Context, conn *net.UnixConn, mon *capture.Monitor, capInfo *ipc.CaptureInfo, print bool) {
	defer conn.Close()

	peer, err := ipc.PeerCred(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pounced: rejecting connection, peer-cred failed: %v\n", err)
		return
	}

	dec := json.NewDecoder(conn)
	var reg ipc.Message
	if err := dec.Decode(&reg); err != nil || reg.Type != ipc.MsgRegister || reg.SessionID == "" || reg.RootPID <= 0 {
		fmt.Fprintf(os.Stderr, "pounced: bad registration from uid=%d pid=%d: %v\n", peer.UID, peer.PID, err)
		return
	}
	fmt.Fprintf(os.Stderr, "pounced: session %s registered (root pid %d, peer uid=%d pid=%d)\n",
		reg.SessionID, reg.RootPID, peer.UID, peer.PID)

	out := make(chan capture.Event, 256)
	mon.AddSession(ctx, reg.SessionID, reg.RootPID, out)

	enc := json.NewEncoder(conn)
	// Send capture provenance first (sequentially, before the event writer
	// goroutine starts using enc) so the shim can record it in the session log.
	if capInfo != nil {
		_ = enc.Encode(ipc.Message{Type: ipc.MsgCaptureInfo, Capture: capInfo})
	}

	// Stream attributed events back to the shim.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range out {
			if print {
				fmt.Fprintf(os.Stderr, "pounced[%s]: %s pid=%d %s %s->%s\n",
					reg.SessionID, ev.Op, ev.PID, netProto(ev), netLocal(ev), netRemote(ev))
			}
			if err := enc.Encode(ipc.Message{Type: ipc.MsgOSEvent, Event: &ev}); err != nil {
				return // shim went away
			}
		}
	}()

	// Block until the shim disconnects (any read error / EOF), then tear down.
	// Order matters: stop the monitor routing to out (RemoveSession) BEFORE
	// closing out, or route() could send on a closed channel.
	for {
		var ignored ipc.Message
		if err := dec.Decode(&ignored); err != nil {
			break
		}
	}
	mon.RemoveSession(reg.SessionID)
	close(out)
	<-done
	if !errors.Is(ctx.Err(), context.Canceled) {
		fmt.Fprintf(os.Stderr, "pounced: session %s ended\n", reg.SessionID)
	}
}

// captureProvenance records what produced the OS events, so a later tcpdump or
// macOS change that breaks parsing is diagnosable from the session log.
func captureProvenance() ipc.CaptureInfo {
	return ipc.CaptureInfo{
		Tcpdump: tcpdumpVersion(),
		OS:      osVersion(),
		Mode:    "pktap text -k NP",
	}
}

// tcpdumpVersion returns the first line of `tcpdump --version`, or "unknown".
func tcpdumpVersion() string {
	out, err := exec.Command("/usr/sbin/tcpdump", "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	line := string(out)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// osVersion returns the macOS product version, e.g. "macOS 26.5.1".
func osVersion() string {
	v, err := unix.Sysctl("kern.osproductversion")
	if err != nil || v == "" {
		return "macOS"
	}
	return "macOS " + v
}

// small helpers for the --print line; tolerate nil Net.
func netProto(e capture.Event) string {
	if e.Net != nil {
		return e.Net.Proto
	}
	return ""
}
func netLocal(e capture.Event) string {
	if e.Net != nil {
		return e.Net.Local
	}
	return ""
}
func netRemote(e capture.Event) string {
	if e.Net != nil {
		return e.Net.Remote
	}
	return ""
}
