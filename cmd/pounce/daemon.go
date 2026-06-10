package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

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

	// Start the network capture source unless we lack privilege.
	if os.Geteuid() == 0 {
		srcCh := make(chan capture.Event, 1024)
		src := &capture.PktapSource{}
		go func() {
			if err := src.Run(ctx, srcCh); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "pounced: pktap source stopped: %v\n", err)
			}
		}()
		go mon.Run(ctx, srcCh)
		fmt.Fprintln(os.Stderr, "pounced: network capture active (pktap)")
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
		go handleConn(ctx, conn, mon, print)
	}
}

// handleConn services one shim session: verify the peer, read its registration,
// then stream attributed OS events back until the shim disconnects.
func handleConn(ctx context.Context, conn *net.UnixConn, mon *capture.Monitor, print bool) {
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

	// Stream attributed events back to the shim.
	done := make(chan struct{})
	go func() {
		defer close(done)
		enc := json.NewEncoder(conn)
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
