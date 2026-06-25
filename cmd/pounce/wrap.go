package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"pounce/internal/intent"
	"pounce/internal/ipc"
	"pounce/internal/store"
	"pounce/internal/triggers"
)

// eventBuffer is how many observed messages can queue for the disk writer
// before the tee starts dropping log events. It is generous; dropping only ever
// loses a log entry, never a forwarded byte.
const eventBuffer = 4096

func newWrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wrap -- <command> [args...]",
		Short: "Run an MCP server through pounce, logging every JSON-RPC message",
		Long: `wrap launches the given command as a child process and transparently
forwards its stdio. A copy of every JSON-RPC message in each direction is parsed
and recorded to a session log, leaving the wrapped server's behavior unchanged.

Example:
  pounce wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("no command given; usage: pounce wrap -- <command> [args...]")
			}
			return runWrap(args)
		},
	}
	return cmd
}

func runWrap(args []string) error {
	start := time.Now()
	sessionID := store.NewID(start)

	w, err := store.Create(store.Header{
		ID:        sessionID,
		PounceVer: version,
		StartedAt: start,
		Command:   args[0],
		Args:      args[1:],
	})
	if err != nil {
		return fmt.Errorf("open session log: %w", err)
	}
	// pounce status goes to stderr only: stdout is the live protocol stream.
	fmt.Fprintf(os.Stderr, "pounce: recording session to %s\n", w.Path())

	// Cancel on SIGINT/SIGTERM so the child is asked to stop gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	src := &intent.StdioSource{Command: args}

	// When the child starts, best-effort register its PID subtree with the
	// capture daemon (if one is running) and stream OS events back into the log.
	// No daemon → this is a no-op and wrap behaves exactly as in Phase 1.
	var daemonConn *net.UnixConn
	var daemonReader sync.WaitGroup
	src.OnStart = func(pid int) {
		daemonConn = connectDaemon(sessionID, pid, w, &daemonReader)
	}

	// Drain observed events to disk on a separate goroutine so disk latency
	// never reaches the forwarding path.
	events := make(chan intent.Event, eventBuffer)
	var consumer sync.WaitGroup
	consumer.Add(1)
	var writeErrOnce sync.Once
	go func() {
		defer consumer.Done()
		for e := range events {
			if err := w.WriteEvent(e); err != nil {
				writeErrOnce.Do(func() {
					fmt.Fprintf(os.Stderr, "pounce: log write error (continuing): %v\n", err)
				})
			}
		}
	}()

	runErr := src.Run(ctx, events)
	close(events)
	consumer.Wait()

	// Stop the OS-event stream before closing the log: closing the connection
	// unblocks the reader goroutine, and we wait for it to finish draining any
	// already-received OS events — so none are written after the log is closed,
	// and learnSession reads a complete file.
	if daemonConn != nil {
		daemonConn.Close()
		daemonReader.Wait()
	}

	if err := w.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "pounce: closing session log: %v\n", err)
	}
	if d := src.Dropped(); d > 0 {
		fmt.Fprintf(os.Stderr, "pounce: dropped %d log events under load (forwarding was unaffected)\n", d)
	}

	// If capture was active, fold this completed session into the learned
	// per-(server, tool) baseline so later sessions can flag novel destinations
	// and tools that newly start egressing. Only when the daemon was attached:
	// without ground truth, "never egressed" would just mean "wasn't watching".
	if daemonConn != nil {
		learnSession(sessionID, w.Path())
	}

	return runErr
}

// learnSession folds a just-finished session's network behavior into the
// persisted per-(server, tool) profile. Best-effort: a failure here never
// affects the wrap's exit. (Concurrent wraps closing at once can race on the
// profile file — last write wins; a dropped update self-heals, since the missing
// destination is simply re-flagged as novel on its next visit.)
func learnSession(sessionID, path string) {
	s, err := store.Read(path)
	if err != nil {
		return
	}
	profile, err := triggers.LoadProfile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pounce: load learned baseline: %v\n", err)
	}
	rep := triggers.Evaluate(s, 0, profile)
	if profile.Learn(sessionID, rep) {
		if err := profile.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "pounce: update learned baseline: %v\n", err)
		}
	}
}

// connectDaemon makes a best-effort connection to the capture daemon, registers
// this session's root PID, and streams the OS events it sends back into the
// session log. It returns nil (and is silent) when no daemon is reachable, so a
// client-launched shim with no daemon behaves exactly as in Phase 1.
//
// The socket path can be overridden with POUNCE_SOCK (for testing).
func connectDaemon(sessionID string, pid int, w *store.Writer, rdr *sync.WaitGroup) *net.UnixConn {
	sock := os.Getenv("POUNCE_SOCK")
	if sock == "" {
		sock = ipc.DefaultSocket
	}
	conn, err := ipc.Dial(sock)
	if err != nil {
		return nil // no daemon — OS capture simply isn't available
	}
	enc := json.NewEncoder(conn)
	if err := enc.Encode(ipc.Message{Type: ipc.MsgRegister, SessionID: sessionID, RootPID: pid}); err != nil {
		conn.Close()
		return nil
	}
	fmt.Fprintf(os.Stderr, "pounce: capture daemon attached — recording OS activity for the server subtree\n")

	rdr.Add(1)
	go func() {
		defer rdr.Done()
		dec := json.NewDecoder(conn)
		for {
			var m ipc.Message
			if err := dec.Decode(&m); err != nil {
				return // connection closed
			}
			switch m.Type {
			case ipc.MsgOSEvent:
				if m.Event != nil {
					_ = w.WriteOSEvent(*m.Event)
				}
			case ipc.MsgCaptureInfo:
				if m.Capture != nil {
					_ = w.WriteCaptureInfo(store.CaptureInfo{
						Tcpdump: m.Capture.Tcpdump, OS: m.Capture.OS, Mode: m.Capture.Mode,
					})
				}
			}
		}
	}()
	return conn
}
