package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"pounce/internal/intent"
	"pounce/internal/store"
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

	w, err := store.Create(store.Header{
		ID:        store.NewID(start),
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

	if err := w.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "pounce: closing session log: %v\n", err)
	}
	if d := src.Dropped(); d > 0 {
		fmt.Fprintf(os.Stderr, "pounce: dropped %d log events under load (forwarding was unaffected)\n", d)
	}

	return runErr
}
