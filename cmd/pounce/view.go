package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"pounce/internal/correlate"
	"pounce/internal/store"
	"pounce/internal/view"
)

func newViewCmd() *cobra.Command {
	var (
		session   string
		colorWhen string
		window    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "view",
		Short: "Print the tool-call timeline from a session log",
		Long: `view reads a recorded session log and prints a timeline of JSON-RPC
activity, pairing each tool call with its response.

With no --session, the most recent session is shown. When OS events were
captured, a correlation section ties each tool call to the connections it caused
and flags out-of-band ones; --window tunes how long after a call a connection
still counts as caused by it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runView(session, colorWhen, window)
		},
	}

	cmd.Flags().StringVar(&session, "session", "", "session id or path to a .jsonl log (default: most recent)")
	cmd.Flags().StringVar(&colorWhen, "color", "auto", "colorize output: auto|always|never")
	cmd.Flags().DurationVar(&window, "window", correlate.DefaultWindow, "correlation window: how long after a call a connection still counts as caused by it")
	return cmd
}

func runView(session, colorWhen string, window time.Duration) error {
	path, err := store.Resolve(session)
	if err != nil {
		return err
	}
	s, err := store.Read(path)
	if err != nil {
		return fmt.Errorf("read session %s: %w", path, err)
	}
	color, err := resolveColor(colorWhen, os.Stdout)
	if err != nil {
		return err
	}
	view.Timeline(os.Stdout, s, color, window)
	return nil
}

// resolveColor decides whether to emit ANSI color, honoring the --color flag,
// the NO_COLOR convention (https://no-color.org), TERM=dumb, and whether the
// output is an interactive terminal.
func resolveColor(when string, out *os.File) (bool, error) {
	switch when {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto", "":
		if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
			return false, nil
		}
		return isTerminal(out), nil
	default:
		return false, fmt.Errorf("invalid --color %q: want auto, always, or never", when)
	}
}

// isTerminal reports whether f is an interactive character device (a TTY),
// using only the standard library.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
