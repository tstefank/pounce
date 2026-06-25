package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"pounce/internal/correlate"
	"pounce/internal/store"
	"pounce/internal/triggers"
	"pounce/internal/view"
)

func newViewCmd() *cobra.Command {
	var (
		session   string
		colorWhen string
		window    time.Duration
		timeline  bool
		all       bool
		limit     int
	)

	cmd := &cobra.Command{
		Use:   "view",
		Short: "Show what a wrapped session did: tool calls, the connections they caused, and divergence",
		Long: `view reads a recorded session log and, by default, prints a verdict-first
summary: each tool call with the connections it caused, labeled by the network
trigger rules — ⚠ alert (e.g. a local-only tool egressed, or a call connected
somewhere it didn't declare), ? to review (a novel or unnamed destination), ✓
expected — led by a one-line verdict.

With no --session, the most recent session is shown. --timeline prints the full
chronological protocol + OS log instead. --window tunes how long after a call a
connection still counts as caused by it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runView(session, colorWhen, window, timeline, all, limit)
		},
	}

	cmd.Flags().StringVar(&session, "session", "", "session id or path to a .jsonl log (default: most recent)")
	cmd.Flags().StringVar(&colorWhen, "color", "auto", "colorize output: auto|always|never")
	cmd.Flags().DurationVar(&window, "window", correlate.DefaultWindow, "correlation window: how long after a call a connection still counts as caused by it")
	cmd.Flags().BoolVar(&timeline, "timeline", false, "print the full chronological protocol + OS log instead of the summary")
	cmd.Flags().BoolVar(&all, "all", false, "show a one-line verdict for every recent session (overview of parallel servers)")
	cmd.Flags().IntVar(&limit, "limit", 25, "with --all, how many recent sessions to show")
	return cmd
}

func runView(session, colorWhen string, window time.Duration, timeline, all bool, limit int) error {
	color, err := resolveColor(colorWhen, os.Stdout)
	if err != nil {
		return err
	}

	// The learned per-(server, tool) baseline feeds the novelty / learned-egress
	// triggers. view is read-only: a missing or corrupt profile degrades to the
	// day-one rules (an empty, usable profile) rather than failing.
	profile, err := triggers.LoadProfile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pounce: %v (continuing without the learned baseline)\n", err)
	}
	if profile == nil {
		// LoadProfile only returns nil when the home dir can't be located; use an
		// empty profile so the day-one rules (incl. soft novelty) still apply
		// rather than silently disabling them.
		profile = triggers.NewProfile()
	}

	if all {
		sessions, err := store.RecentSessions(limit)
		if err != nil {
			return fmt.Errorf("list sessions: %w", err)
		}
		view.Roster(os.Stdout, sessions, color, window, profile)
		return nil
	}

	path, err := store.Resolve(session)
	if err != nil {
		return err
	}
	s, err := store.Read(path)
	if err != nil {
		return fmt.Errorf("read session %s: %w", path, err)
	}
	if timeline {
		view.Timeline(os.Stdout, s, color, window, profile)
	} else {
		view.Summary(os.Stdout, s, color, window, profile)
	}
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
