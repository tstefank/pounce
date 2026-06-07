package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tstefank/pounce/internal/store"
	"github.com/tstefank/pounce/internal/view"
)

func newViewCmd() *cobra.Command {
	var session string

	cmd := &cobra.Command{
		Use:   "view",
		Short: "Print the tool-call timeline from a session log",
		Long: `view reads a recorded session log and prints a timeline of JSON-RPC
activity, pairing each tool call with its response.

With no --session, the most recent session is shown.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runView(session)
		},
	}

	cmd.Flags().StringVar(&session, "session", "", "session id or path to a .jsonl log (default: most recent)")
	return cmd
}

func runView(session string) error {
	path, err := store.Resolve(session)
	if err != nil {
		return err
	}
	s, err := store.Read(path)
	if err != nil {
		return fmt.Errorf("read session %s: %w", path, err)
	}
	view.Timeline(os.Stdout, s)
	return nil
}
