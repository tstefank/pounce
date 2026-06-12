// Command pounce wraps an MCP server and surfaces what it actually does.
//
// Phase 1: a transparent stdio tee. `pounce wrap -- <server cmd>` launches the
// real server, forwards stdio byte-for-byte, and logs every JSON-RPC message to
// a session file that `pounce view` can replay as a tool-call timeline.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// version is the pounce build version, recorded in session metadata.
const version = "0.2.0"

func main() {
	root := &cobra.Command{
		Use:           "pounce",
		Short:         "See what AI coding agents and MCP servers actually do",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newWrapCmd())
	root.AddCommand(newViewCmd())
	root.AddCommand(newDaemonCmd())

	if err := root.Execute(); err != nil {
		// If the wrapped child exited non-zero, mirror its exit code without
		// printing a pounce error — the child has already reported itself.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "pounce:", err)
		os.Exit(1)
	}
}
