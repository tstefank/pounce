package capture

import "context"

// Source produces system-wide OS events from one privileged observer (pktap
// now; eslogger later). It mirrors intent.Source: Run blocks until the observer
// exits or ctx is cancelled, emitting each parsed event to out. Sources do not
// know about sessions or subtrees — the Monitor attributes their output by PID.
//
// A source must never let a parse error stop the underlying observer; it records
// the error and keeps reading (same discipline as the protocol tee).
type Source interface {
	Name() string
	Run(ctx context.Context, out chan<- Event) error
}
