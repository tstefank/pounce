package intent

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"pounce/internal/protocol"
)

// maxFrameBytes caps how much we buffer for a single un-terminated frame before
// giving up on it. MCP frames have no embedded newlines and are small in
// practice; this only guards against a pathological stream and never affects
// the forwarded bytes.
const maxFrameBytes = 16 << 20 // 16 MiB

// Clock returns the current time; injectable for tests.
type Clock func() time.Time

// StdioSource is the first intent source: it launches an MCP server as a child
// process and transparently tees its newline-delimited JSON-RPC stdio.
//
// The forwarded bytes between client and server are identical to an un-wrapped
// run — pounce only ever inspects a copy. stderr passes through untouched. An
// observation error (parse failure, full event channel) is recorded and
// forwarding continues; pounce never takes the server down.
type StdioSource struct {
	// Command is the server command and its arguments (Command[0] is the exe).
	Command []string

	// In, Out, Err default to the process's own stdio when nil. They exist so
	// tests can drive the source with in-memory pipes.
	In  io.Reader
	Out io.Writer
	Err io.Writer

	// Now defaults to time.Now.
	Now Clock

	// OnStart, if set, is called once with the child's PID immediately after the
	// process starts. The wrap command uses it to register the PID subtree with
	// the capture daemon while the server runs.
	OnStart func(pid int)

	cmd     *exec.Cmd
	dropped atomic.Int64
}

// Name implements Source.
func (s *StdioSource) Name() string { return "stdio" }

// Cmd returns the underlying child command (valid after Run starts it). Used by
// the caller to read the exit code.
func (s *StdioSource) Cmd() *exec.Cmd { return s.cmd }

// Dropped reports how many observed messages were dropped because the event
// channel was full. Forwarding is never affected; only the log loses entries.
func (s *StdioSource) Dropped() int64 { return s.dropped.Load() }

// Run launches the child and tees both stdio directions to out until the child
// exits or ctx is cancelled. It returns the child's exit error (an
// *exec.ExitError carries the code), or a setup error.
func (s *StdioSource) Run(ctx context.Context, out chan<- Event) error {
	if len(s.Command) == 0 {
		return errors.New("stdio: empty command")
	}
	in := cmp.Or[io.Reader](s.In, os.Stdin)
	stdout := cmp.Or[io.Writer](s.Out, os.Stdout)
	stderr := cmp.Or[io.Writer](s.Err, os.Stderr)
	now := s.Now
	if now == nil {
		now = time.Now
	}

	cmd := exec.CommandContext(ctx, s.Command[0], s.Command[1:]...)
	cmd.Stderr = stderr // untouched passthrough
	// Graceful stop on ctx cancel: SIGTERM, then SIGKILL after a grace period.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdio: stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdio: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("stdio: start %q: %w", s.Command[0], err)
	}
	s.cmd = cmd
	if s.OnStart != nil {
		s.OnStart(cmd.Process.Pid)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// client -> server: copy in -> serverIn, teeing a copy to the splitter.
	// io.TeeReader writes to the splitter before the byte reaches serverIn, so
	// the splitter must never block; lineSplitter guarantees that.
	go func() {
		defer wg.Done()
		sp := newLineSplitter(s, ClientToServer, now, out)
		_, _ = io.Copy(serverIn, io.TeeReader(in, sp))
		sp.flush()
		// Client closed its stdin: propagate EOF to the server.
		_ = serverIn.Close()
	}()

	// server -> client: copy serverOut -> stdout, teeing a copy to the splitter.
	go func() {
		defer wg.Done()
		sp := newLineSplitter(s, ServerToClient, now, out)
		_, _ = io.Copy(stdout, io.TeeReader(serverOut, sp))
		sp.flush()
	}()

	wg.Wait()
	return cmd.Wait()
}

// emit performs a non-blocking send of an Event. If out is full it drops the
// event and increments the drop counter rather than blocking the tee (which
// would delay the forwarded stream).
func (s *StdioSource) emit(out chan<- Event, e Event) {
	select {
	case out <- e:
	default:
		s.dropped.Add(1)
	}
}

// lineSplitter is an io.Writer that accumulates teed bytes, splits them on
// newlines, parses each complete frame, and emits an Event per message. Write
// never blocks on I/O: parsing is synchronous and the send is non-blocking.
type lineSplitter struct {
	src  *StdioSource
	dir  Direction
	now  Clock
	out  chan<- Event
	buf  bytes.Buffer
	over bool // current frame exceeded maxFrameBytes; skip until next newline
}

func newLineSplitter(src *StdioSource, dir Direction, now Clock, out chan<- Event) *lineSplitter {
	return &lineSplitter{src: src, dir: dir, now: now, out: out}
}

// Write implements io.Writer. It always reports the full length as written and
// returns no error, so it can never interrupt the forwarding copy.
func (l *lineSplitter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			l.append(p)
			break
		}
		l.append(p[:i])
		l.emitFrame()
		p = p[i+1:]
	}
	return n, nil
}

// append adds bytes to the current frame buffer, honoring the size cap.
func (l *lineSplitter) append(b []byte) {
	if l.over {
		return
	}
	if l.buf.Len()+len(b) > maxFrameBytes {
		l.over = true
		l.buf.Reset()
		return
	}
	l.buf.Write(b)
}

// emitFrame parses the buffered frame and emits an Event, then resets the buffer.
func (l *lineSplitter) emitFrame() {
	defer l.buf.Reset()

	if l.over {
		// We discarded an oversized frame; record that we saw something.
		l.over = false
		l.src.emit(l.out, Event{
			TS:       l.now(),
			Source:   "stdio",
			Dir:      l.dir,
			ParseErr: fmt.Sprintf("frame exceeded %d bytes; not recorded", maxFrameBytes),
		})
		return
	}

	frame := bytes.TrimSpace(l.buf.Bytes())
	if len(frame) == 0 {
		return
	}

	msgs, err := protocol.ParseLine(frame)
	if err != nil {
		// Copy the bytes out of the buffer (it's about to be reset).
		l.src.emit(l.out, Event{
			TS:       l.now(),
			Source:   "stdio",
			Dir:      l.dir,
			RawText:  string(frame),
			ParseErr: err.Error(),
		})
		return
	}
	for i := range msgs {
		m := msgs[i]
		l.src.emit(l.out, Event{
			TS:     l.now(),
			Source: "stdio",
			Dir:    l.dir,
			Raw:    rawFor(frame, msgs, i),
			Msg:    &m,
		})
	}
}

// rawFor returns the JSON to store as an event's Raw. For the common
// single-message frame it is the exact frame bytes (detached from the buffer).
// For a legacy batch array it is that one message re-encoded on its own, so the
// stored copy round-trips to the right message — store.Read reconstructs each
// event's Msg from its Raw, and the whole-array frame would otherwise collapse
// every batch element back to the first. Re-encoding our own copy is fine; only
// the *forwarded* stream must never be re-serialized.
func rawFor(frame []byte, msgs []protocol.Message, i int) []byte {
	if len(msgs) == 1 {
		return append([]byte(nil), frame...)
	}
	if b, err := json.Marshal(msgs[i]); err == nil {
		return b
	}
	// Fall back to the whole frame if re-encoding somehow fails; never drop it.
	return append([]byte(nil), frame...)
}

// flush emits any trailing bytes that arrived without a terminating newline
// (e.g. the stream ended mid-frame).
func (l *lineSplitter) flush() {
	if l.over || l.buf.Len() > 0 {
		l.emitFrame()
	}
}
