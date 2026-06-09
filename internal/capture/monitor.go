package capture

import (
	"context"
	"sync"
	"time"
)

// defaultPollInterval is how often the Monitor re-samples the process table to
// keep subtree membership current. Network events carry their own PID, so this
// only governs how quickly a newly-spawned descendant is recognized.
const defaultPollInterval = 500 * time.Millisecond

// Monitor consumes system-wide events from one or more Sources and attributes
// each to the registered session(s) whose PID subtree contains the event's
// process. It is the daemon-side fan-out: one root capture stream, many shim
// sessions.
type Monitor struct {
	mu       sync.Mutex
	sessions map[string]*monSession

	// snapshot returns a pid->ppid map; overridable in tests. Defaults to
	// ProcessSnapshot.
	snapshot     func(context.Context) (map[int]int, error)
	pollInterval time.Duration
}

type monSession struct {
	id   string
	tree *Subtree
	out  chan<- Event
}

// NewMonitor creates an empty Monitor.
func NewMonitor() *Monitor {
	return &Monitor{
		sessions:     map[string]*monSession{},
		snapshot:     ProcessSnapshot,
		pollInterval: defaultPollInterval,
	}
}

// AddSession registers a session identified by id, rooted at rootPID. Attributed
// events are delivered to out. Membership is seeded immediately from a fresh
// process snapshot so events aren't missed before the first poll tick.
func (m *Monitor) AddSession(ctx context.Context, id string, rootPID int, out chan<- Event) {
	s := &monSession{id: id, tree: NewSubtree(rootPID), out: out}
	if parent, err := m.snapshot(ctx); err == nil {
		s.tree.Refresh(parent)
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
}

// RemoveSession unregisters a session. Its out channel is the caller's to close.
func (m *Monitor) RemoveSession(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// Run consumes events from in and routes them until ctx is cancelled or in is
// closed, periodically refreshing subtree membership. It returns ctx.Err() on
// cancellation, or nil when in closes.
func (m *Monitor) Run(ctx context.Context, in <-chan Event) error {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			m.refreshAll(ctx)
		case e, ok := <-in:
			if !ok {
				return nil
			}
			m.route(e)
		}
	}
}

// refreshAll re-samples the process table once and updates every session's tree.
func (m *Monitor) refreshAll(ctx context.Context) {
	parent, err := m.snapshot(ctx)
	if err != nil {
		return // transient; try again next tick
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		s.tree.Refresh(parent)
	}
}

// route delivers e to every session whose subtree contains e.PID. Delivery is
// non-blocking: if a session's channel is full the event is dropped rather than
// stalling capture (the same observe-only discipline as the protocol tee).
func (m *Monitor) route(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.tree.Contains(e.PID) {
			select {
			case s.out <- e:
			default:
			}
		}
	}
}
