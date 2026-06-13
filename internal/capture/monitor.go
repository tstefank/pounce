package capture

import (
	"context"
	"sync"
	"time"
)

// defaultPollInterval is how often the Monitor re-samples the process table to
// keep subtree membership current. Network events carry their own PID, so this
// governs how quickly a newly-spawned descendant is recognized — and, because
// short-lived processes (a quick curl) can live and die between samples, how
// reliably we attribute them at all. Kept short for the network tier; precise
// lineage will come from the eslogger fork stream (files tier).
const defaultPollInterval = 100 * time.Millisecond

// Monitor consumes system-wide events from one or more Sources and attributes
// each to the registered session(s) whose PID subtree contains the event's
// process. It is the daemon-side fan-out: one root capture stream, many shim
// sessions.
type Monitor struct {
	mu       sync.Mutex
	sessions map[string]*monSession

	// lastParent is the most recent pid->ppid snapshot, used for on-demand
	// ancestry attribution between polls. Guarded by mu.
	lastParent map[int]int

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
		lastParent:   map[int]int{},
		snapshot:     ProcessSnapshot,
		pollInterval: defaultPollInterval,
	}
}

// AddSession registers a session identified by id, rooted at rootPID. Attributed
// events are delivered to out. Membership is seeded immediately from a fresh
// process snapshot so events aren't missed before the first poll tick.
func (m *Monitor) AddSession(ctx context.Context, id string, rootPID int, out chan<- Event) {
	s := &monSession{id: id, tree: NewSubtree(rootPID), out: out}
	parent, err := m.snapshot(ctx)
	if err == nil {
		s.tree.Refresh(parent)
	}
	m.mu.Lock()
	m.sessions[id] = s
	if err == nil {
		m.lastParent = parent
	}
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
	m.lastParent = parent
	for _, s := range m.sessions {
		s.tree.Refresh(parent)
	}
}

// route delivers e to the appropriate session(s). A connection is owned by a
// process, so it goes to the session whose subtree contains its PID. A DNS
// resolution is shared system knowledge (the host→IP fact isn't owned by the
// process that happened to ask, and the resolver is often mDNSResponder), so it
// is broadcast to every session — a connection can then be explained regardless
// of which process did the lookup. Delivery is non-blocking (observe-only).
func (m *Monitor) route(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.Op == OpResolve {
		for _, s := range m.sessions {
			select {
			case s.out <- e:
			default:
			}
		}
		return
	}
	if s := m.sessionForPIDLocked(e.PID); s != nil {
		select {
		case s.out <- e:
		default:
		}
	}
}

// sessionForPIDLocked finds the session that owns pid. It first checks current
// subtree membership, then — to catch a short-lived process that spawned and
// connected between polls — walks pid's ancestry in the latest process snapshot
// looking for a session root. A match is memoized into that session's subtree.
// Caller must hold m.mu.
func (m *Monitor) sessionForPIDLocked(pid int) *monSession {
	for _, s := range m.sessions {
		if s.tree.Contains(pid) {
			return s
		}
	}
	cur := pid
	for i := 0; i < 64; i++ {
		ppid, ok := m.lastParent[cur]
		if !ok {
			break // cur not in the snapshot (already exited, or unknown)
		}
		for _, s := range m.sessions {
			if s.tree.Contains(ppid) {
				s.tree.Add(pid)
				return s
			}
		}
		if ppid <= 1 || ppid == cur {
			break
		}
		cur = ppid
	}
	return nil
}
