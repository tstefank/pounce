package capture

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
)

// Subtree tracks the set of PIDs descended from a session's root process, so
// the Monitor can decide whether a system-wide OS event belongs to a session.
//
// The network tier maintains membership by periodically sampling the process
// table (via ProcessSnapshot) and recomputing descendants of the root PID. This
// is intentionally coarse: a process that spawns and exits between samples can
// be missed. Precise lineage requires the eslogger fork/exec stream (files
// tier); the doc accepts this degradation for the process-tree-only path.
type Subtree struct {
	root    int
	mu      sync.RWMutex
	members map[int]bool
}

// NewSubtree returns a tracker seeded with just the root PID.
func NewSubtree(root int) *Subtree {
	return &Subtree{root: root, members: map[int]bool{root: true}}
}

// Root returns the session's root PID.
func (s *Subtree) Root() int { return s.root }

// Contains reports whether pid is currently considered part of the subtree.
func (s *Subtree) Contains(pid int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.members[pid]
}

// Refresh recomputes membership from a parent map (pid -> ppid). Membership is
// monotonic within a session: once a PID has been seen as a member it stays a
// member, so a network event that arrives just after the process exits (and
// after it has left the process table) is still attributed correctly.
func (s *Subtree) Refresh(parent map[int]int) {
	desc := Descendants(s.root, parent)
	s.mu.Lock()
	defer s.mu.Unlock()
	for pid := range desc {
		s.members[pid] = true
	}
}

// Descendants returns the set containing root and all PIDs transitively
// parented by it, given a pid -> ppid map. Pure and table-testable.
func Descendants(root int, parent map[int]int) map[int]bool {
	children := map[int][]int{}
	for pid, ppid := range parent {
		children[ppid] = append(children[ppid], pid)
	}
	out := map[int]bool{root: true}
	stack := []int{root}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range children[p] {
			if !out[c] {
				out[c] = true
				stack = append(stack, c)
			}
		}
	}
	return out
}

// ProcessSnapshot returns a pid -> ppid map for all processes, via `ps`. It is
// unprivileged and dependency-light (no cgo, no x/sys); a sysctl/libproc
// implementation can replace it later without changing callers.
func ProcessSnapshot(ctx context.Context) (map[int]int, error) {
	out, err := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps snapshot: %w", err)
	}
	return parsePsOutput(out)
}

// parsePsOutput parses lines of "<pid> <ppid>" into a pid -> ppid map.
func parsePsOutput(b []byte) (map[int]int, error) {
	parent := map[int]int{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		fields := bytes.Fields(sc.Bytes())
		if len(fields) < 2 {
			continue
		}
		pid, err1 := strconv.Atoi(string(fields[0]))
		ppid, err2 := strconv.Atoi(string(fields[1]))
		if err1 != nil || err2 != nil {
			continue
		}
		parent[pid] = ppid
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return parent, nil
}
