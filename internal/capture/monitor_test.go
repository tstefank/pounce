package capture

import (
	"context"
	"testing"
	"time"
)

func TestMonitorRoutesBySubtree(t *testing.T) {
	m := NewMonitor()
	// Static process table: 200 is a child of root 100; 999 is unrelated.
	m.snapshot = func(context.Context) (map[int]int, error) {
		return map[int]int{200: 100, 999: 1}, nil
	}

	out := make(chan Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.AddSession(ctx, "sess-1", 100, out)

	in := make(chan Event)
	go m.Run(ctx, in)

	// Event from a subtree member (200) is delivered.
	in <- Event{PID: 200, Op: OpConnect, Proc: "curl"}
	// Event from an unrelated process (999) is dropped.
	in <- Event{PID: 999, Op: OpConnect, Proc: "evil"}

	select {
	case e := <-out:
		if e.PID != 200 {
			t.Fatalf("routed wrong event: pid=%d", e.PID)
		}
	case <-time.After(time.Second):
		t.Fatal("expected the subtree event to be routed")
	}

	// Nothing else should arrive (the unrelated event was dropped).
	select {
	case e := <-out:
		t.Fatalf("unexpected event routed: pid=%d", e.PID)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestMonitorAncestryAttribution exercises the on-demand path: a PID that isn't
// yet in the subtree but whose ancestry (in the latest snapshot) reaches the
// session root must still be attributed and memoized.
func TestMonitorAncestryAttribution(t *testing.T) {
	m := NewMonitor()
	out := make(chan Event, 4)

	// Session rooted at 100; its tree currently holds only the root (no refresh
	// has expanded it). The snapshot knows 300 -> 200 -> 100.
	s := &monSession{id: "s", tree: NewSubtree(100), out: out}
	m.sessions["s"] = s
	m.lastParent = map[int]int{200: 100, 300: 200}

	m.route(Event{PID: 300, Op: OpConnect, Proc: "curl"})

	select {
	case e := <-out:
		if e.PID != 300 {
			t.Fatalf("attributed wrong pid %d", e.PID)
		}
	default:
		t.Fatal("event from descendant 300 was not attributed via ancestry")
	}
	if !s.tree.Contains(300) {
		t.Error("descendant 300 should be memoized into the subtree")
	}

	// An unrelated PID whose ancestry never reaches the root is not attributed.
	m.lastParent[900] = 1
	m.route(Event{PID: 900, Op: OpConnect})
	select {
	case e := <-out:
		t.Fatalf("unrelated pid %d should not be attributed", e.PID)
	default:
	}
}

func TestMonitorMultipleSessions(t *testing.T) {
	m := NewMonitor()
	m.snapshot = func(context.Context) (map[int]int, error) {
		return map[int]int{200: 100, 500: 400}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	outA := make(chan Event, 4)
	outB := make(chan Event, 4)
	m.AddSession(ctx, "A", 100, outA)
	m.AddSession(ctx, "B", 400, outB)

	in := make(chan Event)
	go m.Run(ctx, in)

	in <- Event{PID: 500, Op: OpConnect} // belongs to B's tree
	select {
	case e := <-outB:
		if e.PID != 500 {
			t.Fatalf("B got wrong pid %d", e.PID)
		}
	case <-time.After(time.Second):
		t.Fatal("B should have received pid 500")
	}
	select {
	case <-outA:
		t.Fatal("A should not receive B's event")
	case <-time.After(100 * time.Millisecond):
	}
}
