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
