package capture

import (
	"context"
	"os"
	"testing"
)

func TestDescendants(t *testing.T) {
	// Tree:
	//   100
	//   ├── 200
	//   │   └── 400
	//   └── 300
	//   999 (unrelated)
	parent := map[int]int{
		200: 100,
		300: 100,
		400: 200,
		999: 1,
	}
	got := Descendants(100, parent)

	for _, pid := range []int{100, 200, 300, 400} {
		if !got[pid] {
			t.Errorf("expected %d in subtree", pid)
		}
	}
	if got[999] {
		t.Errorf("unrelated pid 999 should not be in subtree")
	}
	if len(got) != 4 {
		t.Errorf("subtree size = %d, want 4: %v", len(got), got)
	}
}

func TestDescendantsHandlesCycle(t *testing.T) {
	// A malformed snapshot with a cycle must not loop forever.
	parent := map[int]int{
		2: 1,
		1: 2, // cycle
		3: 1,
	}
	got := Descendants(1, parent)
	if !got[1] || !got[2] || !got[3] {
		t.Errorf("cycle not handled: %v", got)
	}
}

func TestSubtreeRefreshMonotonic(t *testing.T) {
	s := NewSubtree(100)
	if !s.Contains(100) {
		t.Fatal("root should be a member from the start")
	}

	s.Refresh(map[int]int{200: 100})
	if !s.Contains(200) {
		t.Fatal("200 should be a member after refresh")
	}

	// 200 leaves the process table; membership must persist (late events).
	s.Refresh(map[int]int{300: 100})
	if !s.Contains(200) {
		t.Error("membership should be monotonic; 200 dropped after it exited")
	}
	if !s.Contains(300) {
		t.Error("300 should be a member after second refresh")
	}
}

func TestParsePsOutput(t *testing.T) {
	in := []byte("  100   1\n  200 100\nbad line\n 300   100\n")
	parent, err := parsePsOutput(in)
	if err != nil {
		t.Fatal(err)
	}
	if parent[100] != 1 || parent[200] != 100 || parent[300] != 100 {
		t.Errorf("unexpected parse: %v", parent)
	}
	if len(parent) != 3 {
		t.Errorf("expected 3 entries, got %d: %v", len(parent), parent)
	}
}

// TestProcessSnapshotLive is a light integration check: our own process and its
// parent must appear in a real snapshot.
func TestProcessSnapshotLive(t *testing.T) {
	parent, err := ProcessSnapshot(context.Background())
	if err != nil {
		t.Skipf("ps unavailable: %v", err)
	}
	pid := os.Getpid()
	if _, ok := parent[pid]; !ok {
		t.Errorf("own pid %d not found in snapshot", pid)
	}
}
