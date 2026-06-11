package capture

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestLivePktapAttributesPID is the doc-mandated drift self-check: against real
// root capture it spawns a known connection (curl) and asserts the text parser
// extracts a PID. If a future tcpdump/macOS changes the metadata format, this
// fails — so the drift trips CI, not users.
//
// Skipped unless POUNCE_PKTAP_LIVE=1 and running as root (it spawns the system
// tcpdump on pktap). Intended for a privileged CI lane, run per macOS major:
//
//	sudo POUNCE_PKTAP_LIVE=1 go test ./internal/capture/ -run TestLivePktap -v
func TestLivePktapAttributesPID(t *testing.T) {
	if os.Getenv("POUNCE_PKTAP_LIVE") == "" {
		t.Skip("set POUNCE_PKTAP_LIVE=1 (run as root) for the live pktap drift self-check")
	}
	if os.Geteuid() != 0 {
		t.Skip("live pktap self-check needs root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	src := &PktapSource{}
	events := make(chan Event, 256)
	go func() { _ = src.Run(ctx, events) }()

	time.Sleep(700 * time.Millisecond) // let tcpdump attach
	go func() {
		_ = exec.CommandContext(ctx, "curl", "-s", "-o", "/dev/null", "https://example.com").Run()
	}()

	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.PID > 0 && e.Proc != "" && e.Net != nil && e.Net.Remote != "" {
				t.Logf("attributed live connection: %s pid=%d -> %s", e.Proc, e.PID, e.Net.Remote)
				return // the format still parses
			}
		case <-deadline:
			t.Fatalf("no attributed connection within deadline — possible tcpdump format drift (unattributed=%d)",
				src.Unattributed())
		}
	}
}
