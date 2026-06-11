package capture

import "testing"

// localTest treats 192.168.1.16 (the capture host), a sample local IPv6, and
// loopback as local.
func localTest(ip string) bool {
	switch ip {
	case "192.168.1.16", "2603:1:1::5", "127.0.0.1", "::1":
		return true
	}
	return false
}

func TestParseLine_RealPktapSamples(t *testing.T) {
	src := &PktapSource{IsLocal: localTest}

	tests := []struct {
		name       string
		line       string
		want       parseResult
		wantPID    int
		wantProc   string
		wantProto  string
		wantRemote string
		wantDir    string
		wantBytes  int
	}{
		{
			name:       "inbound tcp, eproc wins over proc",
			line:       `21:43:24.993494 (proc kernel_task:0, eproc curl:32765) IP 172.66.147.243.443 > 192.168.1.16.63188: Flags [S.E], seq 1765589894, ack 277501804, win 65535, options [mss 1400], length 0`,
			want:       parseOK,
			wantPID:    32765,
			wantProc:   "curl",
			wantProto:  "tcp",
			wantRemote: "172.66.147.243:443",
			wantDir:    "in",
			wantBytes:  0,
		},
		{
			name:       "inbound tcp with payload length",
			line:       `21:43:25.010795 (proc kernel_task:0, eproc curl:32765) IP 172.66.147.243.443 > 192.168.1.16.63188: Flags [.], seq 1:1449, ack 322, win 16, options [nop,nop,TS val 4129970458 ecr 2674009348], length 1448`,
			want:       parseOK,
			wantPID:    32765,
			wantProc:   "curl",
			wantProto:  "tcp",
			wantRemote: "172.66.147.243:443",
			wantDir:    "in",
			wantBytes:  1448,
		},
		{
			name:       "process name with spaces, truncated",
			line:       `21:43:23.973558 (proc Google Chrome He:1605, eproc Google Chrome He:1605) IP 142.250.109.95.443 > 192.168.1.16.62596: Flags [.], ack 3229922463, win 536, options [nop,nop,TS val 3144225465 ecr 4293489110], length 0`,
			want:       parseOK,
			wantPID:    1605,
			wantProc:   "Google Chrome He",
			wantProto:  "tcp",
			wantRemote: "142.250.109.95:443",
			wantDir:    "in",
		},
		{
			name:       "udp dns response (no Flags -> udp)",
			line:       `21:43:24.976460 (proc mDNSResponder:638, eproc curl:32765) IP 192.168.1.1.53 > 192.168.1.16.59662: 26885 2/0/0 A 172.66.147.243, A 104.20.23.154 (61)`,
			want:       parseOK,
			wantPID:    32765,
			wantProc:   "curl",
			wantProto:  "udp",
			wantRemote: "192.168.1.1:53",
			wantDir:    "in",
		},
		{
			name: "empty metadata () -> skip (legit no proc)",
			line: `21:43:24.979108 () IP 192.168.1.16.63188 > 172.66.147.243.443: Flags [SEW], seq 277501803, win 65535, length 0`,
			want: parseSkip,
		},
		{
			name: "non-IP ethernet frame -> skip",
			line: `21:43:24.808356 () ec:be:dd:95:59:d0 > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x88e1), length 60:`,
			want: parseSkip,
		},
		{
			name: "hex-dump continuation line -> skip",
			line: `        0x0000:  0120 6000 0000 0000 0000 0000 0000 0000  ..` + "`" + `.............`,
			want: parseSkip,
		},
		{
			name: "metadata present but no parseable pid -> drift (unattributed)",
			line: `21:43:24.993494 (proc weird-no-colon, eproc also-bad) IP 172.66.147.243.443 > 192.168.1.16.63188: Flags [.], length 0`,
			want: parseUnattributed,
		},
		{
			name: "timestamped record we can't structure -> drift",
			line: `21:43:24.993494 something totally unexpected with no parens`,
			want: parseUnattributed,
		},
		{
			name:       "ipv6 inbound",
			line:       `21:43:24.993494 (eproc curl:32765) IP6 2606:4700::1.443 > 2603:1:1::5.51000: Flags [.], length 0`,
			want:       parseOK,
			wantPID:    32765,
			wantProc:   "curl",
			wantProto:  "tcp",
			wantRemote: "2606:4700::1:443",
			wantDir:    "in",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, _, res := src.parseLine(tt.line)
			if res != tt.want {
				t.Fatalf("result = %v, want %v", res, tt.want)
			}
			if tt.want != parseOK {
				return
			}
			if ev.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", ev.PID, tt.wantPID)
			}
			if ev.Proc != tt.wantProc {
				t.Errorf("Proc = %q, want %q", ev.Proc, tt.wantProc)
			}
			if ev.Net == nil {
				t.Fatal("Net is nil")
			}
			if ev.Net.Proto != tt.wantProto {
				t.Errorf("Proto = %q, want %q", ev.Net.Proto, tt.wantProto)
			}
			if ev.Net.Remote != tt.wantRemote {
				t.Errorf("Remote = %q, want %q", ev.Net.Remote, tt.wantRemote)
			}
			if tt.wantDir != "" && ev.Net.Dir != tt.wantDir {
				t.Errorf("Dir = %q, want %q", ev.Net.Dir, tt.wantDir)
			}
			if tt.wantBytes != 0 && ev.Net.Bytes != tt.wantBytes {
				t.Errorf("Bytes = %d, want %d", ev.Net.Bytes, tt.wantBytes)
			}
		})
	}
}

func TestParseLine_DedupKeyStableAcrossPackets(t *testing.T) {
	src := &PktapSource{IsLocal: localTest}
	l1 := `21:43:25.010795 (proc kernel_task:0, eproc curl:32765) IP 172.66.147.243.443 > 192.168.1.16.63188: Flags [.], seq 1:1449, ack 322, win 16, length 1448`
	l2 := `21:43:25.010796 (proc kernel_task:0, eproc curl:32765) IP 172.66.147.243.443 > 192.168.1.16.63188: Flags [.], seq 1449:2897, ack 322, win 16, length 1448`
	_, k1, r1 := src.parseLine(l1)
	_, k2, r2 := src.parseLine(l2)
	if r1 != parseOK || r2 != parseOK {
		t.Fatal("both lines should parse OK")
	}
	if k1 != k2 {
		t.Errorf("same connection produced different keys:\n %q\n %q", k1, k2)
	}
}

func TestSplitNamePID(t *testing.T) {
	n, p, ok := splitNamePID("Google Chrome He:1605")
	if !ok || n != "Google Chrome He" || p != 1605 {
		t.Errorf("got %q,%d,%v", n, p, ok)
	}
	if _, _, ok := splitNamePID("noColon"); ok {
		t.Error("expected failure without colon")
	}
}
