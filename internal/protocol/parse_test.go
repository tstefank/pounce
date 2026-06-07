package protocol

import (
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantLen  int
		wantErr  bool
		wantKind Kind   // checked against the first message when wantLen > 0
		wantID   string // IDKey of the first message
		wantMeth string
	}{
		{
			name:     "request with method and id",
			line:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`,
			wantLen:  1,
			wantKind: KindRequest,
			wantID:   "1",
			wantMeth: "tools/call",
		},
		{
			name:     "notification has method no id",
			line:     `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			wantLen:  1,
			wantKind: KindNotification,
			wantID:   "",
			wantMeth: "notifications/initialized",
		},
		{
			name:     "response with result",
			line:     `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
			wantLen:  1,
			wantKind: KindResponse,
			wantID:   "2",
		},
		{
			name:     "response with error",
			line:     `{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}}`,
			wantLen:  1,
			wantKind: KindResponse,
			wantID:   "3",
		},
		{
			name:     "string id",
			line:     `{"jsonrpc":"2.0","id":"abc","method":"initialize"}`,
			wantLen:  1,
			wantKind: KindRequest,
			wantID:   `"abc"`, // raw JSON token, kept distinct from numeric ids
			wantMeth: "initialize",
		},
		{
			name:     "null id is present (response to a null-id request)",
			line:     `{"jsonrpc":"2.0","id":null,"result":{}}`,
			wantLen:  1,
			wantKind: KindResponse,
			wantID:   "null",
		},
		{
			name:    "blank line yields nothing, no error",
			line:    "   ",
			wantLen: 0,
		},
		{
			name:    "empty line yields nothing, no error",
			line:    "",
			wantLen: 0,
		},
		{
			name:     "leading/trailing whitespace tolerated",
			line:     "   {\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}  ",
			wantLen:  1,
			wantKind: KindRequest,
			wantID:   "7",
			wantMeth: "ping",
		},
		{
			name:    "batch array of two messages",
			line:    `[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","method":"b"}]`,
			wantLen: 2,
			// first message classification checked below
			wantKind: KindRequest,
			wantID:   "1",
			wantMeth: "a",
		},
		{
			name:    "malformed json is an error",
			line:    `{"jsonrpc":"2.0",`,
			wantErr: true,
		},
		{
			name:    "non-json line is an error",
			line:    `hello world`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := ParseLine([]byte(tt.line))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (msgs=%v)", msgs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(msgs) != tt.wantLen {
				t.Fatalf("got %d messages, want %d", len(msgs), tt.wantLen)
			}
			if tt.wantLen == 0 {
				return
			}
			if got := msgs[0].Kind(); got != tt.wantKind {
				t.Errorf("Kind = %q, want %q", got, tt.wantKind)
			}
			if got := msgs[0].IDKey(); got != tt.wantID {
				t.Errorf("IDKey = %q, want %q", got, tt.wantID)
			}
			if tt.wantMeth != "" && msgs[0].Method != tt.wantMeth {
				t.Errorf("Method = %q, want %q", msgs[0].Method, tt.wantMeth)
			}
		})
	}
}

func TestIDKeyNormalizesWhitespace(t *testing.T) {
	a, _ := ParseLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"x"}`))
	b, _ := ParseLine([]byte(`{"jsonrpc":"2.0","id":  1 ,"result":{}}`))
	if a[0].IDKey() != b[0].IDKey() {
		t.Fatalf("ids should match: %q vs %q", a[0].IDKey(), b[0].IDKey())
	}
}

func TestAsToolCall(t *testing.T) {
	msgs, err := ParseLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	tc, ok := msgs[0].AsToolCall()
	if !ok {
		t.Fatal("expected AsToolCall ok")
	}
	if tc.Name != "read_file" {
		t.Errorf("name = %q, want read_file", tc.Name)
	}
	if !strings.Contains(string(tc.Arguments), "/etc/passwd") {
		t.Errorf("arguments missing path: %s", tc.Arguments)
	}

	// A non-tools/call message returns ok=false.
	other, _ := ParseLine([]byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`))
	if _, ok := other[0].AsToolCall(); ok {
		t.Error("ping should not parse as tool call")
	}
}

func TestAsToolList(t *testing.T) {
	msgs, err := ParseLine([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Read a file"},{"name":"write_file"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	tools, ok := msgs[0].AsToolList()
	if !ok {
		t.Fatal("expected AsToolList ok")
	}
	if len(tools) != 2 || tools[0].Name != "read_file" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
}

func TestParseLineLargeFrame(t *testing.T) {
	// A frame well over the default 64KB scanner token size must still parse.
	big := strings.Repeat("a", 200_000)
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"blob":"` + big + `"}}}`
	msgs, err := ParseLine([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if msgs[0].Method != "tools/call" {
		t.Fatalf("method = %q", msgs[0].Method)
	}
}
