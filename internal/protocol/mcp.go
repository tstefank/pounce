package protocol

import "encoding/json"

// MCP method names worth surfacing in Phase 1.
const (
	MethodInitialize = "initialize"
	MethodToolsList  = "tools/list"
	MethodToolsCall  = "tools/call"
)

// ToolCall is the shape of a tools/call request's params.
type ToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// AsToolCall decodes the params of a tools/call request. ok is false if the
// message isn't a tools/call or the params don't decode.
func (m Message) AsToolCall() (tc ToolCall, ok bool) {
	if m.Method != MethodToolsCall || m.Params == nil {
		return ToolCall{}, false
	}
	if err := json.Unmarshal(m.Params, &tc); err != nil {
		return ToolCall{}, false
	}
	return tc, true
}

// Tool is one entry of a tools/list result.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// AsToolList decodes the tools array from a tools/list response result. ok is
// false if the message isn't a response carrying a tools list.
func (m Message) AsToolList() (tools []Tool, ok bool) {
	if m.Result == nil {
		return nil, false
	}
	var res struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(m.Result, &res); err != nil || res.Tools == nil {
		return nil, false
	}
	return res.Tools, true
}
