package protocol

import "encoding/json"

// MCP method names worth surfacing in Phase 1.
const (
	MethodInitialize = "initialize"
	MethodToolsList  = "tools/list"
	MethodToolsCall  = "tools/call"
	MethodRootsList  = "roots/list"
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

// ToolError reports whether a tools/call response carried an execution error.
// MCP conveys tool failures two ways: a JSON-RPC error object (a protocol-level
// failure, see Message.Error) or a *successful* response whose result has
// "isError": true (the tool ran but reported failure). This covers the latter,
// returning the first text content as the message. ok is false when the result
// isn't a failed tool call.
func (m Message) ToolError() (msg string, ok bool) {
	if m.Result == nil {
		return "", false
	}
	var r struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(m.Result, &r) != nil || !r.IsError {
		return "", false
	}
	for _, c := range r.Content {
		if c.Type == "text" && c.Text != "" {
			return c.Text, true
		}
	}
	return "", true
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

// Root is one entry of a roots/list result: a directory/URI the client exposes
// to the server.
type Root struct {
	URI  string `json:"uri"`
	Name string `json:"name,omitempty"`
}

// AsRootList decodes the roots array from a roots/list response result. ok is
// false if the message isn't a response carrying a roots list.
func (m Message) AsRootList() (roots []Root, ok bool) {
	if m.Result == nil {
		return nil, false
	}
	var res struct {
		Roots []Root `json:"roots"`
	}
	if err := json.Unmarshal(m.Result, &res); err != nil || res.Roots == nil {
		return nil, false
	}
	return res.Roots, true
}

// InitializeResult is the part of an initialize response worth surfacing.
type InitializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

// AsInitializeResult decodes an initialize response result. ok is false if the
// result doesn't look like one.
func (m Message) AsInitializeResult() (res InitializeResult, ok bool) {
	if m.Result == nil {
		return InitializeResult{}, false
	}
	if err := json.Unmarshal(m.Result, &res); err != nil || res.ProtocolVersion == "" {
		return InitializeResult{}, false
	}
	return res, true
}
