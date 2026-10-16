// Package mcpwire holds the small slice of MCP / JSON-RPC 2.0 wire handling
// the gateway needs: parsing an inbound message far enough to make a policy
// decision, and building JSON-RPC error responses.
//
// It deliberately does not depend on an MCP SDK. The gateway is a protocol
// proxy, so it only needs to understand the envelope, not every message type.
package mcpwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Header names from the MCP streamable HTTP transport. Since protocol version
// 2026-07-28 clients mirror the method and target name into headers so that
// intermediaries can route without parsing the body (SEP-2243).
const (
	HeaderSessionID       = "Mcp-Session-Id"
	HeaderProtocolVersion = "Mcp-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
	HeaderParamPrefix     = "Mcp-Param-"
)

// Gateway-specific JSON-RPC error codes, inside the implementation-defined
// server error range (-32000 to -32099), chosen to avoid the codes MCP SDKs
// already use (-32001 to -32005, -32002, -32020 to -32022, -32042).
const (
	CodeForbidden   = -32030 // the agent's policy does not allow this tool
	CodeRateLimited = -32029 // the agent exceeded its rate limit for this tool
	CodeUpstream    = -32050 // the tool server could not be reached
	// CodeHeaderMismatch is MCP's own code for Mcp-* headers that disagree
	// with the JSON-RPC body.
	CodeHeaderMismatch = -32020
)

const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
)

// Message is the parsed envelope of a single inbound JSON-RPC message.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	// Result and Error are set when the client posts a response (for example
	// to an elicitation request from the server).
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`

	// Derived fields.
	ToolName  string            // params.name for tools/call
	Arguments json.RawMessage   // params.arguments for tools/call
	Meta      map[string]string // string values from params._meta (trace context lives here)
}

// IsRequest reports whether the message expects a response.
func (m *Message) IsRequest() bool {
	return m.Method != "" && len(m.ID) > 0 && !bytes.Equal(m.ID, []byte("null"))
}

// ErrBatch is returned for JSON-RPC batches. MCP removed batching in protocol
// version 2025-06-18, and a gateway that has to decide per call is simpler
// and safer if it refuses them outright.
var ErrBatch = errors.New("JSON-RPC batches are not supported")

// Parse decodes a single JSON-RPC message from body.
func Parse(body []byte) (*Message, error) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	if trimmed[0] == '[' {
		return nil, ErrBatch
	}
	var m Message
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC message: %w", err)
	}
	if m.JSONRPC != "2.0" {
		return nil, errors.New(`jsonrpc must be "2.0"`)
	}
	if len(m.Params) > 0 && m.Params[0] == '{' {
		var p struct {
			Name      string                     `json:"name"`
			Arguments json.RawMessage            `json:"arguments"`
			Meta      map[string]json.RawMessage `json:"_meta"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if m.Method == "tools/call" {
			m.ToolName = p.Name
			m.Arguments = p.Arguments
		}
		for k, v := range p.Meta {
			var s string
			if json.Unmarshal(v, &s) == nil {
				if m.Meta == nil {
					m.Meta = map[string]string{}
				}
				m.Meta[k] = s
			}
		}
	}
	if m.Method == "tools/call" && m.ToolName == "" {
		return nil, errors.New("tools/call without params.name")
	}
	return &m, nil
}

// ErrorResponse builds a JSON-RPC error response for the given request id.
func ErrorResponse(id json.RawMessage, code int, message string, data any) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	type rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    any    `json:"data,omitempty"`
	}
	out, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcErr          `json:"error"`
	}{"2.0", id, rpcErr{code, message, data}})
	return out
}

// Outcome classifies a JSON-RPC response sent back by a tool server.
type Outcome string

const (
	OutcomeOK        Outcome = "ok"
	OutcomeToolError Outcome = "tool_error" // result.isError == true
	OutcomeRPCError  Outcome = "rpc_error"  // a JSON-RPC error object
	OutcomeUnknown   Outcome = "unknown"
)

// ClassifyResponse inspects a single JSON-RPC response message and reports
// whether it matches id and what the outcome was.
func ClassifyResponse(msg []byte, id json.RawMessage) (matched bool, outcome Outcome) {
	var r struct {
		ID     json.RawMessage `json:"id"`
		Result *struct {
			IsError bool `json:"isError"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(msg, &r) != nil || len(r.ID) == 0 || !bytes.Equal(compact(r.ID), compact(id)) {
		return false, OutcomeUnknown
	}
	switch {
	case len(r.Error) > 0 && !bytes.Equal(r.Error, []byte("null")):
		return true, OutcomeRPCError
	case r.Result != nil && r.Result.IsError:
		return true, OutcomeToolError
	case r.Result != nil:
		return true, OutcomeOK
	}
	return true, OutcomeUnknown
}

func compact(b json.RawMessage) []byte {
	var buf bytes.Buffer
	if json.Compact(&buf, b) != nil {
		return b
	}
	return buf.Bytes()
}
