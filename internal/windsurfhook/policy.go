// Package windsurfhook evaluates Windsurf / Devin Desktop Cascade pre-hooks.
// Cascade blocks an action only when a pre-hook exits with code 2; every other
// outcome, including a missing evaluator, lets the action proceed.
package windsurfhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode"

	"github.com/ryandunton/agent-edict/internal/hookjson"
)

// PolicyLimit bounds the protected policy file read by each hook invocation.
const PolicyLimit = 256 * 1024

// Policy lists exact actions that may proceed. Empty lists block every
// command or MCP tool call reported to the registered hooks.
type Policy struct {
	Version  int       `json:"version" yaml:"version"`
	Commands []string  `json:"commands" yaml:"commands"`
	MCP      []MCPRule `json:"mcp" yaml:"mcp"`
}

// MCPRule matches Cascade's mcp_server_name label, which the user chooses.
// It is not an authenticated server identity.
type MCPRule struct {
	Server string   `json:"server" yaml:"server"`
	Tools  []string `json:"tools" yaml:"tools"`
}

// Events are the pre-hooks this policy registers.
var Events = []string{"pre_run_command", "pre_mcp_tool_use"}

// ErrBlocked reports a well-formed request that the policy does not allow.
var ErrBlocked = errors.New("action is not allowed by the AgentEdict policy")

func ValidatePolicy(p *Policy) error {
	if p == nil || p.Version != 1 {
		return errors.New("Windsurf hook policy version must be 1")
	}
	seen := map[string]bool{}
	for _, command := range p.Commands {
		if !validLiteral(command) || command == "*" || seen[command] {
			return errors.New("commands must be unique exact command lines without control characters")
		}
		seen[command] = true
	}
	servers := map[string]bool{}
	for _, rule := range p.MCP {
		if !validLiteral(rule.Server) || strings.ContainsAny(rule.Server, "*?") || servers[rule.Server] {
			return errors.New("MCP server names must be unique exact names")
		}
		servers[rule.Server] = true
		if len(rule.Tools) == 0 {
			return errors.New("MCP rules require explicit tool names")
		}
		tools := map[string]bool{}
		for _, tool := range rule.Tools {
			if !validLiteral(tool) || strings.ContainsAny(tool, "*?") || tools[tool] {
				return errors.New("MCP tool names must be unique exact names")
			}
			tools[tool] = true
		}
	}
	return nil
}

func validLiteral(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= 16384 && strings.IndexFunc(value, unicode.IsControl) < 0
}

// Evaluate returns nil when the action may proceed. ErrBlocked means the
// policy does not list it; any other error is a malformed policy or request.
// Callers must block on every error.
func Evaluate(event string, policyReader, inputReader io.Reader) error {
	if !slices.Contains(Events, event) {
		return errors.New("unsupported Windsurf hook event")
	}
	policyData, err := hookjson.ReadObject(policyReader, PolicyLimit)
	if err != nil {
		return errors.New("invalid Windsurf hook policy")
	}
	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(policyData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return errors.New("invalid Windsurf hook policy schema")
	}
	if err := ValidatePolicy(&policy); err != nil {
		return err
	}
	inputData, err := hookjson.ReadObject(inputReader, 1024*1024)
	if err != nil {
		return errors.New("invalid Windsurf hook input")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(inputData, &fields); err != nil {
		return errors.New("invalid Windsurf hook input schema")
	}
	if _, present := fields["agent_action_name"]; present {
		name, err := hookjson.StringField(fields, "agent_action_name", true)
		if err != nil || name != event {
			return errors.New("Windsurf hook event mismatch")
		}
	}
	var info map[string]json.RawMessage
	if json.Unmarshal(fields["tool_info"], &info) != nil || info == nil {
		return errors.New("Windsurf hook input requires a tool_info object")
	}
	if event == "pre_run_command" {
		command, err := hookjson.StringField(info, "command_line", true)
		if err != nil {
			return err
		}
		if slices.Contains(policy.Commands, command) {
			return nil
		}
		return ErrBlocked
	}
	server, err := hookjson.StringField(info, "mcp_server_name", true)
	if err != nil {
		return err
	}
	tool, err := hookjson.StringField(info, "mcp_tool_name", true)
	if err != nil {
		return err
	}
	for _, rule := range policy.MCP {
		if rule.Server == server && slices.Contains(rule.Tools, tool) {
			return nil
		}
	}
	return ErrBlocked
}
