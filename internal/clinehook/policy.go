// Package clinehook evaluates Cline PreToolUse file hooks. Cline treats hook
// timeouts, crashes, non-zero exits, and invalid output as permission to run
// the tool, so every answer, including a refusal, must be valid JSON on stdout.
package clinehook

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

// Policy allows exact tool names and exact shell command lines. Unlisted
// tools, and command requests containing any unlisted command, are cancelled.
type Policy struct {
	Version  int               `json:"version" yaml:"version"`
	Tools    map[string]string `json:"tools" yaml:"tools"`
	Commands []string          `json:"commands" yaml:"commands"`
}

// commandTools run shell commands: run_commands in the SDK-based clients and
// execute_command in older extension releases. Commands govern both.
var commandTools = []string{"run_commands", "execute_command"}

func ValidatePolicy(p *Policy) error {
	if p == nil || p.Version != 1 {
		return errors.New("Cline hook policy version must be 1")
	}
	for name, decision := range p.Tools {
		if !validLiteral(name) || strings.ContainsAny(name, "*?") || slices.Contains(commandTools, name) {
			return errors.New("tools must be exact Cline tool names; shell tools are governed by commands")
		}
		if decision != "allow" && decision != "deny" {
			return errors.New("tool decisions must be allow or deny")
		}
	}
	seen := map[string]bool{}
	for _, command := range p.Commands {
		if !validLiteral(command) || command == "*" || seen[command] {
			return errors.New("commands must be unique exact command lines without control characters")
		}
		seen[command] = true
	}
	return nil
}

func validLiteral(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= 16384 && strings.IndexFunc(value, unicode.IsControl) < 0
}

// Evaluate reports whether the tool call may run. Any error means cancel.
func Evaluate(policyReader, inputReader io.Reader) (bool, error) {
	policyData, err := hookjson.ReadObject(policyReader, PolicyLimit)
	if err != nil {
		return false, errors.New("invalid Cline hook policy")
	}
	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(policyData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return false, errors.New("invalid Cline hook policy schema")
	}
	if err := ValidatePolicy(&policy); err != nil {
		return false, err
	}
	inputData, err := hookjson.ReadObject(inputReader, 1024*1024)
	if err != nil {
		return false, errors.New("invalid Cline hook input")
	}
	tool, input, err := toolCall(inputData)
	if err != nil {
		return false, err
	}
	if slices.Contains(commandTools, tool) {
		// Older extension releases send execute_command{command, requires_approval}.
		if fields, ok := input.(map[string]any); ok && tool == "execute_command" {
			if _, present := fields["requires_approval"]; present {
				input = without(fields, "requires_approval")
			}
		}
		commands, err := commandLines(input)
		if err != nil {
			return false, err
		}
		for _, command := range commands {
			if !slices.Contains(policy.Commands, command) {
				return false, nil
			}
		}
		return true, nil
	}
	return policy.Tools[tool] == "allow", nil
}

// toolCall accepts the SDK shape {"tool_call":{"name","input"}} and the VS Code
// shape {"preToolUse":{"toolName","parameters"}}, whose parameters are a string
// record with non-string values JSON-encoded. Exactly one must be present.
func toolCall(data []byte) (string, any, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", nil, errors.New("invalid Cline hook input schema")
	}
	if _, present := fields["hookName"]; present {
		name, err := hookjson.StringField(fields, "hookName", true)
		if err != nil || (name != "tool_call" && name != "PreToolUse") {
			return "", nil, errors.New("not a Cline PreToolUse request")
		}
	}
	_, sdk := fields["tool_call"]
	_, vscode := fields["preToolUse"]
	if sdk == vscode {
		return "", nil, errors.New("Cline hook input requires exactly one tool call")
	}
	if sdk {
		var call map[string]json.RawMessage
		if json.Unmarshal(fields["tool_call"], &call) != nil || call == nil {
			return "", nil, errors.New("tool_call must be an object")
		}
		name, err := hookjson.StringField(call, "name", true)
		if err != nil {
			return "", nil, err
		}
		var input any
		if raw, ok := call["input"]; ok && json.Unmarshal(raw, &input) != nil {
			return "", nil, errors.New("invalid tool input")
		}
		return name, input, nil
	}
	var call map[string]json.RawMessage
	if json.Unmarshal(fields["preToolUse"], &call) != nil || call == nil {
		return "", nil, errors.New("preToolUse must be an object")
	}
	name, err := hookjson.StringField(call, "toolName", true)
	if err != nil {
		return "", nil, err
	}
	var parameters map[string]string
	if raw, ok := call["parameters"]; ok && (json.Unmarshal(raw, &parameters) != nil || parameters == nil) {
		return "", nil, errors.New("preToolUse.parameters must be a string record")
	}
	input := map[string]any{}
	for key, value := range parameters {
		input[key] = value
		// Only array-typed parameters were JSON-encoded by the extension.
		// command and cmd are always shell strings and are never decoded.
		if key == "commands" || key == "args" {
			var decoded any
			if json.Unmarshal([]byte(value), &decoded) == nil {
				if _, isString := decoded.(string); !isString {
					input[key] = decoded
				}
			}
		}
	}
	return name, input, nil
}

// commandLines normalizes every input form Cline's run_commands accepts:
// {commands}, {command[, args]}, {cmd}, a bare string, and arrays of strings
// or {command, args} argv entries. Unknown shapes are errors, never "no
// commands".
func commandLines(input any) ([]string, error) {
	var lines []string
	add := func(entry any) error {
		switch v := entry.(type) {
		case string:
			lines = append(lines, v)
			return nil
		case map[string]any:
			line, err := argv(v)
			lines = append(lines, line)
			return err
		default:
			return errors.New("unsupported command entry")
		}
	}
	switch v := input.(type) {
	case string:
		lines = append(lines, v)
	case []any:
		for _, entry := range v {
			if err := add(entry); err != nil {
				return nil, err
			}
		}
	case map[string]any:
		if commands, ok := v["commands"]; ok {
			if len(v) != 1 {
				return nil, errors.New("unexpected command input fields")
			}
			if list, isList := commands.([]any); isList {
				for _, entry := range list {
					if err := add(entry); err != nil {
						return nil, err
					}
				}
			} else if err := add(commands); err != nil {
				return nil, err
			}
		} else if cmd, ok := v["cmd"]; ok {
			if len(v) != 1 {
				return nil, errors.New("unexpected command input fields")
			}
			if err := add(cmd); err != nil {
				return nil, err
			}
		} else if err := add(v); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported command input")
	}
	if len(lines) == 0 {
		return nil, errors.New("command request contains no commands")
	}
	return lines, nil
}

func without(fields map[string]any, key string) map[string]any {
	copied := make(map[string]any, len(fields))
	for k, v := range fields {
		if k != key {
			copied[k] = v
		}
	}
	return copied
}

// argv renders {command, args} for exact matching. Arguments containing
// whitespace or quotes have no unambiguous single-line form and are rejected.
func argv(entry map[string]any) (string, error) {
	command, ok := entry["command"].(string)
	if !ok || command == "" {
		return "", errors.New("command entry requires a command string")
	}
	for key := range entry {
		if key != "command" && key != "args" {
			return "", errors.New("unexpected command entry field")
		}
	}
	raw, present := entry["args"]
	if !present {
		return command, nil
	}
	args, ok := raw.([]any)
	if !ok {
		return "", errors.New("command args must be an array")
	}
	parts := []string{command}
	for _, arg := range args {
		value, ok := arg.(string)
		if !ok || value == "" || strings.ContainsAny(value, " \t\r\n\"'\\") {
			return "", errors.New("command argument has no exact single-line form")
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, " "), nil
}

// Respond writes a Cline hook control. Cancelling stops the tool call (and, in
// the VS Code extension, the run). The message contains no request data.
func Respond(output io.Writer, allowed bool) error {
	if allowed {
		_, err := io.WriteString(output, "{\"cancel\":false}\n")
		return err
	}
	_, err := io.WriteString(output, "{\"cancel\":true,\"errorMessage\":\"AgentEdict local tool policy does not allow this tool call.\"}\n")
	return err
}
