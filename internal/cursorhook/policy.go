// Package cursorhook evaluates the documented Cursor permission hook protocol.
package cursorhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/ryandunton/agent-edict/internal/hookjson"
)

type Policy struct {
	Version    int         `json:"version" yaml:"version"`
	ToolsAllow []string    `json:"tools_allow" yaml:"tools_allow"`
	Shell      ShellPolicy `json:"shell" yaml:"shell"`
	MCP        []MCPRule   `json:"mcp" yaml:"mcp"`
}

type ShellPolicy struct {
	Allow []string `json:"allow" yaml:"allow"`
	Ask   []string `json:"ask" yaml:"ask"`
	Deny  []string `json:"deny" yaml:"deny"`
}

type MCPRule struct {
	Name     string   `json:"name" yaml:"name"`
	URL      string   `json:"url,omitempty" yaml:"url,omitempty"`
	Command  string   `json:"command,omitempty" yaml:"command,omitempty"`
	Tools    []string `json:"tools" yaml:"tools"`
	Decision string   `json:"decision" yaml:"decision"`
}

// ValidatePolicy validates exact-match invocation rules, not process permissions.
// Empty allow/ask lists mean deny all invocations for that category.
func ValidatePolicy(p *Policy) error {
	if p == nil || p.Version != 1 {
		return errors.New("Cursor hook policy version must be 1")
	}
	tools := map[string]bool{}
	for _, name := range p.ToolsAllow {
		if !validLiteral(name) || strings.ContainsAny(name, "*?") || tools[name] {
			return errors.New("tools_allow requires unique exact tool names without wildcards")
		}
		tools[name] = true
	}
	commands := map[string]bool{}
	for _, list := range [][]string{p.Shell.Allow, p.Shell.Ask, p.Shell.Deny} {
		for _, command := range list {
			if !validLiteral(command) || command == "*" {
				return errors.New("shell rules require a nonempty exact command without control characters")
			}
			if commands[command] {
				return errors.New("duplicate or conflicting exact shell command")
			}
			commands[command] = true
		}
	}
	servers := map[string]bool{}
	for _, rule := range p.MCP {
		if !validLiteral(rule.Name) || strings.ContainsAny(rule.Name, "*?") || servers[rule.Name] {
			return errors.New("MCP server names must be unique exact names")
		}
		servers[rule.Name] = true
		if (rule.URL == "") == (rule.Command == "") {
			return errors.New("MCP rule requires exactly one URL or rendered launch command")
		}
		if rule.URL != "" {
			u, err := url.Parse(rule.URL)
			if err != nil || !validLiteral(rule.URL) || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(rule.URL, "*") {
				return errors.New("MCP URL must be an exact HTTPS URL without credentials, fragments, or wildcards")
			}
		} else if !validLiteral(rule.Command) || rule.Command == "*" {
			return errors.New("MCP launch command must be an exact nonempty string")
		}
		// Cursor 3.24.18's MCP executor only handles deny; ask falls through
		// to tool execution. Do not expose a confirmation that it cannot enforce.
		if rule.Decision != "allow" {
			return errors.New("MCP decision must be allow; ask is not enforced by Cursor 3.24.18 and unlisted calls already deny")
		}
		if len(rule.Tools) == 0 {
			return errors.New("MCP rules require explicit tool names")
		}
		seen := map[string]bool{}
		for _, tool := range rule.Tools {
			if !validLiteral(tool) || strings.ContainsAny(tool, "*?") || seen[tool] {
				return errors.New("MCP tool names must be unique exact names")
			}
			seen[tool] = true
		}
	}
	return nil
}

func validLiteral(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= 16384 && strings.IndexFunc(value, unicode.IsControl) < 0
}

// Run writes a Cursor permission response. Malformed policies, malformed input,
// unsupported events, and ambiguous server identity all write deny and return an
// error. Callers should use exit code 2 on error. Input bytes are never logged.
func Run(event string, policyReader, inputReader io.Reader, output io.Writer) error {
	decision, err := evaluate(event, policyReader, inputReader)
	if err != nil {
		return errors.Join(err, Deny(output))
	}
	return json.NewEncoder(output).Encode(struct {
		Permission string `json:"permission"`
	}{decision})
}

// Deny emits a valid fail-closed response, including when a caller cannot open
// the protected policy file. It contains no caller-controlled data.
func Deny(output io.Writer) error {
	_, err := io.WriteString(output, "{\"permission\":\"deny\",\"user_message\":\"AgentEdict denied an invalid or unsupported hook request.\"}\n")
	return err
}

func evaluate(event string, policyReader, inputReader io.Reader) (string, error) {
	if event != "preToolUse" && event != "beforeShellExecution" && event != "beforeMCPExecution" {
		return "", errors.New("unsupported Cursor hook event")
	}
	policyData, err := hookjson.ReadObject(policyReader, 256*1024)
	if err != nil {
		return "", fmt.Errorf("invalid Cursor hook policy: %w", err)
	}
	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(policyData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return "", errors.New("invalid Cursor hook policy schema")
	}
	if err := ValidatePolicy(&policy); err != nil {
		return "", err
	}
	inputData, err := hookjson.ReadObject(inputReader, 1024*1024)
	if err != nil {
		return "", fmt.Errorf("invalid Cursor hook input: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(inputData, &fields); err != nil {
		return "", errors.New("invalid Cursor hook input schema")
	}
	if _, present := fields["hook_event_name"]; present {
		inputEvent, err := hookjson.StringField(fields, "hook_event_name", true)
		if err != nil || inputEvent != event {
			return "", errors.New("Cursor hook event mismatch")
		}
	}
	if event == "preToolUse" {
		name, err := hookjson.StringField(fields, "tool_name", true)
		if err != nil {
			return "", err
		}
		var toolInput map[string]json.RawMessage
		if json.Unmarshal(fields["tool_input"], &toolInput) != nil || toolInput == nil {
			return "", errors.New("preToolUse requires a tool_input object")
		}
		if slices.Contains(policy.ToolsAllow, name) {
			return "allow", nil
		}
		return "deny", nil
	}
	if event == "beforeShellExecution" {
		command, err := hookjson.StringField(fields, "command", true)
		if err != nil {
			return "", err
		}
		if slices.Contains(policy.Shell.Deny, command) {
			return "deny", nil
		}
		if slices.Contains(policy.Shell.Ask, command) {
			return "ask", nil
		}
		if slices.Contains(policy.Shell.Allow, command) {
			return "allow", nil
		}
		return "deny", nil
	}
	name, err := hookjson.StringField(fields, "mcp_server_name", true)
	if err != nil {
		return "", err
	}
	tool, err := hookjson.StringField(fields, "tool_name", true)
	if err != nil {
		return "", err
	}
	serverURL, err := hookjson.StringField(fields, "mcp_server_url", false)
	if err != nil {
		return "", err
	}
	aliasURL, err := hookjson.StringField(fields, "url", false)
	if err != nil {
		return "", err
	}
	command, err := hookjson.StringField(fields, "command", false)
	if err != nil {
		return "", err
	}
	if serverURL != "" && aliasURL != "" && serverURL != aliasURL {
		return "", errors.New("conflicting MCP URLs")
	}
	if serverURL == "" {
		serverURL = aliasURL
	}
	if (serverURL == "") == (command == "") {
		return "", errors.New("MCP input requires exactly one transport identity")
	}
	for _, rule := range policy.MCP {
		if rule.Name == name && rule.URL == serverURL && rule.Command == command && slices.Contains(rule.Tools, tool) {
			return rule.Decision, nil
		}
	}
	return "deny", nil
}
