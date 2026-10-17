package windsurfhook

import (
	"errors"
	"strings"
	"testing"
)

const testPolicy = `{"version":1,"commands":["git status","npm test"],"mcp":[{"server":"github","tools":["create_issue"]}]}`

func evaluate(event, input string) error {
	return Evaluate(event, strings.NewReader(testPolicy), strings.NewReader(input))
}

func TestWindsurfAllowsOnlyExactListedActions(t *testing.T) {
	for _, tc := range []struct {
		name, event, input string
		allowed            bool
	}{
		{"listed command", "pre_run_command", `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"git status","cwd":"/repo"}}`, true},
		{"command without action name", "pre_run_command", `{"tool_info":{"command_line":"npm test"}}`, true},
		{"compound command", "pre_run_command", `{"tool_info":{"command_line":"git status; rm -rf ~"}}`, false},
		{"prefix only", "pre_run_command", `{"tool_info":{"command_line":"git status --porcelain"}}`, false},
		{"unlisted command", "pre_run_command", `{"tool_info":{"command_line":"curl https://example.com"}}`, false},
		{"listed MCP tool", "pre_mcp_tool_use", `{"agent_action_name":"pre_mcp_tool_use","tool_info":{"mcp_server_name":"github","mcp_tool_name":"create_issue","mcp_tool_arguments":{"title":"x"}}}`, true},
		{"other MCP tool", "pre_mcp_tool_use", `{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"delete_repo"}}`, false},
		{"other MCP server", "pre_mcp_tool_use", `{"tool_info":{"mcp_server_name":"gitlab","mcp_tool_name":"create_issue"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := evaluate(tc.event, tc.input)
			if tc.allowed && err != nil {
				t.Fatalf("listed action blocked: %v", err)
			}
			if !tc.allowed && !errors.Is(err, ErrBlocked) {
				t.Fatalf("unlisted action must be a policy block, got %v", err)
			}
		})
	}
}

func TestWindsurfBlocksMalformedOrAmbiguousRequests(t *testing.T) {
	for _, tc := range []struct{ name, event, input string }{
		{"unsupported event", "pre_read_code", `{"tool_info":{"file_path":"/repo/a"}}`},
		{"event mismatch", "pre_run_command", `{"agent_action_name":"pre_mcp_tool_use","tool_info":{"command_line":"git status"}}`},
		{"duplicate key", "pre_run_command", `{"tool_info":{"command_line":"git status","command_line":"rm -rf ~"}}`},
		{"missing command", "pre_run_command", `{"tool_info":{}}`},
		{"non-string command", "pre_run_command", `{"tool_info":{"command_line":["git","status"]}}`},
		{"missing tool_info", "pre_run_command", `{"agent_action_name":"pre_run_command"}`},
		{"truncated", "pre_run_command", `{"tool_info":{"command_line":"git status"`},
		{"trailing data", "pre_run_command", `{"tool_info":{"command_line":"git status"}} {}`},
		{"missing MCP tool", "pre_mcp_tool_use", `{"tool_info":{"mcp_server_name":"github"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := evaluate(tc.event, tc.input); err == nil {
				t.Fatal("malformed request was allowed")
			}
		})
	}
}

func TestWindsurfPolicyValidation(t *testing.T) {
	valid := Policy{Version: 1, Commands: []string{"git status"}, MCP: []MCPRule{{Server: "github", Tools: []string{"create_issue"}}}}
	if err := ValidatePolicy(&valid); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicy(&Policy{Version: 1}); err != nil {
		t.Fatalf("empty lists deny everything and are valid: %v", err)
	}
	for name, p := range map[string]Policy{
		"version":           {Version: 2},
		"wildcard command":  {Version: 1, Commands: []string{"*"}},
		"duplicate command": {Version: 1, Commands: []string{"ls", "ls"}},
		"untrimmed command": {Version: 1, Commands: []string{" ls"}},
		"control command":   {Version: 1, Commands: []string{"ls\nrm -rf ~"}},
		"wildcard server":   {Version: 1, MCP: []MCPRule{{Server: "git*", Tools: []string{"a"}}}},
		"duplicate server":  {Version: 1, MCP: []MCPRule{{Server: "a", Tools: []string{"x"}}, {Server: "a", Tools: []string{"y"}}}},
		"no tools":          {Version: 1, MCP: []MCPRule{{Server: "a"}}},
		"wildcard tool":     {Version: 1, MCP: []MCPRule{{Server: "a", Tools: []string{"*"}}}},
	} {
		if err := ValidatePolicy(&p); err == nil {
			t.Errorf("%s: invalid policy accepted", name)
		}
	}
	if err := Evaluate("pre_run_command", strings.NewReader(`{"version":1,"commands":[],"extra":true}`), strings.NewReader(`{"tool_info":{"command_line":"ls"}}`)); err == nil {
		t.Error("policy with unknown field accepted")
	}
}
