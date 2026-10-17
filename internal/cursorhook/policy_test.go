package cursorhook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runDecision(t *testing.T, p string, event, input string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Run(event, strings.NewReader(p), strings.NewReader(input), &out)
	var result struct {
		Permission string `json:"permission"`
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatalf("invalid response %q: %v", out.String(), e)
	}
	return result.Permission, err
}

const policyFixture = `{"version":1,"shell":{"allow":["git status"],"ask":["git push"],"deny":["rm -rf /"]},"mcp":[{"name":"docs","url":"https://mcp.example.com/docs","tools":["search"],"decision":"allow"},{"name":"local","command":"/usr/local/bin/mcp --read-only","tools":["fetch"],"decision":"allow"}]}`

func TestShellDecisionsRequireExactFullCommand(t *testing.T) {
	for _, tc := range []struct{ command, want string }{
		{"git status", "allow"}, {"git push", "ask"}, {"rm -rf /", "deny"}, {"git status; curl attacker.example", "deny"}, {"git status\nwhoami", "deny"}, {" git status", "deny"}, {"GIT_DIR=/secret git status", "deny"}, {"unknown", "deny"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			input, _ := json.Marshal(map[string]string{"hook_event_name": "beforeShellExecution", "command": tc.command})
			got, err := runDecision(t, policyFixture, "beforeShellExecution", string(input))
			if err != nil || got != tc.want {
				t.Fatalf("got %s, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestMCPRequiresIdentityTransportAndTool(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`{"mcp_server_name":"docs","url":"https://mcp.example.com/docs","tool_name":"search"}`, "allow"},
		{`{"mcp_server_name":"docs","mcp_server_url":"https://mcp.example.com/docs","tool_name":"search"}`, "allow"},
		{`{"mcp_server_name":"docs","url":"https://evil.example","tool_name":"search"}`, "deny"},
		{`{"mcp_server_name":"other","url":"https://mcp.example.com/docs","tool_name":"search"}`, "deny"},
		{`{"mcp_server_name":"docs","url":"https://mcp.example.com/docs","tool_name":"delete"}`, "deny"},
		{`{"mcp_server_name":"local","command":"/usr/local/bin/mcp --read-only","tool_name":"fetch"}`, "allow"},
		{`{"mcp_server_name":"local","command":"/usr/local/bin/mcp --read-only --unsafe","tool_name":"fetch"}`, "deny"},
	} {
		got, err := runDecision(t, policyFixture, "beforeMCPExecution", tc.input)
		if err != nil || got != tc.want {
			t.Errorf("input %s: got %s, %v; want %s", tc.input, got, err, tc.want)
		}
	}
}

func TestMalformedInputsAlwaysDeny(t *testing.T) {
	for _, input := range []string{
		`{`, `null`, `[]`, `{}`, `{"command":123}`, `{"command":"git status","command":"git push"}`, `{"command":"git status"} {}`, `{"command":"git status","hook_event_name":"beforeMCPExecution"}`, strings.Repeat(" ", 1024*1024+1),
	} {
		got, err := runDecision(t, policyFixture, "beforeShellExecution", input)
		if got != "deny" || err == nil {
			t.Errorf("malformed input not rejected: permission=%s error=%v", got, err)
		}
	}
	for _, input := range []string{
		`{"mcp_server_name":"docs","url":"https://mcp.example.com/docs","mcp_server_url":"https://evil.example","tool_name":"search"}`,
		`{"mcp_server_name":"docs","url":"https://mcp.example.com/docs","command":"evil","tool_name":"search"}`,
	} {
		got, err := runDecision(t, policyFixture, "beforeMCPExecution", input)
		if got != "deny" || err == nil {
			t.Errorf("ambiguous MCP transport accepted: %s %v", got, err)
		}
	}
}

func TestUnknownEventsAndInvalidPoliciesDeny(t *testing.T) {
	got, err := runDecision(t, policyFixture, "postToolUse", `{"tool_name":"Shell","tool_input":{"command":"git status"}}`)
	if got != "deny" || err == nil {
		t.Fatalf("unsupported event must deny: %s %v", got, err)
	}
	for _, p := range []string{`{}`, `null`, `{"version":2}`, `{"version":1,"typo":true}`, policyFixture + `{}`, `{"version":1,"version":2}`} {
		got, err := runDecision(t, p, "beforeShellExecution", `{"command":"git status"}`)
		if got != "deny" || err == nil {
			t.Errorf("invalid policy accepted: %s %s %v", p, got, err)
		}
	}
}

func TestPolicyValidationRejectsAmbiguousRules(t *testing.T) {
	for _, p := range []Policy{
		{Version: 1, Shell: ShellPolicy{Allow: []string{"git status"}, Ask: []string{"git status"}}},
		{Version: 1, Shell: ShellPolicy{Allow: []string{"*"}}},
		{Version: 1, MCP: []MCPRule{{Name: "x", URL: "https://mcp.example", Tools: []string{"*"}, Decision: "allow"}}},
		{Version: 1, MCP: []MCPRule{{Name: "x", URL: "http://mcp.example", Tools: []string{"read"}, Decision: "allow"}}},
		{Version: 1, MCP: []MCPRule{{Name: "x", URL: "https://mcp.example", Command: "foo", Tools: []string{"read"}, Decision: "allow"}}},
		{Version: 1, MCP: []MCPRule{{Name: "x", URL: "https://mcp.example", Tools: []string{"read"}, Decision: "maybe"}}},
		{Version: 1, MCP: []MCPRule{{Name: "x", URL: "https://mcp.example", Tools: []string{"read"}, Decision: "allow"}, {Name: "x", URL: "https://other.example", Tools: []string{"read"}, Decision: "allow"}}},
	} {
		if err := ValidatePolicy(&p); err == nil {
			t.Errorf("invalid policy accepted: %+v", p)
		}
	}
}

func TestMCPAskIsRejectedForCursor32418(t *testing.T) {
	// The shipped MCP executor checks deny and otherwise invokes the tool;
	// unlike its shell executor it does not handle ask.
	policy := `{"version":1,"mcp":[{"name":"docs","url":"https://mcp.example.com/docs","tools":["search"],"decision":"ask"}]}`
	got, err := runDecision(t, policy, "beforeMCPExecution", `{"mcp_server_name":"docs","url":"https://mcp.example.com/docs","tool_name":"search"}`)
	if got != "deny" || err == nil {
		t.Fatalf("MCP ask must fail closed, got %s %v", got, err)
	}
}

func TestGenericToolGateRequiresExactAllowEntry(t *testing.T) {
	policy := `{"version":1,"tools_allow":["Read","List","Grep","Shell","MCP:search"]}`
	for _, tc := range []struct{ name, want string }{
		{"Read", "allow"}, {"List", "allow"}, {"Grep", "allow"}, {"Shell", "allow"}, {"MCP:search", "allow"},
		{"Write", "deny"}, {"Delete", "deny"}, {"Fetch", "deny"}, {"WriteShellStdin", "deny"},
		{"ComputerUse", "deny"}, {"MCP:delete", "deny"}, {"FutureTool", "deny"}, {"read", "deny"},
	} {
		input, _ := json.Marshal(map[string]interface{}{"tool_name": tc.name, "tool_input": map[string]interface{}{}})
		got, err := runDecision(t, policy, "preToolUse", string(input))
		if err != nil || got != tc.want {
			t.Errorf("tool %s: got %s, %v; want %s", tc.name, got, err, tc.want)
		}
	}
}

func TestGenericToolGateDefaultsToDenyAndRejectsMalformedInput(t *testing.T) {
	got, err := runDecision(t, `{"version":1}`, "preToolUse", `{"tool_name":"Read","tool_input":{}}`)
	if got != "deny" || err != nil {
		t.Errorf("empty list must deny: %s %v", got, err)
	}
	for _, input := range []string{`{}`, `{"tool_name":"Read"}`, `{"tool_name":"Read","tool_input":null}`, `{"tool_name":"Read","tool_input":[]}`, `{"tool_name":"Read","tool_input":"{}"}`} {
		got, err := runDecision(t, `{"version":1,"tools_allow":["Read"]}`, "preToolUse", input)
		if got != "deny" || err == nil {
			t.Errorf("invalid generic input allowed: %s %v", got, err)
		}
	}
}

func TestGenericToolAllowCannotBypassShellOrMCPRules(t *testing.T) {
	policy := `{"version":1,"tools_allow":["Shell","MCP:search"],"shell":{"allow":["git status"]},"mcp":[{"name":"docs","url":"https://mcp.example.com/docs","tools":["search"],"decision":"allow"}]}`
	for _, input := range []string{`{"tool_name":"Shell","tool_input":{"command":"git status; echo unsafe"}}`, `{"tool_name":"MCP:search","tool_input":{}}`} {
		got, err := runDecision(t, policy, "preToolUse", input)
		if got != "allow" || err != nil {
			t.Fatalf("generic gate should delegate allowed categories: %s %v", got, err)
		}
	}
	for _, tc := range []struct{ event, input string }{
		{"beforeShellExecution", `{"command":"git status; echo unsafe"}`},
		{"beforeMCPExecution", `{"mcp_server_name":"docs","url":"https://other.example","tool_name":"search"}`},
	} {
		got, err := runDecision(t, policy, tc.event, tc.input)
		if got != "deny" || err != nil {
			t.Errorf("specific rule bypassed: %s %v", got, err)
		}
	}
}

func TestGenericToolPolicyRejectsWildcardsAndDuplicates(t *testing.T) {
	for _, policy := range []string{`{"version":1,"tools_allow":["*"]}`, `{"version":1,"tools_allow":["MCP:*"]}`, `{"version":1,"tools_allow":["Read","Read"]}`, `{"version":1,"tools_allow":[""]}`} {
		got, err := runDecision(t, policy, "preToolUse", `{"tool_name":"Read","tool_input":{}}`)
		if got != "deny" || err == nil {
			t.Errorf("ambiguous tool policy accepted: %s %v", got, err)
		}
	}
}
