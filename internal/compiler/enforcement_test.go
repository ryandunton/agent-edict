package compiler

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func flexiblePolicy() *UnifiedPolicy {
	return &UnifiedPolicy{
		Version:    1,
		Name:       "adapter-test",
		Sandbox:    SandboxConfig{Modes: []string{"read-only", "workspace-write"}},
		Approval:   ApprovalConfig{Policies: []string{"on-request"}, BypassMode: "forbidden"},
		MCPServers: map[string]MCPServerConfig{},
	}
}

func jsonObject(t *testing.T, data string) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		t.Fatalf("invalid generated JSON: %v", err)
	}
	return result
}

func TestClaudeManagedControlsUseDocumentedStructure(t *testing.T) {
	out, err := Compile(flexiblePolicy(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	config := jsonObject(t, out.ClaudeManagedSettings)
	if config["allowManagedPermissionRulesOnly"] != true {
		t.Error("managed-only permission rules must be a root setting")
	}
	permissions := config["permissions"].(map[string]interface{})
	if permissions["disableBypassPermissionsMode"] != "disable" {
		t.Error("bypass prevention must be nested in permissions")
	}
	if _, ok := permissions["allowManagedPermissionRulesOnly"]; ok {
		t.Error("invalid nested managed-only setting remains")
	}
	if _, ok := config["disableBypassPermissionsMode"]; ok {
		t.Error("invalid root bypass setting remains")
	}
	for _, key := range []string{"allow", "ask", "deny"} {
		if _, ok := permissions[key].([]interface{}); !ok {
			t.Errorf("permissions.%s must be an array, not null", key)
		}
	}
	allowed, ok := config["allowedMcpServers"].([]interface{})
	if !ok || len(allowed) != 0 {
		t.Error("empty MCP allowlist must be [], not null")
	}
}

func TestGeminiManagedCompilationIsUnsupported(t *testing.T) {
	cases := []struct {
		name    string
		servers map[string]MCPServerConfig
	}{
		{"omitted MCP scope", nil},
		{"empty MCP scope", map[string]MCPServerConfig{}},
		{"remote MCP scope", map[string]MCPServerConfig{"approved": {URL: "https://mcp.example.test"}}},
		{"stdio MCP scope", map[string]MCPServerConfig{"approved": {Unix: &MCPServerOS{Command: "/usr/bin/mcp", Args: []string{"--readonly"}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := flexiblePolicy()
			p.MCPServers = tc.servers
			if output, err := compileGemini(p, false); err == nil || output != "" || !strings.Contains(err.Error(), "unsupported") {
				t.Error("Gemini must reject managed compilation instead of emitting unenforceable MCP controls")
			}
			out, err := Compile(p, "linux")
			if err != nil {
				t.Fatal(err)
			}
			if out.GeminiSettingsJSON != "" {
				t.Error("public compilation must omit unsupported Gemini output")
			}
			if out.CodexRequirementsTOML == "" || out.ClaudeManagedSettings == "" || out.OpenCodeJSON == "" {
				t.Error("supported adapters must still compile")
			}
		})
	}
}

func TestOpenCodeInstructionsAreManagedFileReferences(t *testing.T) {
	p := flexiblePolicy()
	p.AdditionalDeveloperInstructions = "  Follow the company policy.\n"
	p.GuardianExtraPolicy = "\nReview the exact action.  "
	paths := map[string]string{
		"linux":   "/etc/opencode/managed-instructions.md",
		"darwin":  "/Library/Application Support/opencode/managed-instructions.md",
		"windows": "C:/ProgramData/opencode/managed-instructions.md",
	}
	for targetOS, path := range paths {
		t.Run(targetOS, func(t *testing.T) {
			out, err := Compile(p, targetOS)
			if err != nil {
				t.Fatal(err)
			}
			config := jsonObject(t, out.OpenCodeJSON)
			if !reflect.DeepEqual(config["instructions"], []interface{}{path}) {
				t.Errorf("instructions must reference the managed sidecar: %v", config["instructions"])
			}
			// Reflection lets this test exercise the original compiler before the new field exists.
			sidecar := reflect.ValueOf(out).Elem().FieldByName("OpenCodeInstructions")
			if !sidecar.IsValid() || sidecar.String() != "Follow the company policy.\n\nReview the exact action.\n" {
				t.Error("missing or incorrect materialized instructions sidecar")
			}
		})
	}
}

func TestOpenCodeEmptyInstructionsClearPreviousProfile(t *testing.T) {
	out, err := Compile(flexiblePolicy(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	config := jsonObject(t, out.OpenCodeJSON)
	if !reflect.DeepEqual(config["instructions"], []interface{}{"/etc/opencode/managed-instructions.md"}) {
		t.Error("empty instruction policy must still reference its empty managed sidecar")
	}
	sidecar := reflect.ValueOf(out).Elem().FieldByName("OpenCodeInstructions")
	if !sidecar.IsValid() || sidecar.String() != "" {
		t.Error("empty policy must produce empty sidecar")
	}
}

// openCodeBashRules returns permission.bash in file order. OpenCode applies
// the last matching pattern, so key order is part of the policy.
func openCodeBashRules(t *testing.T, data string) [][2]string {
	t.Helper()
	var config struct {
		Permission struct {
			Bash json.RawMessage `json:"bash"`
		} `json:"permission"`
	}
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(config.Permission.Bash)))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("permission.bash must be an object: %v", err)
	}
	var rules [][2]string
	for dec.More() {
		key, _ := dec.Token()
		value, _ := dec.Token()
		rules = append(rules, [2]string{key.(string), value.(string)})
	}
	return rules
}

// openCodeGlob implements OpenCode's documented wildcards: * and ?.
func openCodeGlob(pattern, value string) bool {
	if pattern == "" {
		return value == ""
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(value); i++ {
			if openCodeGlob(pattern[1:], value[i:]) {
				return true
			}
		}
		return false
	case '?':
		return value != "" && openCodeGlob(pattern[1:], value[1:])
	default:
		return value != "" && pattern[0] == value[0] && openCodeGlob(pattern[1:], value[1:])
	}
}

func TestOpenCodeRestrictiveCommandRulesWinUnderLastMatch(t *testing.T) {
	p := flexiblePolicy()
	p.Commands.Allow.Common = []string{"npm", "git"}
	p.Commands.Prompt.Common = []string{"git push"}
	p.Commands.Deny.Common = []string{"npm publish"}
	out, err := Compile(p, "linux")
	if err != nil {
		t.Fatal(err)
	}
	rules := openCodeBashRules(t, out.OpenCodeJSON)
	decide := func(command string) string {
		decision := "unmatched"
		for _, rule := range rules {
			if openCodeGlob(rule[0], command) {
				decision = rule[1]
			}
		}
		return decision
	}
	for command, want := range map[string]string{
		"npm publish":     "deny",
		"npm test":        "allow",
		"git push origin": "ask",
		"git status":      "allow",
	} {
		if got := decide(command); got != want {
			t.Errorf("%q: OpenCode would apply %q, want %q (rules %v)", command, got, want, rules)
		}
	}
}

func TestCodexTOMLPreservesArbitraryPolicyText(t *testing.T) {
	p := flexiblePolicy()
	p.AdditionalDeveloperInstructions = `Never edit C:\Users\Public\tools.ini or \\server\share.` + "\n" + `Quote """verbatim""" and keep\ttabs` + "\x7f"
	p.GuardianExtraPolicy = `Escapes like \n and \u0041 stay literal.`
	p.Commands.Deny.Windows = []string{`C:\Tools\bad.exe`}
	p.MCPServers = map[string]MCPServerConfig{"corp.docs": {URL: "https://docs.example.com/mcp"}}
	out, err := Compile(p, "windows")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Instructions string `toml:"additional_developer_instructions"`
		Guardian     string `toml:"guardian_extra_policy"`
		Rules        struct {
			PrefixRules []struct {
				Pattern []struct {
					Token string `toml:"token"`
				} `toml:"pattern"`
			} `toml:"prefix_rules"`
		} `toml:"rules"`
		MCPServers map[string]map[string]any `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal([]byte(out.CodexRequirementsTOML), &parsed); err != nil {
		t.Fatalf("generated TOML is invalid: %v\n%s", err, out.CodexRequirementsTOML)
	}
	// The readable multi-line layout ends the value with a newline.
	if parsed.Instructions != p.AdditionalDeveloperInstructions+"\n" {
		t.Errorf("instructions changed:\n got %q\nwant %q", parsed.Instructions, p.AdditionalDeveloperInstructions)
	}
	if parsed.Guardian != p.GuardianExtraPolicy+"\n" {
		t.Errorf("guardian policy changed: %q", parsed.Guardian)
	}
	if len(parsed.Rules.PrefixRules) != 1 || parsed.Rules.PrefixRules[0].Pattern[0].Token != `C:\Tools\bad.exe` {
		t.Errorf("command token changed: %+v", parsed.Rules.PrefixRules)
	}
	if _, ok := parsed.MCPServers["corp.docs"]; !ok || len(parsed.MCPServers) != 1 {
		t.Errorf("MCP server name must stay one table key: %v", parsed.MCPServers)
	}
}

func TestCursorCompilationIsExplicitlyUnsupported(t *testing.T) {
	if _, err := compileCursor(flexiblePolicy(), false); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Error("Cursor must fail explicitly instead of generating an invented policy")
	}
	out, err := Compile(flexiblePolicy(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	if out.CursorJSON != "" {
		t.Error("supported compilation must not emit a Cursor policy")
	}
}

func TestCompilerRejectsInvalidIdentityAndUnsupportedDenyWrite(t *testing.T) {
	cases := []struct {
		name   string
		change func(*UnifiedPolicy)
	}{
		{"missing name", func(p *UnifiedPolicy) { p.Name = "" }},
		{"path name", func(p *UnifiedPolicy) { p.Name = "../escape" }},
		{"unsupported version", func(p *UnifiedPolicy) { p.Version = 2 }},
		{"deny write", func(p *UnifiedPolicy) { p.Filesystem.DenyWrite.Common = []string{"/private"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := flexiblePolicy()
			tc.change(p)
			if _, err := Compile(p, "linux"); err == nil {
				t.Error("cross-agent compilation must reject policy")
			}
			if _, _, err := CompileCodexOnly(p, "linux"); err == nil {
				t.Error("Codex compilation must reject policy")
			}
		})
	}
	if _, err := Compile(flexiblePolicy(), "plan9"); err == nil {
		t.Error("unsupported target OS accepted")
	}
}

func TestCrossAgentCompilationRejectsUnsupportedHardBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*UnifiedPolicy)
	}{
		{"filesystem deny_read", func(p *UnifiedPolicy) { p.Filesystem.DenyRead.Common = []string{"/secrets"} }},
		{"permissions filesystem", func(p *UnifiedPolicy) {
			p.PermissionDefs = map[string]PermissionDef{"restricted": {Filesystem: &PermissionFilesystem{Root: "deny"}}}
		}},
		{"permissions network", func(p *UnifiedPolicy) {
			p.PermissionDefs = map[string]PermissionDef{"restricted": {Network: &PermissionNetwork{Enabled: false}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := flexiblePolicy()
			tc.configure(p)
			if _, err := Compile(p, "linux"); err == nil || !strings.Contains(err.Error(), "Codex-only") {
				t.Error("unsupported hard boundary must fail with Codex-only guidance")
			}
			if _, _, err := CompileCodexOnly(p, "linux"); err != nil {
				t.Fatalf("Codex-only boundary unexpectedly rejected: %v", err)
			}
		})
	}
}

func TestLoadPolicyRejectsMultipleDocuments(t *testing.T) {
	path := t.TempDir() + "/policy.yaml"
	if err := os.WriteFile(path, []byte("version: 1\nname: first\n---\nversion: 1\nname: second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Error("additional policy document must not be ignored")
	}
}
