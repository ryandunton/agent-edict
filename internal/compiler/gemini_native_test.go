package compiler

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func geminiString(value string) *string { return &value }

func TestNativeGeminiEmitsAdminTOMLAndSystemSettings(t *testing.T) {
	p := &GeminiNativePolicy{DefaultDecision: "deny", Rules: []GeminiNativeRule{
		{ToolName: "read_file", Decision: "allow", Priority: 100},
		{ToolName: "run_shell_command", Decision: "ask_user", Priority: 200, CommandPrefix: geminiString("git status"), Modes: []string{"default", "plan"}},
		{ToolName: "*", Decision: "deny", Priority: 999, MCPName: geminiString("*"), DenyMessage: "MCP tool calls are disabled.\nAsk an administrator."},
	}, Settings: &GeminiNativeSettings{SandboxDefault: "auto"}}
	for targetOS, dir := range map[string]string{
		"linux": "/etc/gemini-cli", "darwin": "/Library/Application Support/GeminiCli", "windows": `C:\ProgramData\gemini-cli`,
	} {
		t.Run(targetOS, func(t *testing.T) {
			out, err := compileNativeGemini(p, targetOS)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Artifacts) != 2 {
				t.Fatalf("expected settings and mandatory admin policy: %#v", out.Artifacts)
			}
			files := map[string]NativeArtifact{}
			separator := "/"
			if targetOS == "windows" {
				separator = `\`
			}
			for _, artifact := range out.Artifacts {
				files[artifact.Extension] = artifact
				if artifact.Delivery != "system-file" {
					t.Errorf("incorrect delivery: %s", artifact.Delivery)
				}
			}
			settings := files["gemini.json"]
			policy := files["gemini.policy.toml"]
			if settings.Destination != dir+separator+"settings.json" || policy.Destination != dir+separator+"policies"+separator+"agentedict.toml" {
				t.Errorf("wrong native locations: %#v", files)
			}
			var settingsData map[string]interface{}
			if err := json.Unmarshal([]byte(settings.Content), &settingsData); err != nil {
				t.Fatal(err)
			}
			security := settingsData["security"].(map[string]interface{})
			if security["disableYoloMode"] != true || security["disableAlwaysAllow"] != true {
				t.Errorf("missing conservative security settings: %#v", security)
			}
			if settingsData["tools"].(map[string]interface{})["sandbox"] != true {
				t.Fatal("sandbox default must be tools.sandbox")
			}
			for _, key := range []string{"admin", "mcp", "mcpServers", "sandbox"} {
				if _, ok := settingsData[key]; ok {
					t.Errorf("unsupported or misplaced control emitted: %s", key)
				}
			}
			var parsed struct {
				Rules []map[string]interface{} `toml:"rule"`
			}
			if err := toml.Unmarshal([]byte(policy.Content), &parsed); err != nil {
				t.Fatal(err)
			}
			if len(parsed.Rules) != 4 {
				t.Fatalf("expected catchall and three specific rules, got %#v", parsed.Rules)
			}
			if !reflect.DeepEqual(parsed.Rules[0], map[string]interface{}{"toolName": "*", "decision": "deny", "priority": int64(0)}) {
				t.Errorf("default must apply to every tool in every mode: %#v", parsed.Rules[0])
			}
			if parsed.Rules[2]["commandPrefix"] != "git status" || parsed.Rules[2]["toolName"] != "run_shell_command" || parsed.Rules[3]["mcpName"] != "*" || parsed.Rules[3]["denyMessage"] != p.Rules[2].DenyMessage {
				t.Errorf("rule semantics lost: %#v", parsed.Rules)
			}
			levels := map[string]string{}
			for _, cap := range out.Capabilities {
				if cap.Product != "gemini" || cap.Details == "" {
					t.Errorf("incomplete capability: %#v", cap)
				}
				levels[cap.Control] = cap.Level
			}
			for control, level := range map[string]string{"tool_decisions": "enforced", "security_settings": "configuration-only", "sandbox": "configuration-only", "mcp_processes": "not-enforced"} {
				if levels[control] != level {
					t.Errorf("%s capability = %q, want %q", control, levels[control], level)
				}
			}
		})
	}
}

func TestNativeGeminiRejectsInvalidOrAmbiguousRules(t *testing.T) {
	valid := func() *GeminiNativePolicy {
		return &GeminiNativePolicy{DefaultDecision: "deny", Rules: []GeminiNativeRule{{ToolName: "read_file", Decision: "allow", Priority: 100}}}
	}
	cases := map[string]func(*GeminiNativePolicy){
		"missing default":                func(p *GeminiNativePolicy) { p.DefaultDecision = "" },
		"permissive default":             func(p *GeminiNativePolicy) { p.DefaultDecision = "allow" },
		"missing tool":                   func(p *GeminiNativePolicy) { p.Rules[0].ToolName = "" },
		"invalid decision":               func(p *GeminiNativePolicy) { p.Rules[0].Decision = "prompt" },
		"reserved catchall priority":     func(p *GeminiNativePolicy) { p.Rules[0].Priority = 0 },
		"tier overflow":                  func(p *GeminiNativePolicy) { p.Rules[0].Priority = 1000 },
		"always allow reserved priority": func(p *GeminiNativePolicy) { p.Rules[0].Priority = 950 },
		"empty prefix": func(p *GeminiNativePolicy) {
			p.Rules[0].ToolName = "run_shell_command"
			p.Rules[0].CommandPrefix = geminiString("")
		},
		"prefix on non-shell": func(p *GeminiNativePolicy) { p.Rules[0].CommandPrefix = geminiString("git") },
		"empty MCP name":      func(p *GeminiNativePolicy) { p.Rules[0].MCPName = geminiString("") },
		"MCP plus shell syntax": func(p *GeminiNativePolicy) {
			p.Rules[0].ToolName = "run_shell_command"
			p.Rules[0].CommandPrefix = geminiString("git")
			p.Rules[0].MCPName = geminiString("remote")
		},
		"unknown mode":           func(p *GeminiNativePolicy) { p.Rules[0].Modes = []string{"auto_edit"} },
		"duplicate mode":         func(p *GeminiNativePolicy) { p.Rules[0].Modes = []string{"plan", "plan"} },
		"unsafe tool":            func(p *GeminiNativePolicy) { p.Rules[0].ToolName = "read_file\n[[rule]]" },
		"unknown sandbox":        func(p *GeminiNativePolicy) { p.Settings = &GeminiNativeSettings{SandboxDefault: "container"} },
		"wrong platform sandbox": func(p *GeminiNativePolicy) { p.Settings = &GeminiNativeSettings{SandboxDefault: "windows-native"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid()
			mutate(p)
			if out, err := compileNativeGemini(p, "linux"); err == nil || out != nil {
				t.Fatalf("invalid native policy accepted: %#v, %v", out, err)
			}
		})
	}
	if out, err := compileNativeGemini(nil, "linux"); err == nil || out != nil {
		t.Fatal("nil policy accepted")
	}
	if out, err := compileNativeGemini(valid(), "unsupported"); err == nil || out != nil {
		t.Fatal("unknown target OS accepted")
	}
}

func TestNativeGeminiDefaultsAndExplicitSettings(t *testing.T) {
	for _, decision := range []string{"deny", "ask_user"} {
		out, err := compileNativeGemini(&GeminiNativePolicy{DefaultDecision: decision}, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.Artifacts[0].Content, "sandbox") {
			t.Fatal("an unspecified sandbox must not silently become configured")
		}
	}
	f := false
	out, err := compileNativeGemini(&GeminiNativePolicy{DefaultDecision: "deny", Settings: &GeminiNativeSettings{DisableYOLOMode: &f, DisableAlwaysAllow: &f, SandboxDefault: "disabled"}}, "windows")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Security struct {
			DisableYOLOMode    bool `json:"disableYoloMode"`
			DisableAlwaysAllow bool `json:"disableAlwaysAllow"`
		} `json:"security"`
		Tools struct {
			Sandbox bool `json:"sandbox"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(out.Artifacts[0].Content), &data); err != nil {
		t.Fatal(err)
	}
	if data.Security.DisableYOLOMode || data.Security.DisableAlwaysAllow || data.Tools.Sandbox {
		t.Fatal("explicit false settings lost")
	}
}
