package compiler

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func loadPolicyText(t *testing.T, text string) (*UnifiedPolicy, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return LoadPolicy(path)
}

func TestClaudeSandboxYAMLForms(t *testing.T) {
	p, err := loadPolicyText(t, "version: 1\nname: one\nclaude:\n  sandbox: required\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Claude.Sandbox.For("linux"); got != ClaudeSandboxRequired {
		t.Errorf("scalar linux = %q", got)
	}
	if got := p.Claude.Sandbox.For("windows"); got != ClaudeSandboxRequired {
		t.Errorf("scalar windows = %q", got)
	}
	p, err = loadPolicyText(t, "version: 1\nname: split\nclaude:\n  sandbox:\n    unix: required\n    windows: tools-only\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Claude.Sandbox.For("darwin") != ClaudeSandboxRequired || p.Claude.Sandbox.For("windows") != ClaudeSandboxToolsOnly {
		t.Errorf("split sandbox = %+v", p.Claude.Sandbox)
	}
	for _, bad := range []string{
		"version: 1\nname: bad\nclaude:\n  sandbox: maybe\n",
		"version: 1\nname: bad\nclaude:\n  sandbox:\n    mac: required\n",
		"version: 1\nname: bad\nclaude:\n  sandbox:\n    unix: required\n    unix: tools-only\n",
		"version: 1\nname: bad\nclaude:\n  sandbox: [required]\n",
		"version: 1\nname: bad\nclaude:\n  other: true\n",
	} {
		if _, err := loadPolicyText(t, bad); err == nil {
			t.Errorf("accepted invalid claude section:\n%s", bad)
		}
	}
}

func basePolicy() *UnifiedPolicy {
	return &UnifiedPolicy{Version: 1, Name: "base", Sandbox: SandboxConfig{Modes: []string{"workspace-write"}}}
}

func withDenyRead(p *UnifiedPolicy) {
	p.Filesystem.DenyRead = PathGroup{Common: []string{"~/.ssh"}, Unix: []string{"/etc/shadow"}, Windows: []string{"C:/Secrets"}}
}

func withClaudeSandbox(mode string) func(*UnifiedPolicy) {
	return func(p *UnifiedPolicy) { p.Claude = &ClaudeConfig{Sandbox: ClaudeSandbox{Unix: mode, Windows: mode}} }
}

func withDefaultNetworkOff(p *UnifiedPolicy) {
	p.DefaultPermissions = "dev"
	p.AllowedPermissionProfiles = map[string]bool{"dev": true}
	p.PermissionDefs = map[string]PermissionDef{"dev": {Extends: ":workspace", Network: &PermissionNetwork{Enabled: false}}}
}

func combine(mutations ...func(*UnifiedPolicy)) func(*UnifiedPolicy) {
	return func(p *UnifiedPolicy) {
		for _, mutate := range mutations {
			mutate(p)
		}
	}
}

func TestCompileAgentCapabilityMatrix(t *testing.T) {
	readOnly, err := LoadPolicy(filepath.Join("..", "..", "profiles", "contractor-readonly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		name, os, agent string
		base            *UnifiedPolicy
		mutate          func(*UnifiedPolicy)
		wantErr         string
		wantToolLevel   []string
	}
	none := func(*UnifiedPolicy) {}
	rows := []row{
		{name: "read-only codex", os: "linux", agent: "codex", base: readOnly, mutate: none},
		{name: "read-only claude", os: "linux", agent: "claude", base: readOnly, mutate: none, wantErr: "read-only"},
		{name: "read-only opencode", os: "linux", agent: "opencode", base: readOnly, mutate: none, wantErr: "read-only"},
		{name: "deny_read codex", os: "linux", agent: "codex", mutate: withDenyRead},
		{name: "deny_read opencode", os: "linux", agent: "opencode", mutate: withDenyRead, wantErr: "deny_read"},
		{name: "deny_read claude unset", os: "linux", agent: "claude", mutate: withDenyRead, wantErr: "claude.sandbox must be set"},
		{name: "deny_read claude required linux", os: "linux", agent: "claude", mutate: combine(withDenyRead, withClaudeSandbox(ClaudeSandboxRequired))},
		{name: "deny_read claude required darwin", os: "darwin", agent: "claude", mutate: combine(withDenyRead, withClaudeSandbox(ClaudeSandboxRequired))},
		{name: "deny_read claude required windows", os: "windows", agent: "claude", mutate: combine(withDenyRead, withClaudeSandbox(ClaudeSandboxRequired)), wantErr: "no Claude sandbox on native Windows"},
		{name: "deny_read claude tools-only", os: "windows", agent: "claude", mutate: combine(withDenyRead, withClaudeSandbox(ClaudeSandboxToolsOnly)), wantToolLevel: []string{"filesystem.deny_read"}},
		{name: "permission filesystem codex", os: "linux", agent: "codex", mutate: func(p *UnifiedPolicy) {
			p.PermissionDefs = map[string]PermissionDef{"fs": {Filesystem: &PermissionFilesystem{Root: "deny"}}}
		}},
		{name: "permission filesystem claude", os: "linux", agent: "claude", mutate: func(p *UnifiedPolicy) {
			p.PermissionDefs = map[string]PermissionDef{"fs": {Filesystem: &PermissionFilesystem{Root: "deny"}}}
		}, wantErr: "filesystem boundaries"},
		{name: "permission filesystem opencode", os: "linux", agent: "opencode", mutate: func(p *UnifiedPolicy) {
			p.PermissionDefs = map[string]PermissionDef{"fs": {Filesystem: &PermissionFilesystem{Root: "deny"}}}
		}, wantErr: "filesystem boundaries"},
		{name: "default network off claude unset", os: "linux", agent: "claude", mutate: withDefaultNetworkOff, wantErr: "claude.sandbox must be set"},
		{name: "default network off claude required", os: "linux", agent: "claude", mutate: combine(withDefaultNetworkOff, withClaudeSandbox(ClaudeSandboxRequired))},
		{name: "default network off claude tools-only", os: "linux", agent: "claude", mutate: combine(withDefaultNetworkOff, withClaudeSandbox(ClaudeSandboxToolsOnly)), wantToolLevel: []string{"network.disabled"}},
		{name: "both needs tools-only order", os: "linux", agent: "claude", mutate: combine(withDenyRead, withDefaultNetworkOff, withClaudeSandbox(ClaudeSandboxToolsOnly)), wantToolLevel: []string{"filesystem.deny_read", "network.disabled"}},
		{name: "non-default network off claude", os: "linux", agent: "claude", mutate: func(p *UnifiedPolicy) {
			p.DefaultPermissions = "dev"
			p.PermissionDefs = map[string]PermissionDef{"dev": {Extends: ":workspace"}, "offline": {Extends: ":workspace", Network: &PermissionNetwork{Enabled: false}}}
			p.Claude = &ClaudeConfig{Sandbox: ClaudeSandbox{Unix: ClaudeSandboxRequired}}
		}, wantErr: "network.enabled=false"},
		{name: "unknown agent", os: "linux", agent: "gemini", mutate: none, wantErr: "unsupported unified agent"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var p UnifiedPolicy
			if r.base != nil {
				p = *r.base
			} else {
				p = *basePolicy()
			}
			r.mutate(&p)
			out, err := CompileAgent(&p, r.os, r.agent)
			if r.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), r.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, r.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Files) == 0 {
				t.Fatal("no files emitted")
			}
			if !reflect.DeepEqual(out.ToolLevelOnly, r.wantToolLevel) {
				t.Errorf("ToolLevelOnly = %v, want %v", out.ToolLevelOnly, r.wantToolLevel)
			}
		})
	}
}

func TestCompileAgentFiles(t *testing.T) {
	for agent, want := range map[string][]string{
		"codex":    {"codex.toml"},
		"claude":   {"claude.json"},
		"opencode": {"opencode.json", "opencode.instructions.md"},
	} {
		out, err := CompileAgent(basePolicy(), "linux", agent)
		if err != nil {
			t.Fatalf("%s: %v", agent, err)
		}
		var got []string
		for _, f := range out.Files {
			got = append(got, f.Extension)
			// The instructions sidecar is empty when a profile has none, as in v1.
			if f.Content == "" && !strings.HasSuffix(f.Extension, ".instructions.md") {
				t.Errorf("%s %s is empty", agent, f.Extension)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s files = %v, want %v", agent, got, want)
		}
	}
	for _, name := range []string{"codex", "claude", "opencode"} {
		if !IsUnifiedAgent(name) {
			t.Errorf("IsUnifiedAgent(%q) = false", name)
		}
	}
	if IsUnifiedAgent("cursor") {
		t.Error("cursor is native, not unified")
	}
}

func claudeJSON(t *testing.T, p *UnifiedPolicy, osName string) map[string]any {
	t.Helper()
	out, err := CompileAgent(p, osName, "claude")
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(out.Files[0].Content), &settings); err != nil {
		t.Fatal(err)
	}
	return settings
}

func TestClaudeRequiredSandboxOutput(t *testing.T) {
	p := basePolicy()
	withDenyRead(p)
	withClaudeSandbox(ClaudeSandboxRequired)(p)
	settings := claudeJSON(t, p, "linux")
	sandbox, ok := settings["sandbox"].(map[string]any)
	if !ok {
		t.Fatalf("missing sandbox block: %v", settings)
	}
	if sandbox["enabled"] != true || sandbox["failIfUnavailable"] != true || sandbox["allowUnsandboxedCommands"] != false {
		t.Errorf("sandbox switches = %v", sandbox)
	}
	fs, _ := sandbox["filesystem"].(map[string]any)
	if !reflect.DeepEqual(fs["denyRead"], []any{"~/.ssh", "/etc/shadow"}) || fs["allowManagedReadPathsOnly"] != true {
		t.Errorf("sandbox filesystem = %v", fs)
	}
	if _, present := sandbox["network"]; present {
		t.Errorf("network on must not add sandbox network keys: %v", sandbox["network"])
	}

	offline := basePolicy()
	withDefaultNetworkOff(offline)
	withClaudeSandbox(ClaudeSandboxRequired)(offline)
	network, _ := claudeJSON(t, offline, "darwin")["sandbox"].(map[string]any)["network"].(map[string]any)
	if network["strictAllowlist"] != true || network["allowManagedDomainsOnly"] != true || !reflect.DeepEqual(network["allowedDomains"], []any{}) {
		t.Errorf("network off sandbox = %v", network)
	}

	toolsOnly := basePolicy()
	withDenyRead(toolsOnly)
	withClaudeSandbox(ClaudeSandboxToolsOnly)(toolsOnly)
	if _, present := claudeJSON(t, toolsOnly, "linux")["sandbox"]; present {
		t.Error("tools-only output must not contain a sandbox block")
	}
}

// The combined compile command keeps its pre-existing checks and messages.
func TestCompileUnchangedWithoutClaudeSection(t *testing.T) {
	want := map[string]string{
		"contractor-readonly.yaml": "read-only policies cannot be compiled for all agents",
		"engineering.yaml":         "filesystem.deny_read is unsupported by the OpenCode adapter",
		"knowledge-worker.yaml":    "filesystem.deny_read is unsupported by the OpenCode adapter",
		"principal-eng.yaml":       "filesystem.deny_read is unsupported by the OpenCode adapter",
		"senior-dev.yaml":          "filesystem.deny_read is unsupported by the OpenCode adapter",
	}
	for file, message := range want {
		p, err := LoadPolicy(filepath.Join("..", "..", "profiles", file))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Compile(p, "linux"); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: Compile error = %v, want %q", file, err, message)
		}
	}
	p := basePolicy()
	p.Claude = &ClaudeConfig{Sandbox: ClaudeSandbox{Windows: ClaudeSandboxRequired}}
	if _, err := Compile(p, "windows"); err == nil || !strings.Contains(err.Error(), "no Claude sandbox on native Windows") {
		t.Errorf("Compile must not emit a Windows sandbox block: %v", err)
	}
}

func TestParsePolicyMatchesLoadPolicy(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "profiles", "*.yaml"))
	if len(files) == 0 {
		t.Fatal("no profiles found")
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		fromBytes, err1 := ParsePolicy(data)
		fromFile, err2 := LoadPolicy(file)
		if err1 != nil || err2 != nil || !reflect.DeepEqual(fromBytes, fromFile) {
			t.Errorf("%s: ParsePolicy and LoadPolicy disagree: %v / %v", file, err1, err2)
		}
	}
	for _, bad := range []string{"version: 1\nname: x\nbogus: 1\n", "version: 1\nname: x\n---\nversion: 1\n"} {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		os.WriteFile(path, []byte(bad), 0600)
		_, err1 := ParsePolicy([]byte(bad))
		_, err2 := LoadPolicy(path)
		if err1 == nil || err2 == nil || err1.Error() != err2.Error() {
			t.Errorf("errors differ for %q: %v / %v", bad, err1, err2)
		}
	}
}

func TestClaudeSandboxErrorIsTyped(t *testing.T) {
	p := basePolicy()
	withDenyRead(p)
	_, err := CompileAgent(p, "linux", "claude")
	if !errors.Is(err, ErrClaudeSandboxChoice) || !strings.Contains(err.Error(), "claude.sandbox must be set to required or tools-only") {
		t.Fatalf("error = %v", err)
	}
}
