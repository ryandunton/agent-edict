package compiler

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCompilerOutputs(t *testing.T) {
	sampleYAML := `
version: 1
name: "test-dev"
description: "Test developer profile"

sandbox:
  modes: ["read-only", "workspace-write"]

approval:
  policies: ["untrusted", "on-request"]
  bypass_mode: "forbidden"

web_search:
  modes: ["cached"]

filesystem:
  deny_read:
    common:
      - "~/.ssh"
    windows:
      - "C:/Windows/System32/config"
    unix:
      - "/etc/shadow"

commands:
  allow:
    common:
      - "git status"
  prompt:
    windows:
      - "Remove-Item"
    unix:
      - "rm -rf"
  deny:
    windows:
      - "icacls"
    unix:
      - "chmod"

mcp_servers:
  internal-docs:
    windows:
      command: "C:\\Program Files\\Docs\\mcp.exe"
    unix:
      command: "/usr/local/bin/docs-mcp"
    trust: true

otel:
  enabled: true
  endpoint: "https://otel.example.com:4318"
  log_user_prompt: false

flags:
  allow_managed_hooks_only: true
  disable_auto_update: true
`

	policy := &UnifiedPolicy{}
	if err := yamlUnmarshal([]byte(sampleYAML), policy); err != nil {
		t.Fatalf("Failed unmarshaling sample YAML: %v", err)
	}

	// Codex preserves filesystem restrictions; other adapters must reject them.
	winRequirements, _, err := CompileCodexOnly(policy, "windows")
	if err != nil {
		t.Fatal(err)
	}
	linuxRequirements, _, err := CompileCodexOnly(policy, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(policy, "windows"); err == nil {
		t.Fatal("cross-agent compilation silently weakened filesystem.deny_read")
	}
	adapterPolicy := *policy
	adapterPolicy.Filesystem = FSConfig{}
	winOut, err := Compile(&adapterPolicy, "windows")
	if err != nil {
		t.Fatalf("Failed compiling for windows: %v", err)
	}

	if !strings.Contains(winRequirements, `allow_managed_hooks_only = true`) {
		t.Errorf("Codex TOML missing allow_managed_hooks_only")
	}
	if !strings.Contains(winRequirements, `"C:/Windows/System32/config"`) {
		t.Errorf("Codex TOML missing Windows deny_read path")
	}
	if strings.Contains(winRequirements, `"/etc/shadow"`) {
		t.Errorf("Codex TOML on Windows should not include /etc/shadow")
	}

	// Claude Code JSON
	if !strings.Contains(winOut.ClaudeManagedSettings, `"disableBypassPermissionsMode": "disable"`) {
		t.Errorf("Claude settings missing disableBypassPermissionsMode")
	}
	if !strings.Contains(winOut.ClaudeManagedSettings, `Bash(icacls:*)`) {
		t.Errorf("Claude settings missing Windows icacls deny rule")
	}

	if winOut.GeminiSettingsJSON != "" {
		t.Error("unsupported Gemini adapter must not emit a managed policy")
	}

	// OpenCode JSON
	if !strings.Contains(winOut.OpenCodeJSON, `"icacls*": "deny"`) {
		t.Errorf("OpenCode JSON missing icacls deny rule")
	}

	if winOut.CursorJSON != "" {
		t.Error("unsupported Cursor adapter must not emit a policy")
	}

	// Test Linux Compilation
	_, err = Compile(&adapterPolicy, "linux")
	if err != nil {
		t.Fatalf("Failed compiling for linux: %v", err)
	}
	if !strings.Contains(linuxRequirements, `"/etc/shadow"`) {
		t.Errorf("Codex TOML on Linux should include /etc/shadow")
	}
	if strings.Contains(linuxRequirements, `"C:/Windows/System32/config"`) {
		t.Errorf("Codex TOML on Linux should not include Windows paths")
	}
}

func TestContractorReadOnlyCodexCompilation(t *testing.T) {
	policy, err := LoadPolicy("../../profiles/contractor-readonly.yaml")
	if err != nil {
		t.Fatal(err)
	}
	requirements, telemetry, err := CompileCodexOnly(policy, "linux")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`default_permissions = "contractor-readonly"`,
		`allowed_approval_policies = ["never"]`,
		`allowed_web_search_modes = []`,
		`allow_appshots = false`,
		`allow_browser_and_computer_use = false`,
		`mcp_servers = {}`,
		`[permissions.contractor-readonly.filesystem]`,
		`":root" = "deny"`,
		`[permissions.contractor-readonly.filesystem.":workspace_roots"]`,
		`"." = "read"`,
		`[permissions.contractor-readonly.network]`,
		`enabled = false`,
		`plugins = false`,
	} {
		if !strings.Contains(requirements, expected) {
			t.Errorf("Codex requirements missing %q", expected)
		}
	}
	if strings.Contains(requirements, "[otel]") {
		t.Error("OTEL settings must not appear in requirements.toml")
	}
	if !strings.Contains(telemetry, `[otel]`) || !strings.Contains(telemetry, `exporter = { otlp-http = { endpoint =`) {
		t.Error("separate Codex telemetry config is missing")
	}
	if _, err := Compile(policy, "linux"); err == nil {
		t.Error("cross-agent compilation must fail closed for read-only profiles")
	}
}

func TestLoadPolicyRejectsUnknownFields(t *testing.T) {
	path := t.TempDir() + "/policy.yaml"
	data := []byte("version: 1\nname: test\nflags:\n  unknown_security_flag: false\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Error("unknown security fields must not be silently ignored")
	}
}

func TestKnowledgeWorkerProfile(t *testing.T) {
	policy, err := LoadPolicy("../../profiles/knowledge-worker.yaml")
	if err != nil {
		t.Fatalf("Failed loading knowledge-worker.yaml: %v", err)
	}

	winRequirements, _, err := CompileCodexOnly(policy, "windows")
	if err != nil {
		t.Fatalf("Failed compiling knowledge-worker for windows: %v", err)
	}

	// Verify Codex Requirements TOML outputs exact requested fields
	if !strings.Contains(winRequirements, `default_permissions = "standard"`) {
		t.Errorf("Missing default_permissions = standard")
	}
	if !strings.Contains(winRequirements, `allowed_approvals_reviewers = ["auto_review", "user"]`) {
		t.Errorf("Missing allowed_approvals_reviewers")
	}
	if !strings.Contains(winRequirements, `allow_login_shell = false`) {
		t.Errorf("Missing allow_login_shell = false")
	}
	if !strings.Contains(winRequirements, `allow_remote_control = false`) {
		t.Errorf("Missing allow_remote_control = false")
	}
	if !strings.Contains(winRequirements, `[permissions.standard.network]`) {
		t.Errorf("Missing [permissions.standard.network]")
	}
	if !strings.Contains(winRequirements, `[browser_use.default_origin_policy]`) {
		t.Errorf("Missing [browser_use.default_origin_policy]")
	}
	if !strings.Contains(winRequirements, `uploads = "deny"`) {
		t.Errorf("Missing uploads = deny in browser_use")
	}
	if !strings.Contains(winRequirements, `[features]`) {
		t.Errorf("Missing [features]")
	}
	if !strings.Contains(winRequirements, `computer_use = false`) {
		t.Errorf("Missing computer_use = false")
	}
	if !strings.Contains(winRequirements, `additional_developer_instructions = """`) {
		t.Errorf("Missing additional_developer_instructions")
	}
	if !strings.Contains(winRequirements, `guardian_extra_policy = """`) {
		t.Errorf("Missing guardian_extra_policy")
	}
	if !strings.Contains(winRequirements, `allowed_sandbox_implementations = ["unelevated"]`) {
		t.Errorf("Missing Windows allowed_sandbox_implementations")
	}

	if _, err := Compile(policy, "windows"); err == nil {
		t.Error("cross-agent compilation must reject unsupported hard boundaries")
	}
}

func TestEngineeringProfile(t *testing.T) {
	policy, err := LoadPolicy("../../profiles/engineering.yaml")
	if err != nil {
		t.Fatalf("Failed loading engineering.yaml: %v", err)
	}

	winRequirements, _, err := CompileCodexOnly(policy, "windows")
	if err != nil {
		t.Fatalf("Failed compiling engineering for windows: %v", err)
	}

	// Verify Codex Requirements TOML outputs exact requested fields
	if !strings.Contains(winRequirements, `default_permissions = "engineering"`) {
		t.Errorf("Missing default_permissions = engineering")
	}
	if !strings.Contains(winRequirements, `allowed_approvals_reviewers = ["auto_review", "user"]`) {
		t.Errorf("Missing allowed_approvals_reviewers")
	}
	if !strings.Contains(winRequirements, `[permissions.engineering]`) {
		t.Errorf("Missing [permissions.engineering]")
	}
	if !strings.Contains(winRequirements, `[computer_use]`) {
		t.Errorf("Missing [computer_use]")
	}
	if !strings.Contains(winRequirements, `allow_locked_computer_use = false`) {
		t.Errorf("Missing allow_locked_computer_use = false")
	}
	if !strings.Contains(winRequirements, `plugins = true`) {
		t.Errorf("Missing plugins = true in features")
	}
	if !strings.Contains(winRequirements, `computer_use = false`) {
		t.Errorf("Missing computer_use = false in features")
	}
	if !strings.Contains(winRequirements, `For engineering changes involving authentication`) {
		t.Errorf("Missing engineering developer instructions")
	}
	if !strings.Contains(winRequirements, `## Engineering approval guidance`) {
		t.Errorf("Missing engineering guardian guidance")
	}
	if !strings.Contains(winRequirements, `allowed_sandbox_implementations = ["unelevated"]`) {
		t.Errorf("Missing Windows allowed_sandbox_implementations")
	}

	if _, err := Compile(policy, "windows"); err == nil {
		t.Error("cross-agent compilation must reject unsupported hard boundaries")
	}
}

func yamlUnmarshal(in []byte, out interface{}) error {
	return yaml.Unmarshal(in, out)
}
