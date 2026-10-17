package compiler

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func boolPtr(v bool) *bool { return &v }

func copilotFixture() *CopilotNativePolicy {
	allowed := []CopilotMCPMatcher{{URL: "https://api.githubcopilot.com/*"}, {Command: []string{"npx", "@playwright/mcp@latest"}}}
	return &CopilotNativePolicy{
		Permissions: CopilotPermissions{Allow: []string{"Shell(npm test *)"}, Ask: []string{"Shell(git push *)"}, Deny: []string{"Shell(rm -rf *)", "Read(~/.ssh/**)"}},
		MCP:         &CopilotMCPPolicy{Allowed: &allowed, Denied: []CopilotMCPMatcher{{Name: "filesystem"}}},
		Sandbox:     &CopilotSandbox{Enabled: boolPtr(true), FailIfUnavailable: boolPtr(true), AllowBypass: boolPtr(false)},
		ComputerUse: boolPtr(false),
	}
}

func singleArtifact(t *testing.T, out *NativeOutput) NativeArtifact {
	t.Helper()
	if len(out.Artifacts) != 1 {
		t.Fatalf("expected one artifact, got %d", len(out.Artifacts))
	}
	return out.Artifacts[0]
}

func TestCopilotManagedSettingsUseDocumentedKeysAndPaths(t *testing.T) {
	for osName, path := range map[string]string{
		"linux":   "/etc/github-copilot/managed-settings.json",
		"darwin":  "/Library/Application Support/GitHubCopilot/managed-settings.json",
		"windows": `C:\Program Files\GitHubCopilot\managed-settings.json`,
	} {
		out, err := compileNativeCopilot(copilotFixture(), osName)
		if err != nil {
			t.Fatal(err)
		}
		artifact := singleArtifact(t, out)
		if artifact.Destination != path || artifact.Extension != "copilot.json" || artifact.Delivery != "system-file" {
			t.Fatalf("%s: wrong artifact %+v", osName, artifact)
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(artifact.Content), &settings); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{
			"permissions": map[string]any{
				"disableBypassPermissionsMode": "disable",
				"allow":                        []any{"Shell(npm test *)"},
				"ask":                          []any{"Shell(git push *)"},
				"deny":                         []any{"Shell(rm -rf *)", "Read(~/.ssh/**)"},
			},
			"allowedMcpServers": []any{map[string]any{"serverUrl": "https://api.githubcopilot.com/*"}, map[string]any{"serverCommand": []any{"npx", "@playwright/mcp@latest"}}},
			"deniedMcpServers":  []any{map[string]any{"serverName": "filesystem"}},
			"sandbox":           map[string]any{"enabled": true, "failIfUnavailable": true, "allowBypass": false},
			"features":          map[string]any{"computerUse": false},
		}
		if !reflect.DeepEqual(settings, want) {
			t.Fatalf("%s: unexpected settings\n got %v\nwant %v", osName, settings, want)
		}
	}
}

func TestCopilotEmptyAllowlistSurvivesBundleRoundTrip(t *testing.T) {
	empty := []CopilotMCPMatcher{}
	p := &NativePolicy{Version: 1, Name: "lockdown", Copilot: &CopilotNativePolicy{MCP: &CopilotMCPPolicy{Allowed: &empty}}}
	data, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	before, err := CompileNative(p, "linux", "all")
	if err != nil {
		t.Fatal(err)
	}
	after, err := CompileNative(decoded, "linux", "all")
	if err != nil {
		t.Fatal(err)
	}
	if before.Artifacts[0].Content != after.Artifacts[0].Content {
		t.Fatalf("endpoint recompilation differs:\n%s\n%s", before.Artifacts[0].Content, after.Artifacts[0].Content)
	}
	if !strings.Contains(after.Artifacts[0].Content, `"allowedMcpServers": []`) {
		t.Fatalf("empty allowlist (block all) was lost: %s", after.Artifacts[0].Content)
	}
}

func TestCopilotDefaultsAndRejections(t *testing.T) {
	out, err := compileNativeCopilot(&CopilotNativePolicy{}, "linux")
	if err != nil || !strings.Contains(singleArtifact(t, out).Content, `"disableBypassPermissionsMode": "disable"`) {
		t.Fatalf("bypass mode must be disabled by default: %v", err)
	}
	for name, p := range map[string]*CopilotNativePolicy{
		"nil":                  nil,
		"nothing managed":      {DisableBypassMode: boolPtr(false)},
		"bare selector":        {Permissions: CopilotPermissions{Deny: []string{"rm -rf"}}},
		"unknown selector":     {Permissions: CopilotPermissions{Deny: []string{"Network(*)"}}},
		"conflicting selector": {Permissions: CopilotPermissions{Allow: []string{"Shell(ls)"}, Deny: []string{"Shell(ls)"}}},
		"two matchers":         {MCP: &CopilotMCPPolicy{Denied: []CopilotMCPMatcher{{Name: "a", URL: "https://x"}}}},
		"no matcher":           {MCP: &CopilotMCPPolicy{Denied: []CopilotMCPMatcher{{}}}},
		"wildcard name":        {MCP: &CopilotMCPPolicy{Denied: []CopilotMCPMatcher{{Name: "git*"}}}},
		"credential URL":       {MCP: &CopilotMCPPolicy{Denied: []CopilotMCPMatcher{{URL: "https://u:p@x"}}}},
		"empty sandbox":        {Sandbox: &CopilotSandbox{}},
	} {
		if _, err := compileNativeCopilot(p, "linux"); err == nil {
			t.Errorf("%s: invalid Copilot policy compiled", name)
		}
	}
}

func TestCopilotDisclosesKnownBypassAndLimits(t *testing.T) {
	out, err := compileNativeCopilot(copilotFixture(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	controls := map[string]NativeCapability{}
	for _, c := range out.Capabilities {
		controls[c.Control] = c
	}
	if controls["bypass_mode"].Level != "partial" || !strings.Contains(controls["bypass_mode"].Details, "4528") {
		t.Errorf("open non-interactive bypass issue must be disclosed: %+v", controls["bypass_mode"])
	}
	if controls["sandbox"].Level != "enforced" || controls["client_verification"].Level != "not-verified" {
		t.Errorf("unexpected capability levels: %+v", controls)
	}
}

func TestKiroManagedSettingsUseDocumentedSchemaAndPaths(t *testing.T) {
	p := &KiroNativePolicy{
		Rules: []KiroRule{
			{Capability: "shell", Match: []string{"rm *", "sudo *"}, Effect: "deny"},
			{Capability: "fs_write", Match: []string{"~/**"}, Exclude: []string{"~/.kiro/**"}, Effect: "ask"},
			{Capability: "web_fetch", Effect: "deny"},
			{Capability: "signin_method", Match: []string{"github"}, Effect: "deny"},
		},
		SigninHelpURL: "https://it.example.com/help",
	}
	for osName, path := range map[string]string{
		"linux":   "/etc/kiro/managed-settings.json",
		"darwin":  "/Library/Application Support/Kiro/managed-settings.json",
		"windows": `C:\ProgramData\Kiro\managed-settings.json`,
	} {
		out, err := compileNativeKiro(p, osName)
		if err != nil {
			t.Fatal(err)
		}
		artifact := singleArtifact(t, out)
		if artifact.Destination != path || artifact.Extension != "kiro.json" {
			t.Fatalf("%s: wrong artifact %+v", osName, artifact)
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(artifact.Content), &settings); err != nil {
			t.Fatal(err)
		}
		rules := settings["rules"].([]any)
		if len(settings) != 2 || len(rules) != 4 || settings["settings"].(map[string]any)["signin_help_url"] != "https://it.example.com/help" {
			t.Fatalf("unexpected Kiro file: %s", artifact.Content)
		}
		// Kiro rejects the whole file when a rule carries an unknown field.
		for _, rule := range rules {
			for key := range rule.(map[string]any) {
				if key != "capability" && key != "match" && key != "exclude" && key != "effect" {
					t.Fatalf("unknown rule field %q", key)
				}
			}
		}
		if _, hasExclude := rules[0].(map[string]any)["exclude"]; hasExclude {
			t.Fatal("empty exclude must be omitted")
		}
	}
}

func TestKiroRejectsRulesKiroCannotHonor(t *testing.T) {
	for name, p := range map[string]*KiroNativePolicy{
		"nil":                 nil,
		"no rules":            {},
		"admin allow":         {Rules: []KiroRule{{Capability: "shell", Effect: "allow"}}},
		"unknown capability":  {Rules: []KiroRule{{Capability: "network", Effect: "deny"}}},
		"shell double star":   {Rules: []KiroRule{{Capability: "shell", Match: []string{"rm **"}, Effect: "deny"}}},
		"shell question mark": {Rules: []KiroRule{{Capability: "shell", Match: []string{"rm ?"}, Effect: "deny"}}},
		"signin ask":          {Rules: []KiroRule{{Capability: "signin_method", Match: []string{"github"}, Effect: "ask"}}},
		"signin unknown":      {Rules: []KiroRule{{Capability: "signin_method", Match: []string{"okta"}, Effect: "deny"}}},
		"http help URL":       {Rules: []KiroRule{{Capability: "web_fetch", Effect: "deny"}}, SigninHelpURL: "http://it.example.com"},
	} {
		if _, err := compileNativeKiro(p, "linux"); err == nil {
			t.Errorf("%s: invalid Kiro policy compiled", name)
		}
	}
}
