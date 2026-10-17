package compiler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/antigravityhook"
)

func TestNativeAntigravityUsesDocumentedAppHooks(t *testing.T) {
	for _, osName := range []string{"linux", "darwin", "windows"} {
		t.Run(osName, func(t *testing.T) {
			p := &AntigravityNativePolicy{Hooks: &antigravityhook.Policy{Version: 1}}
			out, err := compileNativeAntigravity(p, osName)
			if err != nil {
				t.Fatal(err)
			}
			if out == nil || len(out.Artifacts) != 2 {
				t.Fatalf("want policy and registration, got %#v", out)
			}
			var policy antigravityhook.Policy
			if err := json.Unmarshal([]byte(out.Artifacts[0].Content), &policy); err != nil {
				t.Fatal(err)
			}
			if policy.Version != 1 || out.Artifacts[0].Delivery != "system-file" || out.Artifacts[0].Extension != "antigravity.policy.json" {
				t.Fatalf("bad policy: %#v", out.Artifacts[0])
			}
			policyPath := "/etc/agent-edict/antigravity-policy.json"
			binary := "/usr/local/bin/edict"
			if osName == "windows" {
				policyPath = `C:\ProgramData\AgentEdict\antigravity-policy.json`
				binary = `C:\Program Files\AgentEdict\edict.exe`
			}
			if out.Artifacts[0].Destination != policyPath {
				t.Fatalf("wrong policy destination %q", out.Artifacts[0].Destination)
			}
			hookArtifact := out.Artifacts[1]
			if hookArtifact.Extension != "antigravity.hooks.json" || hookArtifact.Delivery != "user-registration" || hookArtifact.Destination != "~/.gemini/config/hooks.json" {
				t.Fatalf("bad registration artifact: %#v", hookArtifact)
			}
			var hooks map[string]struct {
				Enabled    bool `json:"enabled"`
				PreToolUse []struct {
					Matcher string `json:"matcher"`
					Hooks   []struct {
						Type    string `json:"type"`
						Command string `json:"command"`
						Timeout int    `json:"timeout"`
					} `json:"hooks"`
				} `json:"PreToolUse"`
			}
			if err := json.Unmarshal([]byte(hookArtifact.Content), &hooks); err != nil {
				t.Fatal(err)
			}
			h := hooks["agent-edict"]
			if len(hooks) != 1 || !h.Enabled || len(h.PreToolUse) != 1 || h.PreToolUse[0].Matcher != "*" || len(h.PreToolUse[0].Hooks) != 1 {
				t.Fatalf("invalid native named hook: %s", hookArtifact.Content)
			}
			command := h.PreToolUse[0].Hooks[0]
			if command.Type != "command" || command.Timeout != 10 || !strings.Contains(command.Command, binary) || !strings.Contains(command.Command, " hook antigravity -policy ") || !strings.Contains(command.Command, policyPath) {
				t.Fatalf("bad hook command: %#v", command)
			}
			if osName == "windows" && !strings.HasPrefix(command.Command, `call "C:\Program Files\AgentEdict\edict.exe" `) {
				t.Fatalf("Windows cmd /c needs an unambiguous quoted executable invocation: %s", command.Command)
			}
			foundLimit := false
			for _, capability := range out.Capabilities {
				if capability.Control == "mandatory_registration" && capability.Level == "not-enforced" {
					foundLimit = true
				}
			}
			if !foundLimit {
				t.Fatal("missing user-disableable registration capability limit")
			}
		})
	}
}

func TestNativeAntigravityRejectsUnsupportedPolicies(t *testing.T) {
	for _, p := range []*AntigravityNativePolicy{nil, {}, {Hooks: &antigravityhook.Policy{}}, {Hooks: &antigravityhook.Policy{Version: 1, Tools: map[string]string{"mcp_any": "allow"}}}, {Hooks: &antigravityhook.Policy{Version: 1, ReadRoots: []string{"relative"}}}} {
		if _, err := compileNativeAntigravity(p, "linux"); err == nil {
			t.Fatalf("accepted invalid policy %#v", p)
		}
	}
	if _, err := compileNativeAntigravity(&AntigravityNativePolicy{Hooks: &antigravityhook.Policy{Version: 1}}, "unknown"); err == nil {
		t.Fatal("accepted unknown OS")
	}
}
