package compiler

import (
	"encoding/json"
	"fmt"

	"github.com/ryandunton/agent-edict/internal/antigravityhook"
)

// AntigravityNativePolicy configures the App's documented local PreToolUse hook.
// Hook registration is per user and does not establish machine containment.
type AntigravityNativePolicy struct {
	Hooks *antigravityhook.Policy `yaml:"hooks"`
}

func compileNativeAntigravity(p *AntigravityNativePolicy, targetOS string) (*NativeOutput, error) {
	if p == nil || p.Hooks == nil {
		return nil, fmt.Errorf("antigravity.hooks is required")
	}
	if err := antigravityhook.Validate(*p.Hooks, targetOS); err != nil {
		return nil, err
	}
	policyPath, executable := "/etc/agent-edict/antigravity-policy.json", "/usr/local/bin/edict"
	quote := func(s string) string { return "'" + s + "'" }
	if targetOS == "windows" {
		policyPath, executable = `C:\ProgramData\AgentEdict\antigravity-policy.json`, `C:\Program Files\AgentEdict\edict.exe`
		quote = func(s string) string { return `"` + s + `"` }
	}
	command := quote(executable) + " hook antigravity -policy " + quote(policyPath)
	if targetOS == "windows" {
		// App command hooks use cmd /c on Windows. CALL avoids cmd's special
		// stripping of an initial quoted executable when later quotes are present.
		command = "call " + command
	}
	// This is the App's named-hook format. It is intentionally separate from
	// Gemini CLI hook settings, and the user must enroll this global registration.
	registration := map[string]any{
		"agent-edict": map[string]any{
			"enabled": true,
			"PreToolUse": []any{map[string]any{
				"matcher": "*",
				"hooks": []any{map[string]any{
					"type":    "command",
					"command": command,
					"timeout": 10,
				}},
			}},
		},
	}
	policyJSON, err := json.MarshalIndent(p.Hooks, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Antigravity hook policy: %w", err)
	}
	hooksJSON, err := json.MarshalIndent(registration, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Antigravity hook registration: %w", err)
	}
	return &NativeOutput{
		Artifacts: []NativeArtifact{
			{Extension: "antigravity.policy.json", Content: string(policyJSON) + "\n", Delivery: "system-file", Destination: policyPath},
			{Extension: "antigravity.hooks.json", Content: string(hooksJSON) + "\n", Delivery: "user-registration", Destination: "~/.gemini/config/hooks.json"},
		},
		Capabilities: []NativeCapability{
			{Product: "antigravity", Control: "tool_invocations", Level: "hook-guardrail", Details: "App PreToolUse hook evaluates explicitly permitted built-in tools, exact terminal command and directory pairs, canonical file roots, and HTTPS origins. Unlisted tools, including MCP tools without authenticated server identity, deny. No enterprise administration credential is used."},
			{Product: "antigravity", Control: "mandatory_registration", Level: "not-enforced", Details: "Each user must enroll the global hook. Users can disable it in App settings or edit their registration. Machine policy installation does not enroll all sessions or prevent alternate clients and configuration roots."},
			{Product: "antigravity", Control: "process_containment", Level: "not-enforced", Details: "Preflight tool decisions do not sandbox processes, bind executable identity, prevent filesystem races, or restrict redirected and child-process network access. MCP tool denial does not prevent server startup or connections."},
			{Product: "antigravity", Control: "client_verification", Level: "not-verified", Details: "Native hook schema and decision semantics follow the App documentation. Timeout, execution-error behavior, global/workspace merge precedence, and invocation coverage require installed-client verification. Evaluator parse errors emit deny; that does not establish App failure behavior."},
		},
	}, nil
}
