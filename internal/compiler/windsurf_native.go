package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ryandunton/agent-edict/internal/windsurfhook"
)

// WindsurfNativePolicy configures Cascade system-level pre-hooks for Devin
// Desktop and the legacy Windsurf locations. It is not an OS sandbox.
type WindsurfNativePolicy struct {
	Hooks *windsurfhook.Policy `yaml:"hooks"`
}

// windowsHookStdin forwards Cascade's UTF-8 payload to a native executable.
// Hooks may run without a console, so console encoding APIs are avoided.
const windowsHookStdin = "$OutputEncoding = [Text.UTF8Encoding]::new($false); $in = New-Object IO.MemoryStream; [Console]::OpenStandardInput().CopyTo($in); [Text.Encoding]::UTF8.GetString($in.ToArray()) | "

func compileNativeWindsurf(p *WindsurfNativePolicy, targetOS string) (*NativeOutput, error) {
	if p == nil || p.Hooks == nil {
		return nil, fmt.Errorf("windsurf.hooks is required")
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	if err := windsurfhook.ValidatePolicy(p.Hooks); err != nil {
		return nil, err
	}
	policy := *p.Hooks
	if policy.Commands == nil {
		policy.Commands = []string{}
	}
	if policy.MCP == nil {
		policy.MCP = []windsurfhook.MCPRule{}
	}
	policyPath, hooksPath := "/etc/agent-edict/windsurf-policy.json", "/etc/devin/hooks.json"
	executable := "'/usr/local/bin/edict'"
	quote := func(s string) string { return "'" + s + "'" }
	if targetOS == "darwin" {
		hooksPath = "/Library/Application Support/Devin/hooks.json"
	} else if targetOS == "windows" {
		policyPath, hooksPath = `C:\ProgramData\AgentEdict\windsurf-policy.json`, `C:\ProgramData\Devin\hooks.json`
		executable = `& 'C:\Program Files\AgentEdict\edict.exe'`
	}
	type hook struct {
		Command    string `json:"command,omitempty"`
		PowerShell string `json:"powershell,omitempty"`
	}
	hooks := map[string][]hook{}
	for _, event := range windsurfhook.Events {
		invocation := executable + " hook windsurf -event " + event + " -policy " + quote(policyPath)
		if targetOS == "windows" {
			// powershell -Command turns a native exit code 2 into 1, and only 2 blocks.
			hooks[event] = []hook{{PowerShell: windowsHookStdin + invocation + "; exit $LASTEXITCODE"}}
		} else {
			hooks[event] = []hook{{Command: invocation}}
		}
	}
	var hooksJSON bytes.Buffer
	enc := json.NewEncoder(&hooksJSON)
	enc.SetEscapeHTML(false) // keep PowerShell's & readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"hooks": hooks}); err != nil {
		return nil, fmt.Errorf("encode Windsurf hooks: %w", err)
	}
	policyJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Windsurf hook policy: %w", err)
	}
	return &NativeOutput{
		Artifacts: []NativeArtifact{
			{Extension: "windsurf.policy.json", Content: string(policyJSON) + "\n", Delivery: "system-file", Destination: policyPath},
			{Extension: "windsurf.hooks.json", Content: hooksJSON.String(), Delivery: "system-file", Destination: hooksPath},
		},
		Capabilities: []NativeCapability{
			{Product: "windsurf", Control: "command_invocations", Level: "hook-guardrail", Details: "A system pre_run_command hook exits 2, blocking the command, unless the exact command line is listed. System hooks merge with cloud, user and workspace hooks and cannot be disabled without administrator rights. Installed at the Devin Desktop path and the legacy Windsurf path, which Devin Desktop reads only when its own file is absent."},
			{Product: "windsurf", Control: "mcp_tool_invocations", Level: "hook-guardrail", Details: "pre_mcp_tool_use blocks unless the exact MCP server label and tool name are listed. Server labels are user-chosen, not authenticated identities. Does not prevent server startup or connections."},
			{Product: "windsurf", Control: "failure_mode", Level: "not-enforced", Details: "Cascade blocks only on exit code 2. Any other exit code, a missing or unlaunchable evaluator, or Restricted Mode (where hooks do not run) lets the action proceed. On Windows the hook ends with exit $LASTEXITCODE because powershell -Command otherwise converts 2 to 1."},
			{Product: "windsurf", Control: "filesystem", Level: "not-enforced", Details: "pre_read_code and pre_write_code are not registered; file reads and writes are not path-restricted by this adapter."},
			{Product: "windsurf", Control: "client_verification", Level: "not-verified", Details: "Hook schema, paths and exit-code semantics follow Devin Desktop's Cascade hooks documentation. Installed-client acceptance has not been verified."},
		},
	}, nil
}
