package compiler

import (
	"encoding/json"
	"fmt"

	"github.com/ryandunton/agent-edict/internal/clinehook"
)

// ClineNativePolicy configures a per-user PreToolUse hook. Cline has no
// machine-wide managed configuration; its remote configuration is delivered
// only by Cline's hosted service.
type ClineNativePolicy struct {
	Hooks *clinehook.Policy `yaml:"hooks"`
}

func clinePolicyPath(targetOS string) string {
	if targetOS == "windows" {
		return `C:\ProgramData\AgentEdict\cline-policy.json`
	}
	return "/etc/agent-edict/cline-policy.json"
}

// ClineUserHook returns the PreToolUse file name and content that
// `edict install-hook cline` writes into each user's Cline hooks directories.
// Cline runs extensionless hooks on Unix and PreToolUse.ps1 on Windows.
func ClineUserHook(targetOS string) (string, string) {
	if targetOS == "windows" {
		return "PreToolUse.ps1", "# Installed by AgentEdict. Removing this file disables the Cline guardrail for this user.\r\n" +
			windowsHookStdin + "& 'C:\\Program Files\\AgentEdict\\edict.exe' hook cline -policy '" + clinePolicyPath(targetOS) + "'\r\n" +
			"exit $LASTEXITCODE\r\n"
	}
	return "PreToolUse", "#!/bin/sh\n# Installed by AgentEdict. Removing this file disables the Cline guardrail for this user.\n" +
		"exec '/usr/local/bin/edict' hook cline -policy '" + clinePolicyPath(targetOS) + "'\n"
}

func compileNativeCline(p *ClineNativePolicy, targetOS string) (*NativeOutput, error) {
	if p == nil || p.Hooks == nil {
		return nil, fmt.Errorf("cline.hooks is required")
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	if err := clinehook.ValidatePolicy(p.Hooks); err != nil {
		return nil, err
	}
	policy := *p.Hooks
	if policy.Tools == nil {
		policy.Tools = map[string]string{}
	}
	if policy.Commands == nil {
		policy.Commands = []string{}
	}
	policyJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Cline hook policy: %w", err)
	}
	return &NativeOutput{
		Artifacts: []NativeArtifact{
			{Extension: "cline.policy.json", Content: string(policyJSON) + "\n", Delivery: "system-file", Destination: clinePolicyPath(targetOS)},
		},
		Capabilities: []NativeCapability{
			{Product: "cline", Control: "tool_invocations", Level: "hook-guardrail", Details: "A PreToolUse hook cancels any tool not set to allow, and any run_commands or execute_command request containing a command that is not an exact listed match. In the VS Code extension a cancel stops the whole run. Hooks do not see MCP server identity."},
			{Product: "cline", Control: "mandatory_registration", Level: "not-enforced", Details: "Each user runs edict install-hook cline, which writes Documents/Cline/Hooks (VS Code extension) and ~/.cline/hooks (CLI). The user can remove the hook; the extension runs hooks only when the user's Enable Hooks setting is on, and Cline disables hooks in --yolo mode."},
			{Product: "cline", Control: "failure_mode", Level: "not-enforced", Details: "Cline treats hook timeouts, crashes, non-zero exits and invalid output as permission to run. The evaluator answers every request, including malformed ones, with valid cancel JSON, but a missing or unlaunchable evaluator fails open. The CLI runs .ps1 hooks without an execution-policy override."},
			{Product: "cline", Control: "remote_configuration", Level: "not-supported", Details: "Cline's remote configuration is delivered only by Cline's hosted service, and Cline documents Allow YOLO mode as unsupported in every client (cline/cline#14765). AgentEdict emits no remote configuration."},
			{Product: "cline", Control: "client_verification", Level: "not-verified", Details: "Payload shapes and hook locations follow Cline's source for the SDK-based CLI and VS Code extension. Installed-client acceptance has not been verified."},
		},
	}, nil
}
