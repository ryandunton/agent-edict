package compiler

import (
	"encoding/json"
	"fmt"

	"github.com/ryandunton/agent-edict/internal/cursorhook"
)

// CursorNativePolicy configures local machine hooks, independent of cloud administration.
type CursorNativePolicy struct {
	Hooks *cursorhook.Policy `yaml:"hooks"`
}

func compileNativeCursor(p *CursorNativePolicy, targetOS string) (*NativeOutput, error) {
	if p == nil || p.Hooks == nil {
		return nil, fmt.Errorf("cursor.hooks is required")
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	if err := cursorhook.ValidatePolicy(p.Hooks); err != nil {
		return nil, err
	}
	dir, separator, executable := "/etc/cursor", "/", "/usr/local/bin/edict"
	quote := func(value string) string { return "'" + value + "'" }
	if targetOS == "darwin" {
		dir = "/Library/Application Support/Cursor"
	} else if targetOS == "windows" {
		dir, separator, executable = `C:\ProgramData\Cursor`, `\`, `C:\Program Files\AgentEdict\edict.exe`
		quote = func(value string) string { return `"` + value + `"` }
	}
	policyPath := dir + separator + "agentedict-policy.json"
	type hookDefinition struct {
		Command    string `json:"command"`
		Timeout    int    `json:"timeout"`
		FailClosed bool   `json:"failClosed"`
	}
	hooks := map[string][]hookDefinition{}
	for _, event := range []string{"preToolUse", "beforeShellExecution", "beforeMCPExecution"} {
		hooks[event] = []hookDefinition{{
			Command:    quote(executable) + " hook cursor -event " + event + " -policy " + quote(policyPath),
			Timeout:    10,
			FailClosed: true,
		}}
	}
	hooksJSON, err := json.MarshalIndent(struct {
		Version int                         `json:"version"`
		Hooks   map[string][]hookDefinition `json:"hooks"`
	}{1, hooks}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Cursor hooks: %w", err)
	}
	policyJSON, err := json.MarshalIndent(p.Hooks, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Cursor hook rules: %w", err)
	}
	return &NativeOutput{
		Artifacts: []NativeArtifact{
			{Extension: "cursor.policy.json", Content: string(policyJSON) + "\n", Delivery: "system-file", Destination: policyPath},
			{Extension: "cursor.hooks.json", Content: string(hooksJSON) + "\n", Delivery: "system-file", Destination: dir + separator + "hooks.json"},
		},
		Capabilities: []NativeCapability{
			{Product: "cursor", Control: "tool_invocations", Level: "hook-guardrail", Details: "preToolUse permits only exact tools_allow names; omitted/empty lists deny all reported tool invocations. Source-verified names include Read, Write, Delete, List, Grep, Shell, Fetch, WriteShellStdin, ComputerUse, and MCP:<tool_name>. Shell and MCP calls must also pass their specific invocation hooks. No ask decision is emitted for this event."},
			{Product: "cursor", Control: "shell_invocations", Level: "hook-guardrail", Details: "Exact full command decisions in local beforeShellExecution hooks; unmatched commands deny. Requires the protected absolute edict executable and a compatible Cursor client invoking machine hooks with failClosed support. No cloud or enterprise administration credential is used."},
			{Product: "cursor", Control: "mcp_tool_invocations", Level: "hook-guardrail", Details: "Exact server name, endpoint or rendered launch command, and tool name in beforeMCPExecution; unmatched calls deny. MCP ask rules are rejected because Cursor 3.24.18's MCP executor does not enforce them. Does not prevent server startup or connection establishment."},
			{Product: "cursor", Control: "process_containment", Level: "not-enforced", Details: "Cursor 3.24.18 launches hooks through a user-influenced shell (SHELL on Unix; PowerShell resolution through PATH on Windows). An absolute evaluator path does not prevent client-environment bypass. Working directory, executable behavior, aliases, child processes, and network access are also outside this hook policy."},
			{Product: "cursor", Control: "filesystem", Level: "not-enforced", Details: "The generic tool gate can deny reported Read/Write/Delete invocations, but does not enforce path-specific or OS filesystem isolation. Allowed tools may access files through their own implementations. Coverage of Tab, cloud agents, unenrolled remote workspaces, and actions that omit preToolUse is not claimed."},
			{Product: "cursor", Control: "client_verification", Level: "static-source-verified", Details: "Official Cursor 3.24.18 source loads local system hooks without a team or entitlement condition and implements failClosed. This is not a live endpoint acceptance test or a complete invocation-coverage guarantee; standalone startup waits for hooks are bounded, remote windows use the remote machine's hooks, and installed-client acceptance must be checked after updates."},
		},
	}, nil
}
