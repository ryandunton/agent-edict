package compiler

import (
	"errors"
	"fmt"
	"sort"
)

// AgentFile is one compiled file, named by its bundle extension.
type AgentFile struct {
	Extension string
	Content   string
}

// AgentOutput is everything one unified agent needs for one profile and OS.
// ToolLevelOnly lists settings the agent enforces only in its own tools.
type AgentOutput struct {
	Files         []AgentFile
	ToolLevelOnly []string
}

var unifiedAgents = []string{"codex", "claude", "opencode"}

// ErrClaudeSandboxChoice reports a profile that needs Claude's OS sandbox to
// block shell commands but doesn't say whether to require it.
var ErrClaudeSandboxChoice = errors.New("claude.sandbox must be set to required or tools-only")

// IsUnifiedAgent reports whether name is compiled from unified profiles.
func IsUnifiedAgent(name string) bool {
	for _, agent := range unifiedAgents {
		if agent == name {
			return true
		}
	}
	return false
}

// CompileAgent compiles p for one agent, rejecting only the settings that
// agent cannot enforce. It never emits a weaker file in place of a rejection.
func CompileAgent(p *UnifiedPolicy, targetOS, agent string) (*AgentOutput, error) {
	if err := validatePolicy(p); err != nil {
		return nil, err
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	isWindows := targetOS == "windows"
	switch agent {
	case "codex":
		if isStrictReadOnly(p) {
			if err := validateStrictReadOnly(p); err != nil {
				return nil, err
			}
		}
		requirements, err := compileCodex(p, isWindows)
		if err != nil {
			return nil, fmt.Errorf("compile codex: %w", err)
		}
		return &AgentOutput{Files: []AgentFile{{Extension: "codex.toml", Content: requirements}}}, nil
	case "claude":
		mode, toolLevel, err := claudeSandboxMode(p, targetOS)
		if err != nil {
			return nil, err
		}
		settings, err := compileClaude(p, isWindows, mode)
		if err != nil {
			return nil, fmt.Errorf("compile claude: %w", err)
		}
		return &AgentOutput{Files: []AgentFile{{Extension: "claude.json", Content: settings}}, ToolLevelOnly: toolLevel}, nil
	case "opencode":
		if err := openCodeRejection(p, isWindows); err != nil {
			return nil, err
		}
		config, err := compileOpenCode(p, targetOS)
		if err != nil {
			return nil, fmt.Errorf("compile opencode: %w", err)
		}
		return &AgentOutput{Files: []AgentFile{
			{Extension: "opencode.json", Content: config},
			{Extension: "opencode.instructions.md", Content: compileInstructions(p)},
		}}, nil
	default:
		return nil, fmt.Errorf("unsupported unified agent %q", agent)
	}
}

// openCodeRejection holds the checks the combined compile applied before
// per-agent compilation existed; OpenCode cannot enforce any of them.
func openCodeRejection(p *UnifiedPolicy, isWindows bool) error {
	if isStrictReadOnly(p) {
		return fmt.Errorf("read-only policies cannot be compiled for all agents: use Codex-only compilation until the other adapters enforce no-write boundaries")
	}
	if len(getPathList(p.Filesystem.DenyRead, isWindows)) > 0 {
		return fmt.Errorf("filesystem.deny_read is unsupported by the OpenCode adapter; use Codex-only compilation")
	}
	for name, def := range p.PermissionDefs {
		if def.Filesystem != nil || def.Extends == ":read-only" {
			return fmt.Errorf("permissions.%s filesystem boundaries are unsupported by the Claude and OpenCode adapters; use Codex-only compilation", name)
		}
		if def.Network != nil && !def.Network.Enabled {
			return fmt.Errorf("permissions.%s.network.enabled=false cannot be enforced by the Claude and OpenCode adapters; use Codex-only compilation", name)
		}
	}
	if p.DefaultPermissions == ":read-only" {
		return fmt.Errorf("default_permissions=:read-only cannot be enforced by the Claude and OpenCode adapters; use Codex-only compilation")
	}
	return nil
}

// claudeNetworkDisabled reports whether the active permission profile turns
// command networking off.
func claudeNetworkDisabled(p *UnifiedPolicy) bool {
	def, ok := p.PermissionDefs[p.DefaultPermissions]
	return p.DefaultPermissions != "" && ok && def.Network != nil && !def.Network.Enabled
}

// claudeSandboxMode rejects what Claude cannot enforce and returns the
// profile's sandbox choice for targetOS. Settings that block shell commands
// only through Claude's OS sandbox require an explicit choice.
func claudeSandboxMode(p *UnifiedPolicy, targetOS string) (string, []string, error) {
	isWindows := targetOS == "windows"
	if isStrictReadOnly(p) {
		return "", nil, fmt.Errorf("read-only policies cannot be compiled for Claude: its adapter cannot enforce no-write boundaries")
	}
	if p.DefaultPermissions == ":read-only" {
		return "", nil, fmt.Errorf("default_permissions=:read-only cannot be enforced by the Claude adapter")
	}
	names := make([]string, 0, len(p.PermissionDefs))
	for name := range p.PermissionDefs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		def := p.PermissionDefs[name]
		if def.Filesystem != nil || def.Extends == ":read-only" {
			return "", nil, fmt.Errorf("permissions.%s filesystem boundaries are unsupported by the Claude adapter", name)
		}
		if def.Network != nil && !def.Network.Enabled && name != p.DefaultPermissions {
			return "", nil, fmt.Errorf("permissions.%s.network.enabled=false cannot be enforced by the Claude adapter: Claude has no permission profiles to switch to", name)
		}
	}
	var needs []string
	if len(getPathList(p.Filesystem.DenyRead, isWindows)) > 0 {
		needs = append(needs, "filesystem.deny_read")
	}
	if claudeNetworkDisabled(p) {
		needs = append(needs, "network.disabled")
	}
	mode := ""
	if p.Claude != nil {
		mode = p.Claude.Sandbox.For(targetOS)
	}
	if mode == ClaudeSandboxRequired && isWindows {
		return "", nil, fmt.Errorf("claude.sandbox=required: there is no Claude sandbox on native Windows; set claude.sandbox.windows to tools-only")
	}
	if len(needs) > 0 && mode == "" {
		return "", nil, fmt.Errorf("%w for %s: %v need OS enforcement of Claude's shell commands", ErrClaudeSandboxChoice, targetOS, needs)
	}
	if mode == ClaudeSandboxToolsOnly {
		return mode, needs, nil
	}
	return mode, nil, nil
}
