package compiler

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/pelletier/go-toml/v2"
)

// GeminiNativePolicy describes Gemini's native tool policy, not an OS sandbox.
type GeminiNativePolicy struct {
	DefaultDecision string                `yaml:"default_decision"`
	Rules           []GeminiNativeRule    `yaml:"rules,omitempty"`
	Settings        *GeminiNativeSettings `yaml:"settings,omitempty"`
}

type GeminiNativeRule struct {
	ToolName      string   `yaml:"tool_name"`
	Decision      string   `yaml:"decision"`
	Priority      int      `yaml:"priority"`
	CommandPrefix *string  `yaml:"command_prefix,omitempty"`
	MCPName       *string  `yaml:"mcp_name,omitempty"`
	Modes         []string `yaml:"modes,omitempty"`
	DenyMessage   string   `yaml:"deny_message,omitempty"`
}

type GeminiNativeSettings struct {
	DisableYOLOMode    *bool  `yaml:"disable_yolo_mode,omitempty"`
	DisableAlwaysAllow *bool  `yaml:"disable_always_allow,omitempty"`
	SandboxDefault     string `yaml:"sandbox_default,omitempty"`
}

// These fields match the native TOML schema in Gemini CLI v0.64.0. Keeping
// these separate from input types prevents accidental emission of YAML names.
type geminiTOMLRule struct {
	ToolName      string   `toml:"toolName"`
	Decision      string   `toml:"decision"`
	Priority      int      `toml:"priority"`
	CommandPrefix *string  `toml:"commandPrefix,omitempty"`
	MCPName       *string  `toml:"mcpName,omitempty"`
	Modes         []string `toml:"modes,omitempty"`
	DenyMessage   string   `toml:"denyMessage,omitempty"`
}

var geminiNativeName = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
var geminiNativeMCPPattern = regexp.MustCompile(`^mcp_[a-zA-Z0-9_.*-]+$`)

func compileNativeGemini(p *GeminiNativePolicy, targetOS string) (*NativeOutput, error) {
	if p == nil {
		return nil, fmt.Errorf("Gemini native policy is required")
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	if p.DefaultDecision != "deny" && p.DefaultDecision != "ask_user" {
		return nil, fmt.Errorf("gemini.default_decision must explicitly be deny or ask_user")
	}
	// Priority zero belongs to the generated catchall and applies in every
	// approval mode. Even YOLO's built-in rule is below the standard admin tier.
	rules := []geminiTOMLRule{{ToolName: "*", Decision: p.DefaultDecision, Priority: 0}}
	for i, rule := range p.Rules {
		if err := validateGeminiNativeRule(rule); err != nil {
			return nil, fmt.Errorf("gemini.rules[%d]: %w", i, err)
		}
		rules = append(rules, geminiTOMLRule{
			ToolName: rule.ToolName, Decision: rule.Decision, Priority: rule.Priority,
			CommandPrefix: rule.CommandPrefix, MCPName: rule.MCPName,
			Modes: rule.Modes, DenyMessage: rule.DenyMessage,
		})
	}

	settings := GeminiNativeSettings{}
	if p.Settings != nil {
		settings = *p.Settings
	}
	disableYOLO, disableAlwaysAllow := true, true
	if settings.DisableYOLOMode != nil {
		disableYOLO = *settings.DisableYOLOMode
	}
	if settings.DisableAlwaysAllow != nil {
		disableAlwaysAllow = *settings.DisableAlwaysAllow
	}
	data := map[string]interface{}{"security": map[string]bool{
		"disableYoloMode": disableYOLO, "disableAlwaysAllow": disableAlwaysAllow,
	}}
	sandboxLevel, sandboxDetails := "not-configured", "No sandbox default was requested. This adapter does not enforce an OS filesystem or network boundary."
	if settings.SandboxDefault != "" {
		sandbox, err := geminiSandboxDefault(settings.SandboxDefault, targetOS)
		if err != nil {
			return nil, err
		}
		data["tools"] = map[string]interface{}{"sandbox": sandbox}
		sandboxLevel = "configuration-only"
		sandboxDetails = "tools.sandbox sets a default; CLI flags and GEMINI_SANDBOX/SANDBOX can override it. It does not enforce an OS filesystem or network boundary."
	}
	settingsJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Gemini system settings: %w", err)
	}
	policyTOML, err := toml.Marshal(struct {
		Rules []geminiTOMLRule `toml:"rule"`
	}{Rules: rules})
	if err != nil {
		return nil, fmt.Errorf("encode Gemini admin policy: %w", err)
	}
	dir, separator := "/etc/gemini-cli", "/"
	if targetOS == "darwin" {
		dir = "/Library/Application Support/GeminiCli"
	} else if targetOS == "windows" {
		dir, separator = `C:\ProgramData\gemini-cli`, `\`
	}
	return &NativeOutput{
		Artifacts: []NativeArtifact{
			{Extension: "gemini.json", Content: string(settingsJSON) + "\n", Delivery: "system-file", Destination: dir + separator + "settings.json"},
			{Extension: "gemini.policy.toml", Content: string(policyTOML), Delivery: "system-file", Destination: dir + separator + "policies" + separator + "agentedict.toml"},
		},
		Capabilities: []NativeCapability{
			{Product: "gemini", Control: "tool_decisions", Level: "enforced", Details: "Gemini CLI v0.64.0 standard admin TOML policies override user/CLI tool rules without an enterprise subscription. Requires the protected standard policy directory and a compatible, unmodified client. Native shell heuristics can refine ask_user decisions."},
			{Product: "gemini", Control: "security_settings", Level: "configuration-only", Details: "disableYoloMode and disableAlwaysAllow are system settings; GEMINI_CLI_SYSTEM_SETTINGS_PATH can redirect settings loading. The fixed standard admin policy directory is independent of this variable."},
			{Product: "gemini", Control: "sandbox", Level: sandboxLevel, Details: sandboxDetails},
			{Product: "gemini", Control: "mcp_processes", Level: "not-enforced", Details: "Admin TOML can deny MCP tool calls, but does not prevent MCP server process startup or connections. Local MCP allowlists are not a reliable lifecycle boundary; this adapter emits no such claim."},
		},
	}, nil
}

func validateGeminiNativeRule(rule GeminiNativeRule) error {
	if rule.ToolName != "*" && !geminiNativeName.MatchString(rule.ToolName) && !geminiNativeMCPPattern.MatchString(rule.ToolName) {
		return fmt.Errorf("tool_name must be a native tool name, *, or an MCP wildcard pattern")
	}
	if rule.Decision != "allow" && rule.Decision != "deny" && rule.Decision != "ask_user" {
		return fmt.Errorf("decision must be allow, deny, or ask_user")
	}
	if rule.Priority < 1 || rule.Priority > 999 || rule.Priority == 950 {
		// v0.64.0 treats fraction .950 as an Always Allow rule in every tier,
		// and skips it when disableAlwaysAllow is enabled. Never emit it.
		return fmt.Errorf("priority must be 1..999 excluding reserved priority 950")
	}
	if rule.CommandPrefix != nil {
		if strings.TrimSpace(*rule.CommandPrefix) == "" || strings.IndexFunc(*rule.CommandPrefix, unicode.IsControl) >= 0 {
			return fmt.Errorf("command_prefix must be nonempty and contain no control characters")
		}
		if rule.ToolName != "run_shell_command" || rule.MCPName != nil {
			return fmt.Errorf("command_prefix is supported only for the built-in run_shell_command tool")
		}
	}
	if rule.MCPName != nil && *rule.MCPName != "*" && !geminiNativeName.MatchString(*rule.MCPName) {
		return fmt.Errorf("mcp_name must be a nonempty native server name or *")
	}
	seenModes := map[string]bool{}
	for _, mode := range rule.Modes {
		if mode != "default" && mode != "autoEdit" && mode != "plan" && mode != "yolo" {
			return fmt.Errorf("invalid native approval mode %q", mode)
		}
		if seenModes[mode] {
			return fmt.Errorf("duplicate approval mode %q", mode)
		}
		seenModes[mode] = true
	}
	return nil
}

func geminiSandboxDefault(value, targetOS string) (interface{}, error) {
	switch value {
	case "disabled":
		return false, nil
	case "auto":
		return true, nil
	case "docker", "podman":
		return value, nil
	case "sandbox-exec":
		if targetOS == "darwin" {
			return value, nil
		}
	case "runsc", "lxc":
		if targetOS == "linux" {
			return value, nil
		}
	case "windows-native":
		if targetOS == "windows" {
			return value, nil
		}
	}
	return nil, fmt.Errorf("gemini.settings.sandbox_default %q is not supported on %s", value, targetOS)
}
