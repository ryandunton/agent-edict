package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// CopilotNativePolicy configures GitHub Copilot's file-based enterprise
// managed settings. Keys mirror GitHub's managed-settings.json reference.
type CopilotNativePolicy struct {
	// DisableBypassMode defaults to true: permissions.disableBypassPermissionsMode.
	DisableBypassMode *bool              `yaml:"disable_bypass_mode,omitempty"`
	Permissions       CopilotPermissions `yaml:"permissions,omitempty"`
	MCP               *CopilotMCPPolicy  `yaml:"mcp,omitempty"`
	Sandbox           *CopilotSandbox    `yaml:"sandbox,omitempty"`
	// ComputerUse=false stops users from enabling computer use.
	ComputerUse *bool `yaml:"computer_use,omitempty"`
}

// CopilotPermissions are Copilot selectors such as Shell(git push *),
// Read(~/.ssh/**), Edit(//etc/**), and Domain(*.example.com).
type CopilotPermissions struct {
	Allow []string `yaml:"allow,omitempty"`
	Ask   []string `yaml:"ask,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
}

type CopilotMCPPolicy struct {
	// Allowed is an allowlist when present; an empty list blocks every
	// non-built-in server. Omitted means no allowlist.
	Allowed *[]CopilotMCPMatcher `yaml:"allowed,omitempty"`
	Denied  []CopilotMCPMatcher  `yaml:"denied,omitempty"`
}

// CopilotMCPMatcher sets exactly one of name, url, or command.
type CopilotMCPMatcher struct {
	Name    string   `yaml:"name,omitempty" json:"serverName,omitempty"`
	URL     string   `yaml:"url,omitempty" json:"serverUrl,omitempty"`
	Command []string `yaml:"command,omitempty" json:"serverCommand,omitempty"`
}

type CopilotSandbox struct {
	Enabled           *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	FailIfUnavailable *bool `yaml:"fail_if_unavailable,omitempty" json:"failIfUnavailable,omitempty"`
	AllowBypass       *bool `yaml:"allow_bypass,omitempty" json:"allowBypass,omitempty"`
}

var copilotSelector = regexp.MustCompile(`^(Shell|Bash|PowerShell|Read|Edit|Write|Domain)\(.+\)$`)

func copilotPaths(targetOS string) string {
	switch targetOS {
	case "darwin":
		return "/Library/Application Support/GitHubCopilot/managed-settings.json"
	case "windows":
		return `C:\Program Files\GitHubCopilot\managed-settings.json`
	}
	return "/etc/github-copilot/managed-settings.json"
}

func compileNativeCopilot(p *CopilotNativePolicy, targetOS string) (*NativeOutput, error) {
	if p == nil {
		return nil, fmt.Errorf("copilot policy is required")
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, list := range [][]string{p.Permissions.Allow, p.Permissions.Ask, p.Permissions.Deny} {
		for _, rule := range list {
			if len(rule) > 4096 || strings.IndexFunc(rule, unicode.IsControl) >= 0 || !copilotSelector.MatchString(rule) {
				return nil, fmt.Errorf("copilot.permissions rule %q must be Shell(...), Bash(...), PowerShell(...), Read(...), Edit(...), Write(...), or Domain(...)", rule)
			}
			if seen[rule] {
				return nil, fmt.Errorf("copilot.permissions rule %q appears more than once", rule)
			}
			seen[rule] = true
		}
	}

	permissions := map[string]any{}
	disableBypass := p.DisableBypassMode == nil || *p.DisableBypassMode
	if disableBypass {
		permissions["disableBypassPermissionsMode"] = "disable"
	}
	for key, list := range map[string][]string{"allow": p.Permissions.Allow, "ask": p.Permissions.Ask, "deny": p.Permissions.Deny} {
		if len(list) > 0 {
			permissions[key] = list
		}
	}
	settings := map[string]any{}
	if len(permissions) > 0 {
		settings["permissions"] = permissions
	}
	mcpLevel, mcpDetails := "not-configured", "No MCP allowlist or denylist was requested."
	if p.MCP != nil {
		if p.MCP.Allowed != nil {
			if err := validateCopilotMatchers(*p.MCP.Allowed); err != nil {
				return nil, fmt.Errorf("copilot.mcp.allowed: %w", err)
			}
			settings["allowedMcpServers"] = append([]CopilotMCPMatcher{}, *p.MCP.Allowed...)
		}
		if len(p.MCP.Denied) > 0 {
			if err := validateCopilotMatchers(p.MCP.Denied); err != nil {
				return nil, fmt.Errorf("copilot.mcp.denied: %w", err)
			}
			settings["deniedMcpServers"] = p.MCP.Denied
		}
		if p.MCP.Allowed != nil || len(p.MCP.Denied) > 0 {
			mcpLevel = "enforced"
			mcpDetails = "allowedMcpServers and deniedMcpServers match an exact server name, a server URL pattern, or an exact launch command; deny wins and an empty allowlist blocks every non-built-in server. Server names are user-chosen labels. First-party servers such as the GitHub MCP server cannot be blocked."
		}
	}
	sandboxLevel, sandboxDetails := "not-configured", "No Copilot sandbox setting was requested. AgentEdict does not provide OS containment."
	if s := p.Sandbox; s != nil {
		if s.Enabled == nil && s.FailIfUnavailable == nil && s.AllowBypass == nil {
			return nil, fmt.Errorf("copilot.sandbox must set enabled, fail_if_unavailable, or allow_bypass")
		}
		settings["sandbox"] = s
		sandboxLevel = "configuration-only"
		sandboxDetails = "Copilot's own sandbox settings are managed; Copilot, not AgentEdict, enforces them. Requires Copilot CLI 1.0.93, VS Code 1.141.0, or GitHub Copilot app 1.1.26; older clients are blocked from connecting once sandbox is set."
		if s.Enabled != nil && *s.Enabled && s.FailIfUnavailable != nil && *s.FailIfUnavailable && (s.AllowBypass == nil || !*s.AllowBypass) {
			sandboxLevel = "enforced"
		}
	}
	if p.ComputerUse != nil {
		settings["features"] = map[string]bool{"computerUse": *p.ComputerUse}
	}
	if len(settings) == 0 {
		return nil, fmt.Errorf("copilot policy has no managed settings")
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(settings); err != nil {
		return nil, fmt.Errorf("encode Copilot managed settings: %w", err)
	}

	permissionLevel := "not-configured"
	if len(seen) > 0 {
		permissionLevel = "enforced"
	}
	bypassLevel, bypassDetails := "not-configured", "Bypass mode is not disabled by this policy."
	if disableBypass {
		bypassLevel = "partial"
		bypassDetails = "permissions.disableBypassPermissionsMode=disable blocks --yolo, --allow-all, /yolo and /allow-all. GitHub issue github/copilot-cli#4528 (open) reports that non-interactive -p sessions still bypass it."
	}
	return &NativeOutput{
		Artifacts: []NativeArtifact{
			{Extension: "copilot.json", Content: buf.String(), Delivery: "system-file", Destination: copilotPaths(targetOS)},
		},
		Capabilities: []NativeCapability{
			{Product: "copilot", Control: "tool_permissions", Level: permissionLevel, Details: "Managed permissions.allow, ask and deny compose deny > ask > allow; a managed ask cannot be satisfied by bypass mode, auto-approval, hooks, or stored grants. Copilot CLI requires a regular root-owned file that is not group- or world-writable on macOS and Linux. MDM and server-managed settings take precedence for other keys; clients load the file at startup."},
			{Product: "copilot", Control: "bypass_mode", Level: bypassLevel, Details: bypassDetails},
			{Product: "copilot", Control: "mcp_servers", Level: mcpLevel, Details: mcpDetails},
			{Product: "copilot", Control: "sandbox", Level: sandboxLevel, Details: sandboxDetails},
			{Product: "copilot", Control: "client_verification", Level: "not-verified", Details: "Schema and paths follow GitHub's enterprise managed settings reference; key support varies by client (CLI, VS Code, JetBrains, Copilot app). Installed-client acceptance has not been verified."},
		},
	}, nil
}

func validateCopilotMatchers(matchers []CopilotMCPMatcher) error {
	seen := map[string]bool{}
	for _, m := range matchers {
		set := 0
		if m.Name != "" {
			set++
			if !validNativeLiteral(m.Name) || strings.ContainsAny(m.Name, "*?") {
				return fmt.Errorf("server name %q must be an exact label", m.Name)
			}
		}
		if m.URL != "" {
			set++
			u, err := url.Parse(m.URL)
			if err != nil || !validNativeLiteral(m.URL) || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
				return fmt.Errorf("server URL %q must be an http(s) URL pattern without credentials", m.URL)
			}
		}
		if len(m.Command) > 0 {
			set++
			for _, arg := range m.Command {
				if arg == "" || strings.IndexFunc(arg, unicode.IsControl) >= 0 {
					return fmt.Errorf("server command arguments must be nonempty without control characters")
				}
			}
		}
		if set != 1 {
			return fmt.Errorf("each MCP matcher requires exactly one of name, url, or command")
		}
		key := fmt.Sprintf("%q", []string{m.Name, m.URL, strings.Join(m.Command, "\x00")})
		if seen[key] {
			return fmt.Errorf("duplicate MCP matcher")
		}
		seen[key] = true
	}
	return nil
}

func validNativeLiteral(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= 4096 && strings.IndexFunc(value, unicode.IsControl) < 0
}
