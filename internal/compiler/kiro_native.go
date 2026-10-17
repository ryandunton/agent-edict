package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// KiroNativePolicy configures Kiro's enterprise managed-settings.json. Admin
// rules can only deny or ask; they never grant access.
type KiroNativePolicy struct {
	Rules         []KiroRule `yaml:"rules"`
	SigninHelpURL string     `yaml:"signin_help_url,omitempty"`
}

type KiroRule struct {
	Capability string   `yaml:"capability" json:"capability"`
	Match      []string `yaml:"match,omitempty" json:"match,omitempty"`
	Exclude    []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	Effect     string   `yaml:"effect" json:"effect"`
}

var kiroCapabilities = []string{"fs_read", "fs_write", "shell", "web_fetch", "web_search", "mcp", "subagent", "skill", "power", "context", "diagnostics", "sandbox_network", "all", "builtin", "filesystem", "signin_method"}
var kiroSigninMethods = []string{"idc", "external_idp", "builder_id", "google", "github", "social"}

func kiroPath(targetOS string) string {
	switch targetOS {
	case "darwin":
		return "/Library/Application Support/Kiro/managed-settings.json"
	case "windows":
		return `C:\ProgramData\Kiro\managed-settings.json`
	}
	return "/etc/kiro/managed-settings.json"
}

func compileNativeKiro(p *KiroNativePolicy, targetOS string) (*NativeOutput, error) {
	if p == nil || len(p.Rules) == 0 {
		return nil, fmt.Errorf("kiro.rules requires at least one deny or ask rule")
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	signin := false
	for i, rule := range p.Rules {
		if err := validateKiroRule(rule); err != nil {
			return nil, fmt.Errorf("kiro.rules[%d]: %w", i, err)
		}
		signin = signin || rule.Capability == "signin_method"
	}
	// Kiro rejects the whole file when a rule has an unknown field, and keeps
	// "rules" mandatory even when only settings are used.
	settings := map[string]any{"rules": p.Rules}
	if p.SigninHelpURL != "" {
		u, err := url.Parse(p.SigninHelpURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !validNativeLiteral(p.SigninHelpURL) {
			return nil, fmt.Errorf("kiro.signin_help_url must be an https URL")
		}
		settings["settings"] = map[string]string{"signin_help_url": p.SigninHelpURL}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(settings); err != nil {
		return nil, fmt.Errorf("encode Kiro managed settings: %w", err)
	}
	capabilities := []NativeCapability{
		{Product: "kiro", Control: "permission_rules", Level: "enforced", Details: "Admin deny and ask rules in managed-settings.json; the stricter effect wins over user rules and presets, an admin ask always prompts, and admin rules cannot grant access. Compound shell commands are split and each sub-command is evaluated. Kiro must be restarted after the file changes. Client-enforced."},
	}
	if signin {
		capabilities = append(capabilities, NativeCapability{Product: "kiro", Control: "signin_methods", Level: "enforced", Details: "signin_method deny rules apply to Kiro IDE 1.2 and Kiro CLI 2.25.0 or later."})
	}
	capabilities = append(capabilities, NativeCapability{Product: "kiro", Control: "client_verification", Level: "not-verified", Details: "Schema and paths follow Kiro's enterprise permission-policy documentation. A malformed file is reported to make Kiro deny all tool calls. Installed IDE and CLI acceptance has not been verified."})
	return &NativeOutput{
		Artifacts:    []NativeArtifact{{Extension: "kiro.json", Content: buf.String(), Delivery: "system-file", Destination: kiroPath(targetOS)}},
		Capabilities: capabilities,
	}, nil
}

func validateKiroRule(rule KiroRule) error {
	if !slices.Contains(kiroCapabilities, rule.Capability) {
		return fmt.Errorf("unsupported capability %q", rule.Capability)
	}
	if rule.Effect != "deny" && rule.Effect != "ask" {
		return fmt.Errorf("effect must be deny or ask; admin rules cannot allow")
	}
	patterns := append(append([]string{}, rule.Match...), rule.Exclude...)
	if rule.Capability == "signin_method" {
		if rule.Effect != "deny" || len(rule.Match) > 16 || len(rule.Exclude) > 16 {
			return fmt.Errorf("signin_method rules must deny at most 16 methods")
		}
		for _, method := range patterns {
			if !slices.Contains(kiroSigninMethods, method) {
				return fmt.Errorf("unsupported sign-in method %q", method)
			}
		}
		return nil
	}
	for _, pattern := range patterns {
		if !validNativeLiteral(pattern) || len(pattern) > 1024 {
			return fmt.Errorf("patterns must be nonempty without control characters")
		}
		// Kiro shell globs support only *; other syntax would silently not match.
		if rule.Capability == "shell" && (strings.Contains(pattern, "**") || strings.ContainsAny(pattern, "?[")) {
			return fmt.Errorf("shell pattern %q uses unsupported glob syntax; only * is supported", pattern)
		}
	}
	return nil
}
