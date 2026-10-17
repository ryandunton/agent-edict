package compiler

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Claude sandbox choices. "required" turns on Claude Code's OS sandbox for
// shell commands and refuses to run without it; "tools-only" accepts that some
// settings are enforced only in Claude's own tools.
const (
	ClaudeSandboxRequired  = "required"
	ClaudeSandboxToolsOnly = "tools-only"
)

// ClaudeConfig holds Claude-specific choices that the profile author makes.
type ClaudeConfig struct {
	Sandbox ClaudeSandbox `yaml:"sandbox"`
}

// ClaudeSandbox is written once for every OS or split as {unix, windows}.
// macOS and Linux use Unix.
type ClaudeSandbox struct {
	Unix    string
	Windows string
}

// For returns the choice for targetOS, or "" when the profile made none.
func (s ClaudeSandbox) For(targetOS string) string {
	if targetOS == "windows" {
		return s.Windows
	}
	return s.Unix
}

func validClaudeSandboxMode(mode string) error {
	if mode != ClaudeSandboxRequired && mode != ClaudeSandboxToolsOnly {
		return fmt.Errorf("claude.sandbox must be %q or %q, not %q", ClaudeSandboxRequired, ClaudeSandboxToolsOnly, mode)
	}
	return nil
}

func (s *ClaudeSandbox) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if err := validClaudeSandboxMode(node.Value); err != nil {
			return err
		}
		s.Unix, s.Windows = node.Value, node.Value
		return nil
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value != "unix" && key.Value != "windows" {
				return fmt.Errorf("claude.sandbox accepts only unix and windows keys, not %q", key.Value)
			}
			if seen[key.Value] {
				return fmt.Errorf("claude.sandbox.%s is set twice", key.Value)
			}
			seen[key.Value] = true
			if value.Kind != yaml.ScalarNode {
				return fmt.Errorf("claude.sandbox.%s must be a string", key.Value)
			}
			if err := validClaudeSandboxMode(value.Value); err != nil {
				return err
			}
			if key.Value == "unix" {
				s.Unix = value.Value
			} else {
				s.Windows = value.Value
			}
		}
		return nil
	default:
		return fmt.Errorf("claude.sandbox must be a string or a unix/windows mapping")
	}
}
