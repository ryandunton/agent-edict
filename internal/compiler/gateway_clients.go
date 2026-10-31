package compiler

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// ClaudeGateway routes Claude Code's Anthropic API requests. The credential
// stays in the client process environment, never in the profile or bundle.
type ClaudeGateway struct {
	BaseURL       string  `yaml:"base_url"`
	CredentialEnv string  `yaml:"credential_env"`
	Model         *string `yaml:"model,omitempty"`
}

type OpenCodeConfig struct {
	Gateway *OpenCodeGateway `yaml:"gateway,omitempty"`
}

// OpenCodeGateway describes one managed OpenCode provider and its model.
type OpenCodeGateway struct {
	Provider string `yaml:"provider"`
	Name     string `yaml:"name,omitempty"`
	BaseURL  string `yaml:"base_url"`
	WireAPI  string `yaml:"wire_api"`
	EnvKey   string `yaml:"env_key"`
	Model    string `yaml:"model"`
}

func validateGatewayURL(field, value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(value, "#") || u.Opaque != "" {
		return fmt.Errorf("%s must be an HTTPS URL without credentials, query, or fragment", field)
	}
	return nil
}

func validGatewayModel(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func validateClientGateways(p *UnifiedPolicy) error {
	if p.Claude != nil && p.Claude.Gateway != nil {
		g := p.Claude.Gateway
		if err := validateGatewayURL("claude.gateway.base_url", g.BaseURL); err != nil {
			return err
		}
		if g.CredentialEnv != "ANTHROPIC_AUTH_TOKEN" && g.CredentialEnv != "ANTHROPIC_API_KEY" {
			return fmt.Errorf("claude.gateway.credential_env must be ANTHROPIC_AUTH_TOKEN or ANTHROPIC_API_KEY")
		}
		if g.Model != nil && !validGatewayModel(*g.Model) {
			return fmt.Errorf("claude.gateway.model must be a nonempty model ID without surrounding whitespace or control characters")
		}
	}
	if p.OpenCode != nil && p.OpenCode.Gateway != nil {
		g := p.OpenCode.Gateway
		if !policyNamePattern.MatchString(g.Provider) {
			return fmt.Errorf("opencode.gateway.provider must be a provider ID")
		}
		if g.Name != "" && !validGatewayModel(g.Name) {
			return fmt.Errorf("opencode.gateway.name must be a nonempty name without surrounding whitespace or control characters")
		}
		if err := validateGatewayURL("opencode.gateway.base_url", g.BaseURL); err != nil {
			return err
		}
		if g.WireAPI != "responses" && g.WireAPI != "chat_completions" {
			return fmt.Errorf("opencode.gateway.wire_api must be responses or chat_completions")
		}
		if !envKeyPattern.MatchString(g.EnvKey) {
			return fmt.Errorf("opencode.gateway.env_key must name an uppercase environment variable")
		}
		if !validGatewayModel(g.Model) {
			return fmt.Errorf("opencode.gateway.model must be a nonempty model ID without surrounding whitespace or control characters")
		}
	}
	return nil
}

// ValidateClaudeGatewayJSON checks the gateway fields of a compiled managed
// settings file before a bundle is accepted for signing or installation.
func ValidateClaudeGatewayJSON(data []byte) error {
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	if _, ok := settings["apiKeyHelper"]; ok {
		return fmt.Errorf("Claude gateway apiKeyHelper is not supported by this compiler")
	}
	value, hasEnv := settings["env"]
	if !hasEnv {
		if _, hasModel := settings["model"]; hasModel {
			return fmt.Errorf("Claude gateway model requires env.ANTHROPIC_BASE_URL")
		}
		if _, hasPin := settings["allowedProviders"]; hasPin {
			return fmt.Errorf("Claude gateway allowedProviders requires env.ANTHROPIC_BASE_URL")
		}
		return nil
	}
	env, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("Claude gateway env must be an object")
	}
	for key := range env {
		if key != "ANTHROPIC_BASE_URL" {
			return fmt.Errorf("Claude gateway env.%s is not supported; credential values are not allowed", key)
		}
	}
	if len(env) != 1 {
		return fmt.Errorf("Claude gateway env must contain ANTHROPIC_BASE_URL")
	}
	baseURL, ok := env["ANTHROPIC_BASE_URL"].(string)
	if !ok {
		return fmt.Errorf("Claude gateway env.ANTHROPIC_BASE_URL must be a URL")
	}
	if err := validateGatewayURL("Claude gateway env.ANTHROPIC_BASE_URL", baseURL); err != nil {
		return err
	}
	allowed, ok := settings["allowedProviders"].([]any)
	if !ok || len(allowed) != 1 || allowed[0] != "customEndpoint" {
		return fmt.Errorf("Claude gateway allowedProviders must contain only customEndpoint")
	}
	if model, hasModel := settings["model"]; hasModel {
		modelID, ok := model.(string)
		if !ok || !validGatewayModel(modelID) {
			return fmt.Errorf("Claude gateway model must be a nonempty model ID")
		}
	}
	return nil
}

// ValidateOpenCodeGatewayJSON checks the managed provider, credential
// reference, and provider allowlist in a compiled OpenCode artifact.
func ValidateOpenCodeGatewayJSON(data []byte) error {
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	value, hasProvider := settings["provider"]
	if !hasProvider {
		for _, key := range []string{"enabled_providers", "model", "small_model"} {
			if _, present := settings[key]; present {
				return fmt.Errorf("OpenCode gateway %s requires provider", key)
			}
		}
		return nil
	}
	providers, ok := value.(map[string]any)
	if !ok || len(providers) != 1 {
		return fmt.Errorf("OpenCode gateway provider must contain exactly one provider")
	}
	for id, value := range providers {
		if !policyNamePattern.MatchString(id) {
			return fmt.Errorf("OpenCode gateway provider ID is invalid")
		}
		provider, ok := value.(map[string]any)
		if !ok || len(provider) != 4 {
			return fmt.Errorf("OpenCode gateway provider must contain only npm, name, options, and models")
		}
		pack, ok := provider["npm"].(string)
		if !ok || pack != "@ai-sdk/openai" && pack != "@ai-sdk/openai-compatible" {
			return fmt.Errorf("OpenCode gateway npm must be a supported provider package")
		}
		name, ok := provider["name"].(string)
		if !ok || !validGatewayModel(name) {
			return fmt.Errorf("OpenCode gateway name must be nonempty")
		}
		options, ok := provider["options"].(map[string]any)
		if !ok || len(options) != 2 {
			return fmt.Errorf("OpenCode gateway options must contain only baseURL and apiKey")
		}
		baseURL, ok := options["baseURL"].(string)
		if !ok {
			return fmt.Errorf("OpenCode gateway options.baseURL must be a URL")
		}
		if err := validateGatewayURL("OpenCode gateway options.baseURL", baseURL); err != nil {
			return err
		}
		key, ok := options["apiKey"].(string)
		if !ok || !strings.HasPrefix(key, "{env:") || !strings.HasSuffix(key, "}") || !envKeyPattern.MatchString(strings.TrimSuffix(strings.TrimPrefix(key, "{env:"), "}")) {
			return fmt.Errorf("OpenCode gateway options.apiKey must reference an environment variable")
		}
		models, ok := provider["models"].(map[string]any)
		if !ok || len(models) != 1 {
			return fmt.Errorf("OpenCode gateway models must contain exactly one model")
		}
		for modelID, value := range models {
			model, ok := value.(map[string]any)
			if !validGatewayModel(modelID) || !ok || len(model) != 1 || model["name"] != modelID {
				return fmt.Errorf("OpenCode gateway models entry is invalid")
			}
			selected := id + "/" + modelID
			if settings["model"] != selected || settings["small_model"] != selected {
				return fmt.Errorf("OpenCode gateway model and small_model must use the managed provider")
			}
		}
		allowed, ok := settings["enabled_providers"].([]any)
		if !ok || len(allowed) != 1 || allowed[0] != id {
			return fmt.Errorf("OpenCode gateway enabled_providers must contain only the managed provider")
		}
	}
	return nil
}
