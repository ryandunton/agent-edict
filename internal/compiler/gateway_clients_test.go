package compiler

import (
	"encoding/json"
	"strings"
	"testing"
)

const multiClientGatewayYAML = `version: 1
name: gateway-example
claude:
  gateway:
    base_url: https://aigateway.internal.company.com/anthropic
    credential_env: ANTHROPIC_AUTH_TOKEN
    model: company-claude-model
opencode:
  gateway:
    provider: company-gateway
    name: Company AI Gateway
    base_url: https://aigateway.internal.company.com/v1
    wire_api: responses
    env_key: AI_GATEWAY_API_KEY
    model: company-coding-model
`

func TestCompileClientGateways(t *testing.T) {
	p, err := ParsePolicy([]byte(multiClientGatewayYAML))
	if err != nil {
		t.Fatal(err)
	}
	for _, osName := range []string{"windows", "linux", "darwin"} {
		claude, err := CompileAgent(p, osName, "claude")
		if err != nil {
			t.Fatal(err)
		}
		var claudeJSON map[string]any
		if err := json.Unmarshal([]byte(claude.Files[0].Content), &claudeJSON); err != nil {
			t.Fatal(err)
		}
		env := claudeJSON["env"].(map[string]any)
		if env["ANTHROPIC_BASE_URL"] != "https://aigateway.internal.company.com/anthropic" || claudeJSON["model"] != "company-claude-model" {
			t.Errorf("%s Claude gateway = %v", osName, claudeJSON)
		}
		if allowed, ok := claudeJSON["allowedProviders"].([]any); !ok || len(allowed) != 1 || allowed[0] != "customEndpoint" {
			t.Errorf("%s Claude gateway must pin the custom endpoint: %v", osName, claudeJSON["allowedProviders"])
		}
		if _, ok := env["ANTHROPIC_AUTH_TOKEN"]; ok {
			t.Error("Claude secret value must not enter managed settings")
		}
		openCode, err := CompileAgent(p, osName, "opencode")
		if err != nil {
			t.Fatal(err)
		}
		var openCodeJSON map[string]any
		if err := json.Unmarshal([]byte(openCode.Files[0].Content), &openCodeJSON); err != nil {
			t.Fatal(err)
		}
		provider := openCodeJSON["provider"].(map[string]any)["company-gateway"].(map[string]any)
		options := provider["options"].(map[string]any)
		if provider["npm"] != "@ai-sdk/openai" || options["baseURL"] != "https://aigateway.internal.company.com/v1" || options["apiKey"] != "{env:AI_GATEWAY_API_KEY}" {
			t.Errorf("%s OpenCode gateway = %v", osName, provider)
		}
		if openCodeJSON["model"] != "company-gateway/company-coding-model" || openCodeJSON["small_model"] != openCodeJSON["model"] {
			t.Errorf("%s OpenCode models = %v", osName, openCodeJSON)
		}
		if allowed := openCodeJSON["enabled_providers"].([]any); len(allowed) != 1 || allowed[0] != "company-gateway" {
			t.Errorf("%s OpenCode provider allowlist = %v", osName, allowed)
		}
	}
}

func TestRejectInvalidClientGateways(t *testing.T) {
	for _, tc := range []struct{ yaml, field string }{
		{"claude:\n  gateway:\n    base_url: http://gateway.example.com\n    credential_env: ANTHROPIC_AUTH_TOKEN\n", "claude.gateway.base_url"},
		{"claude:\n  gateway:\n    base_url: https://secret@gateway.example.com\n    credential_env: ANTHROPIC_AUTH_TOKEN\n", "claude.gateway.base_url"},
		{"claude:\n  gateway:\n    base_url: 'https://gateway.example.com/anthropic?'\n    credential_env: ANTHROPIC_AUTH_TOKEN\n", "claude.gateway.base_url"},
		{"claude:\n  gateway:\n    base_url: https://gateway.example.com\n    credential_env: CUSTOM_GATEWAY_KEY\n", "claude.gateway.credential_env"},
		{"claude:\n  gateway:\n    base_url: https://gateway.example.com\n    credential_env: ANTHROPIC_AUTH_TOKEN\n    model: ''\n", "claude.gateway.model"},
		{"claude:\n  gateway: {}\n", "claude.gateway.base_url"},
		{"claude:\n  gateway:\n    base_url: https://gateway.example.com\n    api_key: secret-sentinel\n", "api_key"},
		{"opencode:\n  gateway:\n    provider: company-gateway\n    base_url: http://gateway.example.com/v1\n    wire_api: responses\n    env_key: AI_GATEWAY_API_KEY\n    model: company-model\n", "opencode.gateway.base_url"},
		{"opencode:\n  gateway:\n    provider: company-gateway\n    base_url: https://gateway.example.com/v1\n    wire_api: chat\n    env_key: AI_GATEWAY_API_KEY\n    model: company-model\n", "opencode.gateway.wire_api"},
		{"opencode:\n  gateway:\n    provider: company-gateway\n    base_url: https://gateway.example.com/v1\n    wire_api: responses\n    env_key: bad-variable\n    model: company-model\n", "opencode.gateway.env_key"},
		{"opencode:\n  gateway:\n    provider: company-gateway\n    base_url: https://gateway.example.com/v1\n    wire_api: responses\n    env_key: AI_GATEWAY_API_KEY\n", "opencode.gateway.model"},
		{"opencode:\n  gateway:\n    provider: company-gateway\n    base_url: https://gateway.example.com/v1\n    wire_api: responses\n    env_key: AI_GATEWAY_API_KEY\n    model: company-model\n    api_key: secret-sentinel\n", "api_key"},
	} {
		_, err := ParsePolicy([]byte("version: 1\nname: example\n" + tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("expected %s error, got %v", tc.field, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-sentinel") {
			t.Error("error disclosed a secret value")
		}
	}
}

func TestOpenCodeChatCompletionsGateway(t *testing.T) {
	yaml := strings.ReplaceAll(multiClientGatewayYAML, "wire_api: responses", "wire_api: chat_completions")
	p, err := ParsePolicy([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	out, err := CompileAgent(p, "linux", "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Files[0].Content, `"npm": "@ai-sdk/openai-compatible"`) {
		t.Fatal("Chat Completions gateway must select OpenCode's compatible provider package")
	}
}

func TestValidateClientGatewayArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
		validate         func([]byte) error
	}{
		{"Claude valid", `{"allowedProviders":["customEndpoint"],"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.com/anthropic"},"model":"example-claude-model"}`, "", ValidateClaudeGatewayJSON},
		{"Claude missing provider pin", `{"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.com/anthropic"}}`, "allowedProviders", ValidateClaudeGatewayJSON},
		{"Claude permits another provider", `{"allowedProviders":["customEndpoint","anthropic"],"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.com/anthropic"}}`, "allowedProviders", ValidateClaudeGatewayJSON},
		{"Claude insecure URL", `{"allowedProviders":["customEndpoint"],"env":{"ANTHROPIC_BASE_URL":"http://gateway.example.com"}}`, "ANTHROPIC_BASE_URL", ValidateClaudeGatewayJSON},
		{"Claude embedded credential", `{"allowedProviders":["customEndpoint"],"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.com","ANTHROPIC_AUTH_TOKEN":"secret-sentinel"}}`, "ANTHROPIC_AUTH_TOKEN", ValidateClaudeGatewayJSON},
		{"Claude unmanaged helper", `{"apiKeyHelper":"/tmp/helper"}`, "apiKeyHelper", ValidateClaudeGatewayJSON},
		{"Claude model without route", `{"model":"example-claude-model"}`, "ANTHROPIC_BASE_URL", ValidateClaudeGatewayJSON},
		{"OpenCode valid", `{"provider":{"gateway":{"npm":"@ai-sdk/openai","name":"Gateway","options":{"baseURL":"https://gateway.example.com/v1","apiKey":"{env:GATEWAY_API_KEY}"},"models":{"example-model":{"name":"example-model"}}}},"enabled_providers":["gateway"],"model":"gateway/example-model","small_model":"gateway/example-model"}`, "", ValidateOpenCodeGatewayJSON},
		{"OpenCode insecure URL", `{"provider":{"gateway":{"npm":"@ai-sdk/openai","name":"Gateway","options":{"baseURL":"http://gateway.example.com/v1","apiKey":"{env:GATEWAY_API_KEY}"},"models":{"example-model":{"name":"example-model"}}}},"enabled_providers":["gateway"],"model":"gateway/example-model","small_model":"gateway/example-model"}`, "baseURL", ValidateOpenCodeGatewayJSON},
		{"OpenCode embedded credential", `{"provider":{"gateway":{"npm":"@ai-sdk/openai","name":"Gateway","options":{"baseURL":"https://gateway.example.com/v1","apiKey":"secret-sentinel"},"models":{"example-model":{"name":"example-model"}}}},"enabled_providers":["gateway"],"model":"gateway/example-model","small_model":"gateway/example-model"}`, "apiKey", ValidateOpenCodeGatewayJSON},
		{"OpenCode bypass allowlist", `{"provider":{"gateway":{"npm":"@ai-sdk/openai","name":"Gateway","options":{"baseURL":"https://gateway.example.com/v1","apiKey":"{env:GATEWAY_API_KEY}"},"models":{"example-model":{"name":"example-model"}}}},"enabled_providers":["gateway","openai"],"model":"gateway/example-model","small_model":"gateway/example-model"}`, "enabled_providers", ValidateOpenCodeGatewayJSON},
	} {
		err := tc.validate([]byte(tc.data))
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-sentinel") {
			t.Errorf("%s leaked credential in error", tc.name)
		}
	}
}
