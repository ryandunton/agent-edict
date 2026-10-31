package compiler

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

const enterpriseProfile = `version: 1
name: enterprise
login:
  methods: [api]
model_provider: gateway
codex_model: gateway-model
model_providers:
  gateway:
    name: Example gateway
    base_url: https://gateway.example.com/v1
    wire_api: responses
    env_key: GATEWAY_API_KEY
    requires_openai_auth: false
windows_platform:
  allowed_sandbox_implementations: [unelevated]
  allow_mxc: false
features:
  prefer_mxc: false
  multi_agent: true
application_network:
  enabled: true
  domains:
    gateway.example.com: allow
mcp_servers: {}
plugins: {}
browser_use:
  allow_history_access: false
  allow_global_persistent_approval: false
  default_origin_policy:
    access: deny
    persistent_approval: false
`

func compileCodexTOML(t *testing.T, profile, targetOS string) map[string]any {
	t.Helper()
	p, err := ParsePolicy([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	out, err := CompileAgent(p, targetOS, "codex")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := toml.Unmarshal([]byte(out.Files[0].Content), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.Files[0].Content)
	}
	return got
}

func TestCodexWritesEnterpriseRequirements(t *testing.T) {
	got := compileCodexTOML(t, enterpriseProfile, "windows")
	want := map[string]any{
		"allowed_login_methods": []any{"api"},
		"model_provider":        "gateway",
		"models":                map[string]any{"new_thread": map[string]any{"model": "gateway-model"}},
		"model_providers": map[string]any{"gateway": map[string]any{"name": "Example gateway", "base_url": "https://gateway.example.com/v1",
			"wire_api": "responses", "env_key": "GATEWAY_API_KEY", "requires_openai_auth": false}},
		"windows":     map[string]any{"allowed_sandbox_implementations": []any{"unelevated"}, "allow_mxc": false},
		"application": map[string]any{"network": map[string]any{"enabled": true, "domains": map[string]any{"gateway.example.com": "allow"}}},
		"mcp_servers": map[string]any{},
		"plugins":     map[string]any{},
		"browser_use": map[string]any{"allow_history_access": false, "allow_global_persistent_approval": false,
			"default_origin_policy": map[string]any{"access": "deny", "persistent_approval": false}},
	}
	for key, value := range want {
		if !reflect.DeepEqual(got[key], value) {
			t.Errorf("%s = %#v, want %#v", key, got[key], value)
		}
	}
	features, _ := got["features"].(map[string]any)
	if features["prefer_mxc"] != false || features["multi_agent"] != true {
		t.Errorf("features = %#v", features)
	}
	if linux := compileCodexTOML(t, enterpriseProfile, "linux"); linux["windows"] != nil {
		t.Errorf("[windows] written for Linux: %#v", linux["windows"])
	}
}

func TestCodexWritesPluginMCPServers(t *testing.T) {
	profile := "version: 1\nname: p\nplugins:\n  docs:\n    mcp_servers:\n      search:\n        url: https://mcp.example.com/search\n      local:\n        command: /usr/local/bin/docs-mcp\n  empty:\n    mcp_servers: {}\n"
	got := compileCodexTOML(t, profile, "linux")
	want := map[string]any{
		"docs":  map[string]any{"mcp_servers": map[string]any{"search": map[string]any{"identity": map[string]any{"url": "https://mcp.example.com/search"}}, "local": map[string]any{"identity": map[string]any{"command": "/usr/local/bin/docs-mcp"}}}},
		"empty": map[string]any{"mcp_servers": map[string]any{}},
	}
	if !reflect.DeepEqual(got["plugins"], want) {
		t.Fatalf("plugins = %#v", got["plugins"])
	}
}

func TestEnterpriseRequirementsAcceptCodexDomains(t *testing.T) {
	profile := "version: 1\nname: d\napplication_network:\n  enabled: true\n  domains:\n    Gateway.Example.com.: allow\n    blocked.example.com: deny\n"
	got := compileCodexTOML(t, profile, "linux")
	want := map[string]any{"enabled": true, "domains": map[string]any{"Gateway.Example.com.": "allow", "blocked.example.com": "deny"}}
	if app, _ := got["application"].(map[string]any); !reflect.DeepEqual(app["network"], want) {
		t.Fatalf("application = %#v", got["application"])
	}
}

func TestEnterpriseRequirementsValidation(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{"login:\n  methods: [sso]\n", "login.methods"},
		{"login:\n  methods: []\n", "login.methods"},
		{"login:\n  methods: [api, api]\n", "login.methods"},
		{"application_network:\n  enabled: true\n  domains:\n    example.com: ask\n", "application_network.domains"},
		{"application_network:\n  enabled: true\n  domains:\n    https://example.com: allow\n", "application_network.domains"},
		{"application_network:\n  enabled: true\n  domains:\n    \"*.example.com\": allow\n", "application_network.domains"},
		{"application_network:\n  enabled: true\n  domains:\n    example.com:8443: allow\n", "application_network.domains"},
		{"application_network:\n  enabled: true\n  domains:\n    -bad.example.com: allow\n", "application_network.domains"},
		{"application_network:\n  enabled: true\n  domains:\n    example.com: allow\n    Example.com.: deny\n", "application_network.domains"},
		{"browser_use:\n  default_origin_policy:\n    access: ask\n", "browser_use.default_origin_policy.access"},
		{"browser_use:\n  default_origin_policy:\n    access_approval_lifetime: session\n", "browser_use.default_origin_policy.access_approval_lifetime"},
		{"model_providers:\n  gw:\n    wire_api: chat\n", "model_providers.gw.wire_api"},
		{"codex_model: gateway-model\n", "codex_model requires model_provider"},
		{"codex_model: ''\nmodel_provider: openai\n", "codex_model"},
		{"model_provider: missing\n", "model_provider"},
		{"model_provider: gw\nmodel_providers:\n  gw:\n    wire_api: responses\n    env_key: GATEWAY_API_KEY\n", "model_providers.gw.base_url"},
		{"model_provider: gw\nmodel_providers:\n  gw:\n    base_url: http://gateway.example.com/v1\n    wire_api: responses\n    env_key: GATEWAY_API_KEY\n", "model_providers.gw.base_url"},
		{"model_provider: gw\nmodel_providers:\n  gw:\n    base_url: https://secret@gateway.example.com/v1\n    wire_api: responses\n    env_key: GATEWAY_API_KEY\n", "model_providers.gw.base_url"},
		{"model_provider: gw\nmodel_providers:\n  gw:\n    base_url: https://gateway.example.com/v1\n    wire_api: responses\n    env_key: not-a-variable\n", "model_providers.gw.env_key"},
		{"model_provider: gw\nmodel_providers:\n  gw:\n    base_url: https://gateway.example.com/v1\n    wire_api: responses\n", "model_providers.gw.env_key"},
		{"model_provider: gw\nmodel_providers:\n  gw:\n    base_url: https://gateway.example.com/v1\n    wire_api: responses\n    env_key: GATEWAY_API_KEY\n    requires_openai_auth: true\n", "model_providers.gw.requires_openai_auth"},
		{"plugins:\n  p:\n    mcp_servers:\n      s: {}\n", "plugins.p.mcp_servers.s"},
		{"plugins:\n  p:\n    mcp_servers:\n      s:\n        url: https://a.example.com\n        command: /bin/a\n", "plugins.p.mcp_servers.s"},
	} {
		if _, err := ParsePolicy([]byte("version: 1\nname: x\n" + tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %v, want one mentioning %s", tc.yaml, err, tc.want)
		}
	}
}

func TestCodexBuiltinProviderRemainsValid(t *testing.T) {
	for _, name := range []string{"openai", "amazon-bedrock"} {
		if _, err := ParsePolicy([]byte("version: 1\nname: x\nmodel_provider: " + name + "\ncodex_model: gpt-5\n")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCodexResponsesWireAPIDefaultRemainsValid(t *testing.T) {
	if _, err := ParsePolicy([]byte("version: 1\nname: x\nmodel_provider: gateway\nmodel_providers:\n  gateway:\n    base_url: https://gateway.example.com/v1\n    env_key: GATEWAY_API_KEY\n")); err != nil {
		t.Fatal(err)
	}
}
