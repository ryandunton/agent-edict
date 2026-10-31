package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/platform"
)

func TestCheckProfileFileRejectsClientGatewayTampering(t *testing.T) {
	for _, tc := range []struct{ ext, content, want string }{
		{"claude.json", `{"allowedProviders":["customEndpoint"],"env":{"ANTHROPIC_BASE_URL":"http://gateway.example.com"}}`, "ANTHROPIC_BASE_URL"},
		{"claude.json", `{"allowedProviders":["customEndpoint"],"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.com","ANTHROPIC_AUTH_TOKEN":"secret-sentinel"}}`, "ANTHROPIC_AUTH_TOKEN"},
		{"claude.json", `{"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.com"}}`, "allowedProviders"},
		{"claude.json", `{"allowedProviders":["customEndpoint","anthropic"],"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.com"}}`, "allowedProviders"},
		{"opencode.json", `{"provider":{"gateway":{"npm":"@ai-sdk/openai","name":"Gateway","options":{"baseURL":"https://gateway.example.com/v1","apiKey":"secret-sentinel"},"models":{"example-model":{"name":"example-model"}}}},"enabled_providers":["gateway"],"model":"gateway/example-model","small_model":"gateway/example-model"}`, "apiKey"},
	} {
		dir := t.TempDir()
		profiles := filepath.Join(dir, "profiles", "linux")
		if err := os.MkdirAll(profiles, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(profiles, "sample."+tc.ext), []byte(tc.content), 0600); err != nil {
			t.Fatal(err)
		}
		err := checkProfileFile(dir, "linux", "sample", platform.PolicyTarget{BundleExt: tc.ext})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.ext, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-sentinel") {
			t.Errorf("%s leaked credential in error", tc.ext)
		}
	}
}
