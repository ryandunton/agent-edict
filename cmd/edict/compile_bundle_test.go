package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/compiler"
)

var exampleDir = filepath.Join("..", "..", "examples", "role-policy")

func runCompileBundle(t *testing.T, mapPath, profilesDir string) (string, string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "dist")
	var output bytes.Buffer
	err := compileBundleCommand([]string{"-map", mapPath, "-profiles-dir", profilesDir, "-target-os", "all", "-output-dir", out}, &output)
	return out, output.String(), err
}

func writeMap(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy-map.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompileBundleExample(t *testing.T) {
	mapPath := filepath.Join(exampleDir, "policy-map.yaml")
	out, printed, err := runCompileBundle(t, mapPath, filepath.Join(exampleDir, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"profiles/linux/contractor-readonly.codex.toml",
		"profiles/linux/engineering.claude.json",
		"profiles/windows/contractor-claude.claude.notes.json",
		"profiles/darwin/engineering.cursor.policy.json",
		"profiles/darwin/engineering.cursor.hooks.json",
		"profiles/linux/engineering.native.yaml",
		"profiles/windows/standard.claude.json",
	} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	for _, name := range []string{"profiles/linux/contractor-readonly.claude.json", "profiles/linux/contractor-claude.codex.toml", "profiles/linux/contractor-readonly.native.yaml"} {
		if _, err := os.Stat(filepath.Join(out, name)); err == nil {
			t.Errorf("%s was emitted although no rule selects it", name)
		}
	}
	source, _ := os.ReadFile(mapPath)
	copied, err := os.ReadFile(filepath.Join(out, "policy-map.yaml"))
	if err != nil || !bytes.Equal(source, copied) {
		t.Errorf("policy-map.yaml is not a byte copy of the reviewed map: %v", err)
	}
	var notes struct {
		ToolLevelOnly []string `json:"tool_level_only"`
	}
	data, _ := os.ReadFile(filepath.Join(out, "profiles/windows/contractor-claude.claude.notes.json"))
	if json.Unmarshal(data, &notes) != nil || !slices.Equal(notes.ToolLevelOnly, []string{"filesystem.deny_read", "network.disabled"}) {
		t.Errorf("notes = %s", data)
	}
	if !strings.Contains(printed, "windows contractor-claude claude: filesystem.deny_read is enforced in Claude's own tools only") {
		t.Errorf("tool-level note not printed:\n%s", printed)
	}
	declaration, _ := os.ReadFile(filepath.Join(out, "profiles/linux/engineering.native.yaml"))
	if !strings.Contains(string(declaration), "cursor:") || strings.Contains(string(declaration), "windsurf:") {
		t.Errorf("native declaration must hold exactly the selected products:\n%s", declaration)
	}
}

func TestKnowledgeWorkerGatewayBundle(t *testing.T) {
	profile, err := compiler.LoadPolicy(filepath.Join("..", "..", "profiles", "knowledge-worker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := profile.ModelProviders["company-gateway"]
	if profile.ModelProvider != "company-gateway" ||
		profile.CodexModel == nil || *profile.CodexModel != "company-coding-model" ||
		len(profile.ModelProviders) != 1 || !ok ||
		provider.Name != "Company AI Gateway" ||
		provider.BaseURL != "https://aigateway.internal.company.com/v1" ||
		provider.WireAPI != "responses" ||
		provider.EnvKey != "AI_GATEWAY_API_KEY" ||
		provider.RequiresOpenAIAuth == nil || *provider.RequiresOpenAIAuth {
		t.Fatal("public knowledge-worker profile must keep the generic gateway example; use a private policy source for deployment values")
	}
	guide, err := os.ReadFile(filepath.Join("..", "..", "docs", "codex-gateway.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(guide), "https://") != 2 || strings.Count(string(guide), "https://aigateway.internal.company.com/v1") != 2 || strings.Contains(string(guide), "http://") {
		t.Fatal("public gateway guide must contain only the generic example URL")
	}
	out, _, err := runCompileBundle(t, filepath.Join("..", "..", "policy-map.yaml"), filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.ValidateBundleDirectory(out, "windows"); err != nil {
		t.Fatal(err)
	}
	for _, osName := range []string{"windows", "linux", "darwin"} {
		codex, err := os.ReadFile(filepath.Join(out, "profiles", osName, "knowledge-worker.codex.toml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`model_provider = "company-gateway"`, `base_url = "https://aigateway.internal.company.com/v1"`, `wire_api = "responses"`, `env_key = "AI_GATEWAY_API_KEY"`, `model = "company-coding-model"`} {
			if !bytes.Contains(codex, []byte(want)) {
				t.Errorf("%s Codex settings missing %s", osName, want)
			}
		}
		claude, err := os.ReadFile(filepath.Join(out, "profiles", osName, "knowledge-worker.claude.json"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(claude, []byte("aigateway.internal.company.com")) || bytes.Contains(claude, []byte("company-coding-model")) || bytes.Contains(claude, []byte("AI_GATEWAY_API_KEY")) {
			t.Errorf("%s Claude settings contain Codex gateway configuration", osName)
		}
	}
}

func TestBundleRejectsInvalidCodexGateway(t *testing.T) {
	out, _, err := runCompileBundle(t, filepath.Join("..", "..", "policy-map.yaml"), filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(out, "profiles", "windows", "knowledge-worker.codex.toml")
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	content = bytes.Replace(content, []byte(`env_key = "AI_GATEWAY_API_KEY"`), []byte(`env_key = "not-a-variable"`), 1)
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := agent.ValidateBundleDirectory(out, "windows"); err == nil || !strings.Contains(err.Error(), "env_key") {
		t.Fatalf("invalid gateway bundle validation = %v", err)
	}
	content = bytes.Replace(content, []byte(`env_key = "not-a-variable"`), []byte(`env_key = "AI_GATEWAY_API_KEY"`), 1)
	content = bytes.Replace(content, []byte(`wire_api = "responses"`), []byte("api_key = \"secret-sentinel\"\nwire_api = \"responses\""), 1)
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := agent.ValidateBundleDirectory(out, "windows"); err == nil || !strings.Contains(err.Error(), "api_key") || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("unsupported secret field validation = %v", err)
	}
}

func TestCompileBundleRejectsUnsupportedPairing(t *testing.T) {
	example, err := os.ReadFile(filepath.Join(exampleDir, "policy-map.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(example), "    agents: [codex]\n", "    agents: [codex, claude]\n", 1)
	if broken == string(example) {
		t.Fatal("fixture edit did not apply")
	}
	out, _, err := runCompileBundle(t, writeMap(t, broken), filepath.Join(exampleDir, "profiles"))
	if err == nil || !strings.Contains(err.Error(), "claude") || !strings.Contains(err.Error(), "contractor-readonly") {
		t.Fatalf("error = %v, want it to name contractor-readonly and claude", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("a failed compile must not write any output")
	}
}

func TestCompileBundleRejectsMissingNativeSection(t *testing.T) {
	m := writeMap(t, "version: 2\nmanaged_agents: [codex, windsurf]\nstandard:\n  profile: standard\n  priority: 100\n")
	if _, _, err := runCompileBundle(t, m, filepath.Join(exampleDir, "profiles")); err == nil || !strings.Contains(err.Error(), "no windsurf section") {
		t.Fatalf("error = %v", err)
	}
}

func TestCompileBundleRejectsNameMismatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "renamed.yaml"), []byte("version: 1\nname: other\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := writeMap(t, "version: 2\nmanaged_agents: [codex]\nstandard:\n  profile: renamed\n  priority: 100\n")
	if _, _, err := runCompileBundle(t, m, dir); err == nil || !strings.Contains(err.Error(), `"other"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestCompileBundleRejectsV1Map(t *testing.T) {
	m := writeMap(t, "version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n")
	if _, _, err := runCompileBundle(t, m, t.TempDir()); err == nil || !strings.Contains(err.Error(), "compile-bundle requires a version 2 map") {
		t.Fatalf("error = %v", err)
	}
}

// Writing over an earlier bundle would leave stale files, such as an old
// notes file, to be signed with the new one.
func TestCompileBundleRefusesExistingBundleDirectory(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dist")
	args := []string{"-map", filepath.Join(exampleDir, "policy-map.yaml"), "-profiles-dir", filepath.Join(exampleDir, "profiles"), "-target-os", "linux", "-output-dir", out}
	var output bytes.Buffer
	if err := compileBundleCommand(args, &output); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(out, "profiles", "linux", "old.claude.notes.json")
	if err := os.WriteFile(stale, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := compileBundleCommand(args, &output); err == nil || !strings.Contains(err.Error(), "already contains a bundle") {
		t.Fatalf("error = %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	os.MkdirAll(empty, 0755)
	args[len(args)-1] = empty
	if err := compileBundleCommand(args, &output); err != nil {
		t.Fatalf("an existing empty directory must be accepted: %v", err)
	}
}

// CI signs the repository's own sample with this exact command, so it must
// compile for every OS and pass bundle validation.
func TestRepositorySampleBundleCompilesAndValidates(t *testing.T) {
	out, _, err := runCompileBundle(t, filepath.Join("..", "..", "policy-map.yaml"), filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, osName := range []string{"windows", "linux", "darwin"} {
		if err := agent.ValidateBundleDirectory(out, osName); err != nil {
			t.Errorf("%s: %v", osName, err)
		}
	}
}
