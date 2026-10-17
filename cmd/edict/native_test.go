package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCLIProducesCompletePlatformOutputs(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(profile, []byte("version: 1\nname: desktop\ngemini:\n  default_decision: deny\ncursor:\n  hooks:\n    version: 1\nantigravity:\n  hooks:\n    version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "compiled")
	var output bytes.Buffer
	if err := compileNativeCommand([]string{"-profile", profile, "-output-dir", outDir}, &output); err != nil {
		t.Fatal(err)
	}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		for _, extension := range []string{"native.yaml", "native-capabilities.json", "gemini.json", "gemini.policy.toml", "cursor.hooks.json", "cursor.policy.json", "antigravity.hooks.json", "antigravity.policy.json"} {
			if _, err := os.Stat(filepath.Join(outDir, osName, "desktop."+extension)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !strings.Contains(output.String(), "not-enforced") {
		t.Fatal("capability limits missing from output")
	}
}

func TestAntigravityHookCLIUsesNativeProtocol(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte(`{"version":1,"tools":{"ask_question":"ask"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		input, decision string
		code            int
	}{
		{`{"toolCall":{"name":"ask_question","args":{}}}`, "force_ask", 0},
		{`{"toolCall":{"name":"run_command","args":{}}}`, "deny", 0},
		{`{"toolCall":null}`, "deny", 2},
	} {
		var output, diagnostics bytes.Buffer
		code := hookCommand([]string{"antigravity", "-policy", policy}, strings.NewReader(tc.input), &output, &diagnostics)
		if code != tc.code || !strings.Contains(output.String(), `"decision":"`+tc.decision+`"`) {
			t.Fatalf("wrong Antigravity protocol: %s code=%d", &output, code)
		}
	}
}

func TestWindsurfHookCLIBlocksWithExitCodeTwo(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte(`{"version":1,"commands":["git status"],"mcp":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	run := []string{"windsurf", "-event", "pre_run_command", "-policy", policy}
	for _, tc := range []struct {
		args  []string
		input string
		code  int
	}{
		{run, `{"tool_info":{"command_line":"git status"}}`, 0},
		{run, `{"tool_info":{"command_line":"git status; rm -rf ~"}}`, 2},
		{run, `{"tool_info":`, 2},
		{[]string{"windsurf", "-event", "pre_read_code", "-policy", policy}, `{"tool_info":{"file_path":"/a"}}`, 2},
		{[]string{"windsurf", "-event", "pre_run_command", "-policy", policy + ".missing"}, `{}`, 2},
		{[]string{"windsurf", "-policy", policy}, `{}`, 2},
	} {
		var output, diagnostics bytes.Buffer
		code := hookCommand(tc.args, strings.NewReader(tc.input), &output, &diagnostics)
		if code != tc.code {
			t.Fatalf("%v %s: code %d, want %d", tc.args, tc.input, code, tc.code)
		}
		// Cascade shows stderr to the agent when a pre-hook blocks.
		if code == 2 && !strings.Contains(diagnostics.String(), "AgentEdict") {
			t.Fatalf("block without explanation: %q", diagnostics.String())
		}
		if output.Len() != 0 {
			t.Fatalf("Windsurf hooks must not write stdout: %q", output.String())
		}
	}
}

func TestClineHookCLIAlwaysAnswersWithJSONAndExitZero(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte(`{"version":1,"tools":{"read_files":"allow"},"commands":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args   []string
		input  string
		cancel bool
	}{
		{[]string{"cline", "-policy", policy}, `{"tool_call":{"name":"read_files","input":{}}}`, false},
		{[]string{"cline", "-policy", policy}, `{"tool_call":{"name":"editor","input":{}}}`, true},
		{[]string{"cline", "-policy", policy}, `not json`, true},
		{[]string{"cline", "-policy", policy + ".missing"}, `{}`, true},
		{[]string{"cline", "-event", "x", "-policy", policy}, `{"tool_call":{"name":"read_files","input":{}}}`, true},
		{[]string{"cline", "-unknown"}, `{}`, true},
	} {
		var output, diagnostics bytes.Buffer
		// Cline treats a non-zero exit as permission to run the tool.
		if code := hookCommand(tc.args, strings.NewReader(tc.input), &output, &diagnostics); code != 0 {
			t.Fatalf("%v: Cline hook must exit 0, got %d", tc.args, code)
		}
		want := `"cancel":false`
		if tc.cancel {
			want = `"cancel":true`
		}
		if !strings.Contains(output.String(), want) {
			t.Fatalf("%v %s: got %q, want %s", tc.args, tc.input, output.String(), want)
		}
	}
}

func TestCursorHookCLIAlwaysDeniesInvalidRequests(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte(`{"version":1,"shell":{"allow":["git status"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args     []string
		input    string
		code     int
		decision string
	}{
		{[]string{"cursor", "-event", "beforeShellExecution", "-policy", policy}, `{"command":"git status"}`, 0, "allow"},
		{[]string{"cursor", "-event", "beforeShellExecution", "-policy", policy}, `{"command":"git status; echo bypass"}`, 0, "deny"},
		{[]string{"cursor", "-event", "beforeShellExecution", "-policy", policy}, `{"command":`, 2, "deny"},
		{[]string{"cursor", "-policy", policy + ".missing"}, `{}`, 2, "deny"},
		{[]string{"cursor", "-unknown"}, `{}`, 2, "deny"},
	} {
		var output, diagnostics bytes.Buffer
		if code := hookCommand(tc.args, strings.NewReader(tc.input), &output, &diagnostics); code != tc.code {
			t.Fatalf("code %d, expected %d", code, tc.code)
		}
		if !strings.Contains(output.String(), `"permission":"`+tc.decision+`"`) {
			t.Fatalf("wrong hook response %s", &output)
		}
	}
}
