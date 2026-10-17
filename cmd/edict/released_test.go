package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/hookjson"
)

func writePolicy(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A released agent is outside AgentEdict's hands: hooks still registered in
// users' home folders must let every action through.
func TestReleasedPolicyAllowsAntigravityAndCline(t *testing.T) {
	policy := writePolicy(t, hookjson.ReleasedPolicy)
	for _, input := range []string{`{"toolCall":{"name":"run_command","args":{}}}`, `{"toolCall":null}`} {
		var output, diagnostics bytes.Buffer
		code := hookCommand([]string{"antigravity", "-policy", policy}, strings.NewReader(input), &output, &diagnostics)
		if code != 0 || !strings.Contains(output.String(), `"decision":"allow"`) {
			t.Errorf("antigravity %s: code %d output %q", input, code, output.String())
		}
	}
	for _, input := range []string{`{"tool_call":{"name":"editor","input":{}}}`, `not json`} {
		var output, diagnostics bytes.Buffer
		code := hookCommand([]string{"cline", "-policy", policy}, strings.NewReader(input), &output, &diagnostics)
		if code != 0 || !strings.Contains(output.String(), `"cancel":false`) {
			t.Errorf("cline %s: code %d output %q", input, code, output.String())
		}
	}
}

// Cursor and Windsurf hook registrations are removed before their policy, so
// a released policy never applies to them and must still deny.
func TestReleasedPolicyIgnoredForCursorAndWindsurf(t *testing.T) {
	policy := writePolicy(t, hookjson.ReleasedPolicy)
	for _, args := range [][]string{
		{"cursor", "-event", "beforeShellExecution", "-policy", policy},
		{"windsurf", "-event", "pre_run_command", "-policy", policy},
	} {
		var output, diagnostics bytes.Buffer
		input := `{"command":"git status","tool_info":{"command_line":"git status"}}`
		if code := hookCommand(args, strings.NewReader(input), &output, &diagnostics); code != 2 {
			t.Errorf("%s: code %d, want 2", args[0], code)
		}
	}
}

func TestEditedReleasedPolicyStillDenies(t *testing.T) {
	for _, data := range []string{
		`{"agentedict": "released"}` + "\n",
		`{"agentedict":"released"}` + "\n{}",
		`{"agentedict":"released"}`,
		`{"agentedict":"released","tools":{}}` + "\n",
	} {
		policy := writePolicy(t, []byte(data))
		var output, diagnostics bytes.Buffer
		hookCommand([]string{"cline", "-policy", policy}, strings.NewReader(`{"tool_call":{"name":"editor","input":{}}}`), &output, &diagnostics)
		if !strings.Contains(output.String(), `"cancel":true`) {
			t.Errorf("cline honored edited released policy %q: %q", data, output.String())
		}
		output.Reset()
		hookCommand([]string{"antigravity", "-policy", policy}, strings.NewReader(`{"toolCall":{"name":"run_command","args":{}}}`), &output, &diagnostics)
		if !strings.Contains(output.String(), `"decision":"deny"`) {
			t.Errorf("antigravity honored edited released policy %q: %q", data, output.String())
		}
	}
	if !hookjson.IsReleased(hookjson.ReleasedPolicy) || hookjson.IsReleased([]byte(`{"agentedict":"released"}`)) {
		t.Error("IsReleased must compare exact bytes")
	}
}
