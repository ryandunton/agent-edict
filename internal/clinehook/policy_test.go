package clinehook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testPolicy = `{"version":1,"tools":{"read_files":"allow","editor":"deny"},"commands":["git status","npm test"]}`

func decide(t *testing.T, input string) bool {
	t.Helper()
	allowed, err := Evaluate(strings.NewReader(testPolicy), strings.NewReader(input))
	if err != nil {
		return false
	}
	return allowed
}

func TestClineSDKAndVSCodePayloads(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		allowed     bool
	}{
		// CLI / SDK file hooks.
		{"sdk allowed tool", `{"hookName":"tool_call","tool_call":{"id":"1","name":"read_files","input":{"files":["/repo/a.go"]}}}`, true},
		{"sdk denied tool", `{"hookName":"tool_call","tool_call":{"name":"editor","input":{}}}`, false},
		{"sdk unlisted tool", `{"tool_call":{"name":"fetch_web_content","input":{"url":"https://example.com"}}}`, false},
		{"sdk commands array", `{"tool_call":{"name":"run_commands","input":{"commands":["git status","npm test"]}}}`, true},
		{"sdk one unlisted command", `{"tool_call":{"name":"run_commands","input":{"commands":["git status","rm -rf ~"]}}}`, false},
		{"sdk command string", `{"tool_call":{"name":"run_commands","input":{"command":"git status"}}}`, true},
		{"sdk cmd alias", `{"tool_call":{"name":"run_commands","input":{"cmd":"npm test"}}}`, true},
		{"sdk bare string", `{"tool_call":{"name":"run_commands","input":"git status"}}`, true},
		{"sdk bare array", `{"tool_call":{"name":"run_commands","input":["git status"]}}`, true},
		{"sdk structured argv", `{"tool_call":{"name":"run_commands","input":{"commands":[{"command":"git","args":["status"]}]}}}`, true},
		{"sdk structured argv with shell text", `{"tool_call":{"name":"run_commands","input":[{"command":"git","args":["status; rm -rf ~"]}]}}`, false},
		{"sdk ambiguous argv spacing", `{"tool_call":{"name":"run_commands","input":{"command":"git","args":["status --short"]}}}`, false},
		{"sdk compound command", `{"tool_call":{"name":"run_commands","input":{"commands":["git status && rm -rf ~"]}}}`, false},
		{"sdk empty commands", `{"tool_call":{"name":"run_commands","input":{"commands":[]}}}`, false},
		{"sdk unknown command key", `{"tool_call":{"name":"run_commands","input":{"commands":["git status"],"timeout":5}}}`, false},
		// VS Code extension: parameters are a string record.
		{"vscode allowed tool", `{"taskId":"t","hookName":"PreToolUse","preToolUse":{"toolName":"read_files","parameters":{"files":"[\"/repo/a.go\"]"}}}`, true},
		{"vscode stringified commands", `{"preToolUse":{"toolName":"run_commands","parameters":{"commands":"[\"git status\"]"}}}`, true},
		{"vscode plain command", `{"preToolUse":{"toolName":"run_commands","parameters":{"commands":"npm test"}}}`, true},
		{"vscode shell test command", `{"preToolUse":{"toolName":"run_commands","parameters":{"commands":"[ -f x ] && rm x"}}}`, false},
		{"vscode legacy execute_command", `{"preToolUse":{"toolName":"execute_command","parameters":{"command":"git status","requires_approval":"false"}}}`, true},
		{"vscode legacy extra field", `{"preToolUse":{"toolName":"execute_command","parameters":{"command":"git status","cwd":"/"}}}`, false},
		{"sdk requires_approval is legacy-only", `{"tool_call":{"name":"run_commands","input":{"command":"git status","requires_approval":false}}}`, false},
		{"vscode legacy unlisted", `{"preToolUse":{"toolName":"execute_command","parameters":{"command":"curl x"}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tc.input); got != tc.allowed {
				t.Fatalf("allowed=%v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestClineRejectsMalformedOrAmbiguousPayloads(t *testing.T) {
	for name, input := range map[string]string{
		"both shapes":      `{"tool_call":{"name":"read_files","input":{}},"preToolUse":{"toolName":"read_files","parameters":{}}}`,
		"no shape":         `{"hookName":"tool_call"}`,
		"wrong hook name":  `{"hookName":"tool_result","tool_call":{"name":"read_files","input":{}}}`,
		"duplicate key":    `{"tool_call":{"name":"read_files","name":"editor","input":{}}}`,
		"missing name":     `{"tool_call":{"input":{}}}`,
		"non-string param": `{"preToolUse":{"toolName":"read_files","parameters":{"files":["a"]}}}`,
		"truncated":        `{"tool_call":{"name":"read_files"`,
	} {
		t.Run(name, func(t *testing.T) {
			if allowed, err := Evaluate(strings.NewReader(testPolicy), strings.NewReader(input)); allowed || err == nil {
				t.Fatalf("malformed payload allowed=%v err=%v", allowed, err)
			}
		})
	}
}

func TestClineResponsesAreValidCancelControls(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		var out bytes.Buffer
		if err := Respond(&out, allowed); err != nil {
			t.Fatal(err)
		}
		var control struct {
			Cancel       *bool  `json:"cancel"`
			ErrorMessage string `json:"errorMessage"`
		}
		if err := json.Unmarshal(out.Bytes(), &control); err != nil || control.Cancel == nil || *control.Cancel == allowed {
			t.Fatalf("invalid control for allowed=%v: %s", allowed, &out)
		}
		if !allowed && control.ErrorMessage == "" {
			t.Fatal("cancel must explain itself to the agent")
		}
	}
}

func TestClinePolicyValidation(t *testing.T) {
	if err := ValidatePolicy(&Policy{Version: 1}); err != nil {
		t.Fatalf("empty policy denies everything and is valid: %v", err)
	}
	for name, p := range map[string]Policy{
		"version":           {Version: 0},
		"bad decision":      {Version: 1, Tools: map[string]string{"read_files": "ask"}},
		"command tool":      {Version: 1, Tools: map[string]string{"run_commands": "allow"}},
		"wildcard tool":     {Version: 1, Tools: map[string]string{"*": "allow"}},
		"duplicate command": {Version: 1, Commands: []string{"ls", "ls"}},
		"wildcard command":  {Version: 1, Commands: []string{"*"}},
		"control command":   {Version: 1, Commands: []string{"ls\r"}},
	} {
		if err := ValidatePolicy(&p); err == nil {
			t.Errorf("%s: invalid policy accepted", name)
		}
	}
}
