package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryandunton/agent-edict/internal/cursorhook"
)

func cursorNativeFixture() *CursorNativePolicy {
	return &CursorNativePolicy{Hooks: &cursorhook.Policy{Version: 1, ToolsAllow: []string{"Read", "Shell", "MCP:search"}, Shell: cursorhook.ShellPolicy{Allow: []string{"git status"}, Ask: []string{"git push"}}, MCP: []cursorhook.MCPRule{{Name: "docs", URL: "https://mcp.example.com/docs", Tools: []string{"search"}, Decision: "allow"}}}}
}

func TestCursorNativeHooksUseDocumentedSystemPaths(t *testing.T) {
	for _, tc := range []struct{ os, dir, sep, executable string }{
		{"linux", "/etc/cursor", "/", "/usr/local/bin/edict"},
		{"darwin", "/Library/Application Support/Cursor", "/", "/usr/local/bin/edict"},
		{"windows", `C:\ProgramData\Cursor`, `\`, `C:\Program Files\AgentEdict\edict.exe`},
	} {
		t.Run(tc.os, func(t *testing.T) {
			out, err := compileNativeCursor(cursorNativeFixture(), tc.os)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Artifacts) != 2 {
				t.Fatalf("expected sidecar and hook files, got %d", len(out.Artifacts))
			}
			artifacts := map[string]NativeArtifact{}
			for _, artifact := range out.Artifacts {
				artifacts[artifact.Extension] = artifact
			}
			hooks := artifacts["cursor.hooks.json"]
			policy := artifacts["cursor.policy.json"]
			if hooks.Destination != tc.dir+tc.sep+"hooks.json" || policy.Destination != tc.dir+tc.sep+"agentedict-policy.json" {
				t.Fatalf("incorrect consumer destinations: %+v", out.Artifacts)
			}
			if hooks.Delivery != "system-file" || policy.Delivery != "system-file" {
				t.Fatal("native files must declare delivery")
			}
			var native struct {
				Version int `json:"version"`
				Hooks   map[string][]struct {
					Command    string `json:"command"`
					FailClosed bool   `json:"failClosed"`
					Timeout    int    `json:"timeout"`
					Matcher    string `json:"matcher"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal([]byte(hooks.Content), &native); err != nil {
				t.Fatal(err)
			}
			if native.Version != 1 || len(native.Hooks) != 3 {
				t.Fatalf("unexpected hooks schema: %+v", native)
			}
			for _, event := range []string{"preToolUse", "beforeShellExecution", "beforeMCPExecution"} {
				entries := native.Hooks[event]
				if len(entries) != 1 {
					t.Fatalf("missing %s hook", event)
				}
				hook := entries[0]
				if !hook.FailClosed || hook.Timeout <= 0 || hook.Matcher != "" {
					t.Fatalf("hook failure or matcher could fail open: %+v", hook)
				}
				if !strings.Contains(hook.Command, tc.executable) || !strings.Contains(hook.Command, " hook cursor -event "+event+" -policy ") || !strings.Contains(hook.Command, policy.Destination) {
					t.Fatalf("wrong absolute hook command: %q", hook.Command)
				}
			}
			var response bytes.Buffer
			if err := cursorhook.Run("beforeShellExecution", strings.NewReader(policy.Content), strings.NewReader(`{"command":"git status; echo bypass"}`), &response); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(response.String(), `"permission":"deny"`) {
				t.Fatalf("compiled rules failed to deny unmatched invocation: %s", response.String())
			}
		})
	}
}

func TestCursorNativeRejectsMissingOrAmbiguousPolicy(t *testing.T) {
	for _, p := range []*CursorNativePolicy{nil, {}, {Hooks: &cursorhook.Policy{Version: 1, Shell: cursorhook.ShellPolicy{Allow: []string{"git status"}, Ask: []string{"git status"}}}}} {
		if _, err := compileNativeCursor(p, "linux"); err == nil {
			t.Error("invalid Cursor policy compiled")
		}
	}
	if _, err := compileNativeCursor(cursorNativeFixture(), "other"); err == nil {
		t.Error("unsupported platform compiled")
	}
}

func TestCursorNativeReportsGuardrailLimits(t *testing.T) {
	out, err := compileNativeCursor(cursorNativeFixture(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	controls := map[string]NativeCapability{}
	for _, capability := range out.Capabilities {
		controls[capability.Control] = capability
	}
	for _, control := range []string{"tool_invocations", "shell_invocations", "mcp_tool_invocations", "process_containment", "filesystem", "client_verification"} {
		if controls[control].Details == "" {
			t.Errorf("missing disclosure for %s", control)
		}
	}
	if controls["process_containment"].Level != "not-enforced" || controls["filesystem"].Level != "not-enforced" {
		t.Error("hooks must not claim OS process/filesystem isolation")
	}
}

func TestCursorWindowsCommandThroughDocumentedClientTransport(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is required to validate the shipped Windows hook transport")
	}
	out, err := compileNativeCursor(cursorNativeFixture(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Hooks map[string][]struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	for _, artifact := range out.Artifacts {
		if artifact.Extension == "cursor.hooks.json" {
			if err := json.Unmarshal([]byte(artifact.Content), &config); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	captureDir := filepath.Join(root, "Program Files")
	if err := os.Mkdir(captureDir, 0700); err != nil {
		t.Fatal(err)
	}
	capturePath := filepath.Join(captureDir, "capture.ps1")
	capture := `param([Parameter(Position=0)][string]$Command,[Parameter(Position=1)][string]$Product,[string]$Event,[string]$Policy,[Parameter(ValueFromPipeline=$true)][string]$InputData)
process {
  $payload = $InputData.Trim()
  @{ command=$Command; product=$Product; event=$Event; policy=$Policy; payload=$payload } | ConvertTo-Json -Compress
}
`
	if err := os.WriteFile(capturePath, []byte(capture), 0600); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(root, "input.json")
	if err := os.WriteFile(payloadPath, []byte(`{"command":"git status"}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Cursor 3.24.18's Windows transport converts a quoted executable command
	// into a PowerShell invocation using &, then pipes the JSON payload to it.
	// Substitute a harmless capture script without changing quoting or argv.
	command := config.Hooks["beforeShellExecution"][0].Command
	command = strings.Replace(command, `C:\Program Files\AgentEdict\edict.exe`, capturePath, 1)
	fixture, _ := json.Marshal(map[string]string{"command": command, "payload": payloadPath})
	fixturePath := filepath.Join(root, "fixture.json")
	if err := os.WriteFile(fixturePath, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	harness := `param([string]$Fixture)
$ErrorActionPreference = 'Stop'
$data = Get-Content -LiteralPath $Fixture -Raw | ConvertFrom-Json
$tokens = $null; $parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($data.command, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -eq 0) { throw 'The raw quoted command should require the PowerShell call operator.' }
$adapted = '& ' + $data.command
$payload = $data.payload.Replace("'", "''")
$transport = "Get-Content -LiteralPath '$payload' -Raw | & { " + '$input | ' + $adapted + ' }'
Invoke-Expression $transport
`
	harnessPath := filepath.Join(root, "transport.ps1")
	if err := os.WriteFile(harnessPath, []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-File", harnessPath, "-Fixture", fixturePath).CombinedOutput()
	if err != nil {
		t.Fatalf("Cursor-style PowerShell transport failed: %v: %s", err, result)
	}
	var received map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(result), &received); err != nil {
		t.Fatalf("invalid capture response: %s: %v", result, err)
	}
	for key, expected := range map[string]string{"command": "hook", "product": "cursor", "event": "beforeShellExecution", "policy": `C:\ProgramData\Cursor\agentedict-policy.json`, "payload": `{"command":"git status"}`} {
		if received[key] != expected {
			t.Errorf("%s: got %q, want %q", key, received[key], expected)
		}
	}
}
