package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryandunton/agent-edict/internal/clinehook"
	"github.com/ryandunton/agent-edict/internal/windsurfhook"
)

func windsurfFixture() *WindsurfNativePolicy {
	return &WindsurfNativePolicy{Hooks: &windsurfhook.Policy{Version: 1, Commands: []string{"git status"}, MCP: []windsurfhook.MCPRule{{Server: "github", Tools: []string{"create_issue"}}}}}
}

type windsurfHookFile struct {
	Hooks map[string][]struct {
		Command    string `json:"command"`
		PowerShell string `json:"powershell"`
	} `json:"hooks"`
}

func windsurfArtifacts(t *testing.T, osName string) (NativeArtifact, NativeArtifact, windsurfHookFile) {
	t.Helper()
	out, err := compileNativeWindsurf(windsurfFixture(), osName)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Artifacts) != 2 {
		t.Fatalf("expected policy and hooks, got %d", len(out.Artifacts))
	}
	byExt := map[string]NativeArtifact{}
	for _, a := range out.Artifacts {
		byExt[a.Extension] = a
	}
	var hooks windsurfHookFile
	if err := json.Unmarshal([]byte(byExt["windsurf.hooks.json"].Content), &hooks); err != nil {
		t.Fatal(err)
	}
	return byExt["windsurf.policy.json"], byExt["windsurf.hooks.json"], hooks
}

func TestWindsurfSystemHooksUseDocumentedPathsAndEvents(t *testing.T) {
	for _, tc := range []struct{ os, policy, hooks string }{
		{"linux", "/etc/agent-edict/windsurf-policy.json", "/etc/devin/hooks.json"},
		{"darwin", "/etc/agent-edict/windsurf-policy.json", "/Library/Application Support/Devin/hooks.json"},
		{"windows", `C:\ProgramData\AgentEdict\windsurf-policy.json`, `C:\ProgramData\Devin\hooks.json`},
	} {
		policy, hooksArtifact, hooks := windsurfArtifacts(t, tc.os)
		if policy.Destination != tc.policy || hooksArtifact.Destination != tc.hooks {
			t.Fatalf("%s: wrong destinations %s, %s", tc.os, policy.Destination, hooksArtifact.Destination)
		}
		if len(hooks.Hooks) != len(windsurfhook.Events) {
			t.Fatalf("%s: unexpected events %v", tc.os, hooks.Hooks)
		}
		for _, event := range windsurfhook.Events {
			entries := hooks.Hooks[event]
			if len(entries) != 1 {
				t.Fatalf("%s: missing %s", tc.os, event)
			}
			h := entries[0]
			invocation := " hook windsurf -event " + event + " -policy '" + tc.policy + "'"
			if tc.os == "windows" {
				// Cascade falls back to command on Windows; only powershell may be set.
				if h.Command != "" || !strings.Contains(h.PowerShell, `& 'C:\Program Files\AgentEdict\edict.exe'`+invocation) || !strings.HasSuffix(h.PowerShell, "; exit $LASTEXITCODE") {
					t.Fatalf("Windows hook cannot propagate exit 2: %+v", h)
				}
			} else if h.PowerShell != "" || h.Command != "'/usr/local/bin/edict'"+invocation {
				t.Fatalf("%s: wrong Unix hook %+v", tc.os, h)
			}
		}
		if err := windsurfhook.Evaluate("pre_run_command", strings.NewReader(policy.Content), strings.NewReader(`{"tool_info":{"command_line":"git status; rm -rf ~"}}`)); !errors.Is(err, windsurfhook.ErrBlocked) {
			t.Fatalf("compiled policy must block unlisted commands: %v", err)
		}
	}
	out, err := compileNativeWindsurf(&WindsurfNativePolicy{Hooks: &windsurfhook.Policy{Version: 1}}, "linux")
	if err != nil || !strings.Contains(out.Artifacts[0].Content, `"commands": []`) || !strings.Contains(out.Artifacts[0].Content, `"mcp": []`) {
		t.Fatalf("empty policy must emit explicit empty lists: %v", err)
	}
	for _, p := range []*WindsurfNativePolicy{nil, {}, {Hooks: &windsurfhook.Policy{Version: 1, Commands: []string{"*"}}}} {
		if _, err := compileNativeWindsurf(p, "linux"); err == nil {
			t.Error("invalid Windsurf policy compiled")
		}
	}
}

// writeStandIn writes a PowerShell script that replaces edict.exe in a shipped
// Windows hook: it records argv and stdin, prints out, and exits with code.
func writeStandIn(t *testing.T, dir, out string, code int) string {
	t.Helper()
	path := filepath.Join(dir, "edict stand-in.ps1")
	script := `param([Parameter(Position=0)][string]$Command,[Parameter(Position=1)][string]$Product,[string]$Event,[string]$Policy,[Parameter(ValueFromPipeline=$true)][string]$InputData)
process {
  $record = @{ command=$Command; product=$Product; event=$Event; policy=$Policy; payload=$InputData.TrimEnd() } | ConvertTo-Json -Compress
  [IO.File]::WriteAllText('` + filepath.Join(dir, "received.json") + `', $record, [Text.UTF8Encoding]::new($false))
}
end { if ('` + out + `') { [Console]::Out.Write('` + out + `') }; exit ` + string(rune('0'+code)) + ` }
`
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runPowerShell(t *testing.T, args []string, stdin string) (string, int, map[string]string) {
	t.Helper()
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is required to validate the shipped Windows hook transport")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pwsh, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err = cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stdout.String(), code, nil
}

func TestWindsurfWindowsHookForwardsPayloadAndExitCode(t *testing.T) {
	_, _, hooks := windsurfArtifacts(t, "windows")
	payload := `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"git status — ünïcode","cwd":"C:\\repo"}}`
	for _, want := range []int{2, 0} {
		dir := t.TempDir()
		standIn := writeStandIn(t, dir, "", want)
		command := strings.Replace(hooks.Hooks["pre_run_command"][0].PowerShell, `C:\Program Files\AgentEdict\edict.exe`, standIn, 1)
		// Cascade runs Windows hooks as: powershell -Command <powershell>.
		_, code, _ := runPowerShell(t, []string{"-NoProfile", "-NonInteractive", "-Command", command}, payload)
		if code != want {
			t.Fatalf("hook exit %d did not reach Cascade (got %d)", want, code)
		}
		var received map[string]string
		data, err := os.ReadFile(filepath.Join(dir, "received.json"))
		if err != nil || json.Unmarshal(data, &received) != nil {
			t.Fatalf("stand-in did not run: %v %s", err, data)
		}
		if received["payload"] != payload || received["product"] != "windsurf" || received["event"] != "pre_run_command" || received["policy"] != `C:\ProgramData\AgentEdict\windsurf-policy.json` {
			t.Fatalf("payload or arguments changed in transit: %v", received)
		}
	}
}

func TestClinePolicyAndUserHook(t *testing.T) {
	p := &ClineNativePolicy{Hooks: &clinehook.Policy{Version: 1, Tools: map[string]string{"read_files": "allow"}, Commands: []string{"git status"}}}
	for osName, path := range map[string]string{"linux": "/etc/agent-edict/cline-policy.json", "darwin": "/etc/agent-edict/cline-policy.json", "windows": `C:\ProgramData\AgentEdict\cline-policy.json`} {
		out, err := compileNativeCline(p, osName)
		if err != nil {
			t.Fatal(err)
		}
		artifact := singleArtifact(t, out)
		if artifact.Destination != path || artifact.Extension != "cline.policy.json" {
			t.Fatalf("%s: wrong artifact %+v", osName, artifact)
		}
		allowed, err := clinehook.Evaluate(strings.NewReader(artifact.Content), strings.NewReader(`{"tool_call":{"name":"run_commands","input":{"commands":["git status && curl x"]}}}`))
		if err != nil || allowed {
			t.Fatalf("compiled policy must cancel unlisted commands: %v %v", allowed, err)
		}
		name, script := ClineUserHook(osName)
		if !strings.Contains(script, "hook cline -policy '"+path+"'") {
			t.Fatalf("%s: user hook does not reference the machine policy: %s", osName, script)
		}
		if osName == "windows" && name != "PreToolUse.ps1" || osName != "windows" && (name != "PreToolUse" || !strings.HasPrefix(script, "#!/bin/sh\n")) {
			t.Fatalf("%s: wrong hook file %s", osName, name)
		}
	}
	controls := map[string]string{}
	out, _ := compileNativeCline(p, "linux")
	for _, c := range out.Capabilities {
		controls[c.Control] = c.Level
	}
	if controls["remote_configuration"] != "not-supported" || controls["failure_mode"] != "not-enforced" || controls["mandatory_registration"] != "not-enforced" {
		t.Fatalf("Cline limits must be disclosed: %v", controls)
	}
	for _, bad := range []*ClineNativePolicy{nil, {}, {Hooks: &clinehook.Policy{Version: 1, Tools: map[string]string{"run_commands": "allow"}}}} {
		if _, err := compileNativeCline(bad, "linux"); err == nil {
			t.Error("invalid Cline policy compiled")
		}
	}
}

func TestClineUnixHookForwardsPayloadAndAnswer(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	dir := t.TempDir()
	standIn := filepath.Join(dir, "edict")
	if err := os.WriteFile(standIn, []byte("#!/bin/sh\ncat > '"+filepath.Join(dir, "stdin")+"'\nprintf '%s|' \"$@\" > '"+filepath.Join(dir, "argv")+"'\nprintf '{\"cancel\":true}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, script := ClineUserHook("linux")
	hook := filepath.Join(dir, "PreToolUse")
	if err := os.WriteFile(hook, []byte(strings.Replace(script, "/usr/local/bin/edict", standIn, 1)), 0700); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_call":{"name":"run_commands","input":{"commands":["ls — ü"]}}}`
	cmd := exec.Command(sh, hook) // Cline's SDK runs a #!/bin/sh hook as: sh <file>
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.Output()
	if err != nil || string(out) != `{"cancel":true}` {
		t.Fatalf("hook answer lost: %q %v", out, err)
	}
	stdin, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	if string(stdin) != payload || string(argv) != "hook|cline|-policy|/etc/agent-edict/cline-policy.json|" {
		t.Fatalf("payload or argv changed: %q %q", stdin, argv)
	}
}

func TestClineWindowsHookForwardsPayloadAndAnswer(t *testing.T) {
	dir := t.TempDir()
	answer := `{"cancel":true,"errorMessage":"denied"}`
	standIn := writeStandIn(t, dir, answer, 0)
	_, script := ClineUserHook("windows")
	hook := filepath.Join(dir, "PreToolUse.ps1")
	if err := os.WriteFile(hook, []byte(strings.Replace(script, `C:\Program Files\AgentEdict\edict.exe`, standIn, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	payload := `{"preToolUse":{"toolName":"run_commands","parameters":{"commands":"ls — ü"}}}`
	// The VS Code extension runs: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <hook>.
	stdout, code, _ := runPowerShell(t, []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", hook}, payload)
	if code != 0 || strings.TrimSpace(stdout) != answer {
		t.Fatalf("hook answer lost: code=%d stdout=%q", code, stdout)
	}
	var received map[string]string
	data, err := os.ReadFile(filepath.Join(dir, "received.json"))
	if err != nil || json.Unmarshal(data, &received) != nil || received["payload"] != payload || received["product"] != "cline" {
		t.Fatalf("payload changed in transit: %v %s", err, data)
	}
}
