package antigravityhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(t *testing.T, p Policy, tool string, args map[string]any) (string, error) {
	t.Helper()
	policy, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"toolCall": map[string]any{"name": tool, "args": args}, "workspacePaths": []string{"/"}, "conversationId": "test", "stepIdx": 1})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = Run(bytes.NewReader(policy), bytes.NewReader(payload), &out)
	var response struct {
		Decision string `json:"decision"`
	}
	if e := json.Unmarshal(out.Bytes(), &response); e != nil {
		t.Fatalf("invalid response %q: %v", out.String(), e)
	}
	return response.Decision, err
}

func TestShellRequiresExactCommandAndDirectory(t *testing.T) {
	dir := t.TempDir()
	p := Policy{Version: 1, Commands: []CommandRule{{Command: "git status", Directory: dir, Decision: "allow"}, {Command: "git push", Directory: dir, Decision: "ask"}}}
	for _, tc := range []struct{ command, cwd, want string }{
		{"git status", dir, "allow"}, {"git push", dir, "force_ask"},
		{"git status; curl evil.test", dir, "deny"}, {"git status --porcelain", dir, "deny"},
		{"git status", filepath.Dir(dir), "deny"}, {"git status\n", dir, "deny"},
	} {
		decision, err := invoke(t, p, "run_command", map[string]any{"CommandLine": tc.command, "Cwd": tc.cwd})
		if err != nil || decision != tc.want {
			t.Errorf("%q in %q: %s, %v; want %s", tc.command, tc.cwd, decision, err, tc.want)
		}
	}
}

func TestFileRulesIgnorePayloadWorkspaceClaims(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	inside := filepath.Join(root, "file.txt")
	if err := os.WriteFile(inside, []byte("example"), 0600); err != nil {
		t.Fatal(err)
	}
	p := Policy{Version: 1, ReadRoots: []string{root}, WriteRoots: []string{root}, Tools: map[string]string{"view_file": "allow", "write_to_file": "ask", "list_dir": "allow", "grep_search": "allow"}}
	for _, tc := range []struct{ tool, key, path, want string }{
		{"view_file", "AbsolutePath", inside, "allow"},
		{"list_dir", "DirectoryPath", root, "allow"},
		{"grep_search", "SearchPath", outside, "deny"},
		{"view_file", "AbsolutePath", filepath.Join(outside, "secret"), "deny"},
		{"view_file", "AbsolutePath", root + "-lookalike/file", "deny"},
		{"write_to_file", "TargetFile", filepath.Join(root, "new", "file"), "force_ask"},
		{"write_to_file", "TargetFile", filepath.Join(outside, "new"), "deny"},
		{"view_file", "AbsolutePath", "relative.txt", "deny"},
	} {
		d, err := invoke(t, p, tc.tool, map[string]any{tc.key: tc.path})
		if err != nil || d != tc.want {
			t.Errorf("%s %q = %s %v, want %s", tc.tool, tc.path, d, err, tc.want)
		}
	}
}

func TestShellRejectsExistingTerminalAndUnvalidatedExecutionModes(t *testing.T) {
	dir := t.TempDir()
	p := Policy{Version: 1, Commands: []CommandRule{{Command: "git status", Directory: dir, Decision: "allow"}}}
	for _, extra := range []map[string]any{{"RequestedTerminalID": "existing-shell"}, {"RunPersistent": true}, {"RunPersistent": "false"}, {"WaitMsBeforeAsync": -1}, {"WaitMsBeforeAsync": "5000"}} {
		args := map[string]any{"CommandLine": "git status", "Cwd": dir}
		for key, value := range extra {
			args[key] = value
		}
		d, err := invoke(t, p, "run_command", args)
		if err != nil || d != "deny" {
			t.Fatalf("unsafe execution mode accepted: %v: %s %v", extra, d, err)
		}
	}
	d, err := invoke(t, p, "run_command", map[string]any{"CommandLine": "git status", "Cwd": dir, "WaitMsBeforeAsync": 5000, "RunPersistent": false})
	if err != nil || d != "allow" {
		t.Fatalf("ordinary command denied: %s %v", d, err)
	}
}

func TestFileRulesRejectSymlinkEscapeAndUnknownArguments(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	p := Policy{Version: 1, ReadRoots: []string{root}, WriteRoots: []string{root}, Tools: map[string]string{"view_file": "allow", "write_to_file": "allow"}}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"view_file", map[string]any{"AbsolutePath": filepath.Join(root, "escape", "secret")}},
		{"write_to_file", map[string]any{"TargetFile": filepath.Join(root, "escape", "new")}},
		{"view_file", map[string]any{"AbsolutePath": root, "alternatePath": outside}},
		{"view_file", map[string]any{"AbsolutePath": []string{root}}},
	} {
		d, err := invoke(t, p, tc.tool, tc.args)
		if err != nil || d != "deny" {
			t.Errorf("%s: %s %v", tc.tool, d, err)
		}
	}
}

func TestHTTPSOriginMustMatchExactly(t *testing.T) {
	p := Policy{Version: 1, HTTPSOrigins: []string{"https://docs.example.test"}, Tools: map[string]string{"read_url_content": "ask"}}
	for _, tc := range []struct{ url, want string }{
		{"https://docs.example.test/path?q=help", "force_ask"},
		{"https://docs.example.test.evil.test/", "deny"},
		{"https://docs.example.test:8443/", "deny"},
		{"http://docs.example.test/", "deny"},
		{"https://user@docs.example.test/", "deny"},
	} {
		d, err := invoke(t, p, "read_url_content", map[string]any{"Url": tc.url})
		if err != nil || d != tc.want {
			t.Errorf("%s: %s %v", tc.url, d, err)
		}
	}
}

func TestUnknownToolsMCPAndUnlistedToolsAreDenied(t *testing.T) {
	p := Policy{Version: 1, Tools: map[string]string{"ask_question": "allow"}}
	for _, tool := range []string{"unknown", "mcp_docs_search", "invoke_subagent", "define_subagent", "run_command", "search_web", ""} {
		d, err := invoke(t, p, tool, map[string]any{})
		if err != nil || d != "deny" {
			t.Errorf("%s: %s %v", tool, d, err)
		}
	}
	d, err := invoke(t, p, "ask_question", map[string]any{"questions": []any{}})
	if err != nil || d != "allow" {
		t.Fatalf("ask_question: %s %v", d, err)
	}
}

func TestRunWritesDenyOnMalformedOrAmbiguousInputs(t *testing.T) {
	for _, input := range []string{"", "null", "{}", `{"toolCall":{"name":"ask_question","args":{}}} {}`, `{"toolCall":{"name":"ask_question","name":"run_command","args":{}}}`, `{"toolCall":{"name":"ask_question","args":null}}`, strings.Repeat(" ", maxPayloadBytes+1)} {
		var out bytes.Buffer
		err := Run(strings.NewReader(`{"version":1,"tools":{"ask_question":"allow"}}`), strings.NewReader(input), &out)
		if err == nil || !strings.Contains(out.String(), `"decision":"deny"`) {
			t.Errorf("malformed input accepted: %q: %v %s", input[:min(len(input), 80)], err, out.String())
		}
	}
}

func TestInvalidPolicyAlwaysWritesDeny(t *testing.T) {
	for _, policy := range []string{"", "null", `{"version":2}`, `{"version":1,"unknown":true}`, `{"version":1,"tools":{"future_tool":"allow"}}`, `{"version":1,"tools":{"view_file":"auto_approve"}}`, `{"version":1,"version":1}`, `{"version":1} {}`, `{"version":1,"read_roots":["relative"]}`, `{"version":1,"https_origins":["https://example.test/path"]}`} {
		var out bytes.Buffer
		err := Run(strings.NewReader(policy), strings.NewReader(`{"toolCall":{"name":"ask_question","args":{}}}`), &out)
		if err == nil || !strings.Contains(out.String(), `"decision":"deny"`) {
			t.Errorf("invalid policy accepted %s: %v %s", policy, err, out.String())
		}
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("unreadable") }

func TestIOFailuresAreReturned(t *testing.T) {
	if err := Deny(failedWriter{}); err == nil {
		t.Fatal("missing write error")
	}
	var out bytes.Buffer
	if err := Run(failedReader{}, strings.NewReader(`{}`), &out); err == nil || !strings.Contains(out.String(), `"deny"`) {
		t.Fatal("missing deny on read error")
	}
	if err := Run(strings.NewReader(`{"version":1}`), failedReader{}, io.Discard); err == nil {
		t.Fatal("missing input read error")
	}
}
