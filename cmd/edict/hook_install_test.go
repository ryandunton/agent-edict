package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAntigravityRegistrationPreservesOtherHooksAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".gemini", "config")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	existing := []byte(`{"my-linter":{"PostToolUse":[]},"agent-edict":{"enabled":false}}`)
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, existing, 0600); err != nil {
		t.Fatal(err)
	}
	template := []byte(`{"agent-edict":{"enabled":true,"PreToolUse":[]}}`)
	_, changed, err := installAntigravityRegistration(home, template)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v error=%v", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 2 || hooks["my-linter"] == nil {
		t.Fatalf("other hooks lost: %s", data)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "hooks.json.before-agentedict-*"))
	if len(backups) != 1 {
		t.Fatal("original registration not backed up")
	}
	backup, _ := os.ReadFile(backups[0])
	if string(backup) != string(existing) {
		t.Fatal("backup differs")
	}
	_, changed, err = installAntigravityRegistration(home, template)
	if err != nil || changed {
		t.Fatalf("idempotent install: changed=%v error=%v", changed, err)
	}
}

func TestClineHookInstallIsIdempotentAndNeverClobbersUserHooks(t *testing.T) {
	base := t.TempDir()
	script := "#!/bin/sh\nexec edict hook cline\n"
	path, changed, err := installClineHook(base, []string{".cline", "hooks"}, "PreToolUse", script)
	if err != nil || !changed || path != filepath.Join(base, ".cline", "hooks", "PreToolUse") {
		t.Fatalf("install: %s changed=%v err=%v", path, changed, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Cline's extension executes extensionless Unix hooks directly.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0100 == 0 {
		t.Fatalf("hook is not executable: %v", info.Mode())
	}
	if _, changed, err := installClineHook(base, []string{".cline", "hooks"}, "PreToolUse", script); err != nil || changed {
		t.Fatalf("reinstall must be a no-op: changed=%v err=%v", changed, err)
	}
	userHook := filepath.Join(base, "Documents", "Cline", "Hooks", "PreToolUse")
	if err := os.MkdirAll(filepath.Dir(userHook), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userHook, []byte("#!/bin/sh\necho mine\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installClineHook(base, []string{"Documents", "Cline", "Hooks"}, "PreToolUse", script); err == nil {
		t.Fatal("existing user hook was replaced")
	}
	if data, _ := os.ReadFile(userHook); string(data) != "#!/bin/sh\necho mine\n" {
		t.Fatal("existing user hook changed")
	}
}

func TestClineHookInstallRejectsLinkedHookDirectories(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, ".cline")); err != nil {
		t.Skip(err)
	}
	if _, _, err := installClineHook(base, []string{".cline", "hooks"}, "PreToolUse", "#!/bin/sh\n"); err == nil {
		t.Fatal("linked hook directory accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "hooks")); !os.IsNotExist(err) {
		t.Fatal("wrote outside the user's hook directory")
	}
}

func TestAntigravityRegistrationRejectsAmbiguousOrLinkedPaths(t *testing.T) {
	for _, value := range []string{`null`, `{"a":{},"a":{}}`, `{} {}`, `{"a":`} {
		if _, err := namedHooks([]byte(value)); err == nil {
			t.Fatalf("invalid hooks accepted: %s", value)
		}
	}
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".gemini")); err != nil {
		t.Skip(err)
	}
	if _, _, err := installAntigravityRegistration(home, []byte(`{"agent-edict":{"enabled":true}}`)); err == nil {
		t.Fatal("linked config path accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "config")); !os.IsNotExist(err) {
		t.Fatal("wrote outside enrollment directory")
	}
}
