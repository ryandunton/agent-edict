package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
)

func installHookCommand(args []string, output io.Writer) error {
	if len(args) != 1 || (args[0] != "antigravity" && args[0] != "cline") {
		return fmt.Errorf("usage: edict install-hook <antigravity|cline> (run as the application user)")
	}
	// Never turn a per-user customization path into a privileged write primitive.
	if platform.IsElevated() {
		return fmt.Errorf("run install-hook as the ordinary application user, without sudo or an elevated administrator terminal")
	}
	provider := platform.NewProvider()
	validator, ok := provider.(platform.HookRuntimeValidator)
	if !ok {
		return fmt.Errorf("hook registration is unsupported on this platform")
	}
	if err := validator.ValidateHookRuntime(); err != nil {
		return err
	}
	if args[0] == "cline" {
		return installClineHooks(provider, output)
	}
	var templatePath string
	for _, target := range provider.GetTargets() {
		if target.AgentName == "antigravity" && target.Purpose == "registration-template" {
			templatePath = target.FilePath(provider.OSName())
		}
	}
	if templatePath == "" {
		return fmt.Errorf("missing Antigravity registration target")
	}
	if err := platform.ValidateProtectedPolicyFile(templatePath); err != nil {
		return fmt.Errorf("untrusted machine hook registration: %w", err)
	}
	template, err := readHookRegistration(templatePath)
	if err != nil {
		return fmt.Errorf("install a signed Antigravity machine policy first: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path, changed, err := installAntigravityRegistration(home, template)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintf(output, "Registered AgentEdict in %s\n", path)
	} else {
		fmt.Fprintf(output, "AgentEdict registration already matches %s\n", path)
	}
	fmt.Fprintln(output, "Restart Antigravity and verify a denied tool call. This user can disable the hook; other users must register separately.")
	return nil
}

// installClineHooks writes the PreToolUse hook into the directories each Cline
// client reads: Documents/Cline/Hooks (VS Code extension) and ~/.cline/hooks
// (CLI). Both reference the protected machine policy.
func installClineHooks(provider platform.PlatformProvider, output io.Writer) error {
	osName := provider.OSName()
	var policyPath string
	for _, target := range provider.GetTargets() {
		if target.AgentName == "cline" {
			policyPath = target.FilePath(osName)
		}
	}
	if policyPath == "" {
		return fmt.Errorf("missing Cline policy target")
	}
	if err := platform.ValidateProtectedPolicyFile(policyPath); err != nil {
		return fmt.Errorf("install a signed Cline machine policy first: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	documents, err := platform.UserDocumentsDir(home)
	if err != nil {
		return err
	}
	name, script := compiler.ClineUserHook(osName)
	for _, location := range []struct {
		base  string
		parts []string
	}{{documents, []string{"Cline", "Hooks"}}, {home, []string{".cline", "hooks"}}} {
		path, changed, err := installClineHook(location.base, location.parts, name, script)
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintf(output, "Registered AgentEdict in %s\n", path)
		} else {
			fmt.Fprintf(output, "AgentEdict hook already installed at %s\n", path)
		}
	}
	fmt.Fprintln(output, "In the Cline extension, turn on Enable Hooks, restart Cline, and verify a denied tool call. Cline skips hooks in --yolo mode; this user can remove the hook, and other users must register separately.")
	return nil
}

// installClineHook creates base/parts.../name, refusing symlinked directories
// below base and never replacing a different hook the user already has.
func installClineHook(base string, parts []string, name, script string) (string, bool, error) {
	// Cline creates its Documents directory on demand, e.g. on CLI-only hosts.
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", false, err
	}
	info, err := os.Stat(base)
	if err != nil || !info.IsDir() {
		return "", false, fmt.Errorf("hook base directory unavailable: %s", base)
	}
	dir := base
	for _, part := range parts {
		dir = filepath.Join(dir, part)
		if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", false, err
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", false, fmt.Errorf("hook directory must not be a symlink or non-directory: %s", dir)
		}
	}
	filename := filepath.Join(dir, name)
	if existing, err := readHookRegistration(filename); err == nil {
		if string(existing) == script {
			return filename, false, nil
		}
		return "", false, fmt.Errorf("a different %s hook already exists at %s; move or merge it, then retry", name, filename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	f, err := os.CreateTemp(dir, ".agentedict-hook-*")
	if err != nil {
		return "", false, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.WriteString(script); err != nil {
		return "", false, err
	}
	// Cline's extension executes extensionless Unix hooks directly.
	if err := f.Chmod(0755); err != nil {
		return "", false, err
	}
	if err := f.Sync(); err != nil {
		return "", false, err
	}
	if err := f.Close(); err != nil {
		return "", false, err
	}
	if err := os.Rename(f.Name(), filename); err != nil {
		return "", false, err
	}
	return filename, true, nil
}

func readHookRegistration(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return nil, fmt.Errorf("hook registration must be a regular file within 1 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, fmt.Errorf("hook registration changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if len(data) > 1024*1024 {
		return nil, fmt.Errorf("hook registration exceeds limit")
	}
	return data, err
}

func namedHooks(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, fmt.Errorf("hooks must be a JSON object")
	}
	hooks := map[string]json.RawMessage{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid hook name")
		}
		if _, exists := hooks[name]; exists {
			return nil, fmt.Errorf("duplicate hook name")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		hooks[name] = value
	}
	if last, err := dec.Token(); err != nil || last != json.Delim('}') {
		return nil, fmt.Errorf("invalid hooks object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing hook data")
	}
	return hooks, nil
}

func installAntigravityRegistration(home string, template []byte) (string, bool, error) {
	managed, err := namedHooks(template)
	if err != nil {
		return "", false, err
	}
	entry, ok := managed["agent-edict"]
	if !ok || len(managed) != 1 {
		return "", false, fmt.Errorf("invalid AgentEdict registration template")
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", false, fmt.Errorf("home must be an absolute normalized path")
	}
	dir := home
	for _, part := range []string{"", ".gemini", "config"} {
		if part != "" {
			dir = filepath.Join(dir, part)
			if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return "", false, err
			}
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", false, fmt.Errorf("hook directory must not be a symlink or non-directory: %s", dir)
		}
	}
	filename := filepath.Join(dir, "hooks.json")
	existing, err := readHookRegistration(filename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	hooks := map[string]json.RawMessage{}
	if err == nil {
		hooks, err = namedHooks(existing)
		if err != nil {
			return "", false, fmt.Errorf("preserving invalid existing hooks is unsafe: %w", err)
		}
	}
	if current, exists := hooks["agent-edict"]; exists {
		var a, b bytes.Buffer
		if json.Compact(&a, current) == nil && json.Compact(&b, entry) == nil && bytes.Equal(a.Bytes(), b.Bytes()) {
			return filename, false, nil
		}
	}
	hooks["agent-edict"] = entry
	merged, err := json.MarshalIndent(hooks, "", "  ")
	if err != nil {
		return "", false, err
	}
	if len(existing) > 0 {
		backup, err := os.CreateTemp(dir, "hooks.json.before-agentedict-*")
		if err != nil {
			return "", false, err
		}
		_, writeErr := backup.Write(existing)
		closeErr := backup.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return "", false, err
		}
	}
	f, err := os.CreateTemp(dir, ".hooks-agentedict-*")
	if err != nil {
		return "", false, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(append(merged, '\n')); err != nil {
		return "", false, err
	}
	if err := f.Sync(); err != nil {
		return "", false, err
	}
	if err := f.Close(); err != nil {
		return "", false, err
	}
	if err := os.Rename(f.Name(), filename); err != nil {
		return "", false, err
	}
	return filename, true, nil
}
