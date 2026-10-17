//go:build darwin

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDarwinFlagDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy")
	if hasDarwinFlag(path) {
		t.Fatal("missing policy must not be reported immutable")
	}
	if err := os.WriteFile(path, []byte("policy"), 0600); err != nil {
		t.Fatal(err)
	}
	if hasDarwinFlag(path) {
		t.Fatal("ordinary file reported immutable")
	}
	if output, err := exec.Command("/usr/bin/chflags", "uchg", path).CombinedOutput(); err != nil {
		t.Fatalf("flag disposable test file: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if output, err := exec.Command("/usr/bin/chflags", "nouchg", path).CombinedOutput(); err != nil {
			t.Errorf("unflag disposable test file: %v: %s", err, output)
		}
	})
	if !hasDarwinFlag(path) {
		t.Fatal("uchg policy must be reported immutable")
	}
}

func TestDarwinLockReportsOwnershipFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged ownership failure")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "policy")
	for _, path := range []string{source, destination} {
		if err := os.WriteFile(path, []byte("same policy"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	provider := &DarwinProvider{}
	if err := provider.AtomicSwapAndLock(PolicyTarget{DarwinFile: destination}, source); err == nil {
		// The old implementation sets uchg even after chown fails. Always clean up.
		_ = exec.Command("/usr/bin/chflags", "nouchg", destination).Run()
		t.Fatal("unprivileged root ownership failure reported as successful enforcement")
	}
}
