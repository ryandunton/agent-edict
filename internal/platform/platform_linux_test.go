//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxMissingFileIsNotImmutable(t *testing.T) {
	if isImmutable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("failed lsattr must not be reported as immutable")
	}
}

func TestLinuxLockReportsOwnershipFailure(t *testing.T) {
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
	provider := &LinuxProvider{}
	if err := provider.AtomicSwapAndLock(PolicyTarget{UnixFile: destination}, source); err == nil {
		t.Fatal("unprivileged root ownership failure reported as successful enforcement")
	}
}
