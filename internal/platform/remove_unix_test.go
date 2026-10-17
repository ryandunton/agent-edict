//go:build darwin || linux

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveManagedFileRemovesRegularFilesOnly(t *testing.T) {
	remover, ok := NewProvider().(TargetRemover)
	if !ok {
		t.Fatal("provider cannot remove managed files")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "managed-settings.json")
	if err := os.WriteFile(file, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	target := PolicyTarget{UnixFile: file, DarwinFile: file}
	if err := remover.RemoveManagedFile(target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Fatal("managed file still present")
	}
	if err := remover.RemoveManagedFile(target); err != nil {
		t.Fatalf("an already-missing file is not an error: %v", err)
	}
	other := filepath.Join(dir, "other")
	os.WriteFile(other, []byte("keep"), 0644)
	if err := os.Symlink(other, file); err != nil {
		t.Fatal(err)
	}
	if err := remover.RemoveManagedFile(target); err == nil {
		t.Fatal("a symlink at the target path was removed")
	}
	if data, _ := os.ReadFile(other); string(data) != "keep" {
		t.Fatal("symlink destination was touched")
	}
}

func TestIsElevatedMatchesEffectiveUID(t *testing.T) {
	if IsElevated() != (os.Geteuid() == 0) {
		t.Fatal("IsElevated disagrees with the effective UID")
	}
}
