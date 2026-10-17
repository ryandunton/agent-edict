//go:build darwin

package platform

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

func TestHookPathACLRejectsHiddenWriteGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook")
	if err := os.WriteFile(path, []byte("test fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateHookPathACL(path); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/chmod", "+a", "user:"+u.Username+" allow write", path).CombinedOutput(); err != nil {
		t.Fatalf("set disposable ACL: %s: %v", out, err)
	}
	if err := validateHookPathACL(path); err == nil {
		t.Fatal("ACL-bearing evaluator accepted based on mode bits")
	}
}
