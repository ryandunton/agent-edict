//go:build linux || darwin

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedHookTemplateRejectsUserControlledStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "antigravity-hooks.json")
	if err := os.WriteFile(path, []byte(`{"agent-edict":{"enabled":true}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProtectedPolicyFile(path); err == nil {
		t.Fatal("untrusted registration template accepted")
	}
}
