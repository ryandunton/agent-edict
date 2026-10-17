//go:build darwin || linux

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialFileProtection(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		mode          os.FileMode
		valid         bool
	}{{"private", "fake-package-token\n", 0600, true}, {"readable", "fake-package-token", 0644, false}, {"empty", "\n", 0600, false}, {"multiline", "fake\ninjected", 0600, false}, {"oversize", strings.Repeat("x", 8193), 0600, false}} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(p, []byte(tc.content), tc.mode); err != nil {
				t.Fatal(err)
			}
			value, err := ReadDeployTokenFile(p)
			if tc.valid {
				if err != nil || value != "fake-package-token" {
					t.Fatalf("value=%q err=%v", value, err)
				}
			} else if err == nil {
				t.Fatal("unsafe credential file accepted")
			}
		})
	}
}
func TestCredentialSymlinkRejected(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "token")
	os.WriteFile(p, []byte("fake"), 0600)
	link := filepath.Join(d, "link")
	os.Symlink(p, link)
	if _, err := ReadDeployTokenFile(link); err == nil {
		t.Fatal("credential symlink accepted")
	}
}
