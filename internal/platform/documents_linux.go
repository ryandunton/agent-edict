//go:build linux

package platform

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// UserDocumentsDir matches Cline: xdg-user-dir DOCUMENTS when available,
// otherwise ~/Documents.
func UserDocumentsDir(home string) (string, error) {
	if tool, err := exec.LookPath("xdg-user-dir"); err == nil {
		if out, err := exec.Command(tool, "DOCUMENTS").Output(); err == nil {
			if dir := strings.TrimSpace(string(out)); filepath.IsAbs(dir) {
				return dir, nil
			}
		}
	}
	return filepath.Join(home, "Documents"), nil
}
