//go:build !windows && !linux

package platform

import "path/filepath"

// UserDocumentsDir matches Cline's default: ~/Documents.
func UserDocumentsDir(home string) (string, error) {
	return filepath.Join(home, "Documents"), nil
}
