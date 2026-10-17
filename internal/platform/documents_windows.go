//go:build windows

package platform

import "golang.org/x/sys/windows"

// UserDocumentsDir matches Cline, which asks .NET for MyDocuments: the
// Documents known folder, including folder redirection such as OneDrive.
func UserDocumentsDir(string) (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_Documents, 0)
}
