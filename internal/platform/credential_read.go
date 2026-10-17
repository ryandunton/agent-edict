package platform

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

// ReadDeployTokenFile loads a secret without placing it in process arguments.
func ReadDeployTokenFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect credential file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 8192 {
		return "", fmt.Errorf("credential must be a regular file no larger than 8192 bytes")
	}
	if err := validateCredentialFile(path, info); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, actual) {
		return "", fmt.Errorf("credential file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return "", err
	}
	if len(data) > 8192 {
		return "", fmt.Errorf("credential file too large")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if token == "" || strings.IndexFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", fmt.Errorf("credential file must contain one nonempty token")
	}
	return token, nil
}
