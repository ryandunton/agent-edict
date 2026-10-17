//go:build darwin

package platform

import (
	"bytes"
	"fmt"
	"os/exec"
)

func validateHookPathACL(filename string) error {
	// Match the installer's conservative ACL policy. Mode bits alone do not
	// expose macOS ACL grants that could replace a root-owned file.
	cmd := exec.Command("/bin/ls", "-lde", filename)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("inspect protected path ACL: %w", err)
	}
	if bytes.Contains(bytes.TrimSpace(out), []byte("\n")) {
		return fmt.Errorf("protected path has an ACL requiring administrator review: %s", filename)
	}
	return nil
}
