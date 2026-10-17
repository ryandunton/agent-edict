//go:build !darwin && !linux && !windows

package platform

import (
	"fmt"
	"os"
)

func validateCredentialFile(string, os.FileInfo) error {
	return fmt.Errorf("credential protection unsupported on this OS")
}
func InspectPolicyLock(string) (bool, string) { return false, "lock inspection unsupported on this OS" }
