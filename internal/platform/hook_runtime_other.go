//go:build !windows && !linux && !darwin

package platform

import "fmt"

// Hook registration is not supported on these platforms.
func IsElevated() bool { return true }

func ValidateProtectedPolicyFile(string) error {
	return fmt.Errorf("protected hook files are unsupported on this platform")
}
