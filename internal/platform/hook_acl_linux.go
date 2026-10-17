//go:build linux

package platform

// POSIX ACL effective write grants are limited by the group-class mode mask,
// which validateRootControlledPath already rejects when writable.
func validateHookPathACL(string) error { return nil }
