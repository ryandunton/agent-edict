//go:build linux || darwin

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func validateHookRuntime() error {
	return validateRootControlledPath("/usr/local/bin/edict", true)
}

func ValidateProtectedPolicyFile(filename string) error {
	return validateRootControlledPath(filename, false)
}

func validateRootControlledPath(filename string, executable bool) error {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return fmt.Errorf("protected path must be absolute and normalized")
	}
	// Reject links and writable/foreign-owned ancestry. The generated hook uses
	// this absolute path, so PATH cannot substitute the evaluator.
	for current := filename; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("protected file not installed securely: %w", err)
		}
		// macOS's root-owned /etc -> private/etc is a standard system alias.
		// Continue checking the actual target ancestry, including its ACLs.
		if runtime.GOOS == "darwin" && current == "/etc" && info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			dest, linkErr := os.Readlink(current)
			if !ok || stat.Uid != 0 || linkErr != nil || (dest != "private/etc" && dest != "/private/etc") {
				return fmt.Errorf("untrusted /etc alias")
			}
			current = "/private/etc"
			info, err = os.Lstat(current)
			if err != nil {
				return err
			}
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("hook evaluator path must be root-owned, non-writable by other users, and contain no symlinks: %s", current)
		}
		if err := validateHookPathACL(current); err != nil {
			return err
		}
		if current == filename && (!info.Mode().IsRegular() || (executable && info.Mode().Perm()&0555 != 0555) || info.Mode().Perm()&0444 != 0444) {
			return fmt.Errorf("protected file has an invalid type or executable mode")
		}
		if current != filename && (!info.IsDir() || info.Mode().Perm()&0111 != 0111) {
			return fmt.Errorf("protected file ancestor must be traversable by application users")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

func IsElevated() bool { return os.Geteuid() == 0 }
