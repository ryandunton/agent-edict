//go:build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (w *WindowsProvider) ValidateHookRuntime() error {
	const executable = `C:\Program Files\AgentEdict\edict.exe`
	if err := ValidateServiceExecutable(executable); err != nil {
		return err
	}
	return validateWindowsApplicationAccess(executable, windows.ACCESS_MASK(windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE))
}

func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func ValidateProtectedPolicyFile(filename string) error {
	if err := validateWindowsPath(filename, false); err != nil {
		return err
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("protected hook policy must be a regular file")
	}
	return validateWindowsApplicationAccess(filename, windows.ACCESS_MASK(windows.FILE_GENERIC_READ))
}

// validateWindowsApplicationAccess is called only after trusted ownership,
// non-writable ancestry, and reparse-point checks. Read access is not trust.
func validateWindowsApplicationAccess(filename string, fileAccess windows.ACCESS_MASK) error {
	for current := filename; ; current = filepath.Dir(current) {
		required := windows.ACCESS_MASK(windows.FILE_TRAVERSE)
		if current == filename {
			required = fileAccess
		}
		sd, err := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("inspect application-user access to %q: %w", current, err)
		}
		if err := validateOrdinaryUserWindowsAccess(sd, required); err != nil {
			return fmt.Errorf("application users cannot reliably access %q: %w", current, err)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

// validateOrdinaryUserWindowsAccess conservatively establishes broad access for
// application users instead of testing the daemon's SYSTEM/administrator token.
// It does not emulate arbitrary token membership: any applicable deny touching
// a required right is rejected because it could exclude a user or a deny-only
// group in a filtered token. Custom-group-only access is deliberately rejected.
func validateOrdinaryUserWindowsAccess(sd *windows.SECURITY_DESCRIPTOR, required windows.ACCESS_MASK) error {
	if sd == nil || required == 0 {
		return fmt.Errorf("missing security descriptor or required access")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("missing or unreadable DACL")
	}
	var granted windows.ACCESS_MASK
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return fmt.Errorf("unsupported access ACE type %d", ace.Header.AceType)
		}
		mask := expandWindowsFileAccess(ace.Mask)
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			if mask&required != 0 {
				return fmt.Errorf("explicit denial affects required application-user access")
			}
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		switch sid {
		case "S-1-1-0", "S-1-5-11", "S-1-5-32-545": // Everyone, Authenticated Users, BUILTIN\Users.
			granted |= mask
		}
	}
	if granted&required != required {
		return fmt.Errorf("Everyone, Authenticated Users, or Users must grant all required read/execute/traversal rights")
	}
	return nil
}

func expandWindowsFileAccess(mask windows.ACCESS_MASK) windows.ACCESS_MASK {
	if mask&windows.GENERIC_ALL != 0 {
		mask |= windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE
	}
	if mask&windows.GENERIC_READ != 0 {
		mask |= windows.FILE_GENERIC_READ
	}
	if mask&windows.GENERIC_WRITE != 0 {
		mask |= windows.FILE_GENERIC_WRITE
	}
	if mask&windows.GENERIC_EXECUTE != 0 {
		mask |= windows.FILE_GENERIC_EXECUTE
	}
	return mask
}
