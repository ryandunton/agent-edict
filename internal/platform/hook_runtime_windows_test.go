//go:build windows

package platform

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsHookAccessRequiresOrdinaryUsers(t *testing.T) {
	readExecute := windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE)
	read := windows.ACCESS_MASK(windows.FILE_GENERIC_READ)
	traverse := windows.ACCESS_MASK(windows.FILE_TRAVERSE)
	for _, tc := range []struct {
		name      string
		sddl      string
		required  windows.ACCESS_MASK
		wantError bool
	}{
		{"administrators and SYSTEM only", "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)", readExecute, true},
		{"builtin users file rights", "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;BU)", readExecute, false},
		{"authenticated users generic rights", "O:BAD:P(A;;GRGX;;;AU)", readExecute, false},
		{"everyone generic rights", "O:BAD:P(A;;GRGX;;;WD)", readExecute, false},
		{"split broadly applicable grants", "O:BAD:P(A;;FR;;;BU)(A;;FX;;;AU)", readExecute, false},
		{"unrelated individual account", "O:BAD:P(A;;FRFX;;;S-1-5-21-1-2-3-1001)", readExecute, true},
		{"read without execution", "O:BAD:P(A;;FR;;;BU)", readExecute, true},
		{"execution without read", "O:BAD:P(A;;FX;;;BU)", readExecute, true},
		{"data and execution without generic read metadata", "O:BAD:P(A;;0x21;;;BU)", readExecute, true},
		{"inherit-only is not current access", "O:BAD:P(A;OIIO;FRFX;;;BU)", readExecute, true},
		{"inherited current access counts", "O:BAD:P(A;ID;FRFX;;;BU)", readExecute, false},
		{"builtin users denied execution", "O:BAD:P(D;;FX;;;BU)(A;;FRFX;;;BU)", readExecute, true},
		{"named user deny may affect an application user", "O:BAD:P(D;;FX;;;S-1-5-21-1-2-3-1001)(A;;FRFX;;;BU)", readExecute, true},
		{"deny-only administrator group can affect filtered tokens", "O:BAD:P(D;;FX;;;BA)(A;;FRFX;;;BU)", readExecute, true},
		{"write denial does not deny read or execute", "O:BAD:P(D;;0x2;;;BU)(A;;FRFX;;;BU)", readExecute, false},
		{"inherit-only denial does not affect current file", "O:BAD:P(D;OIIO;FX;;;BU)(A;;FRFX;;;BU)", readExecute, false},
		{"policy file needs read but not execute", "O:BAD:P(A;;FR;;;BU)", read, false},
		{"policy execute-only does not grant read", "O:BAD:P(A;;FX;;;BU)", read, true},
		{"directory traversal is sufficient", "O:BAD:P(A;;0x20;;;BU)", traverse, false},
		{"directory listing is not traversal", "O:BAD:P(A;;0x1;;;BU)", traverse, true},
		{"generic execute grants traversal", "O:BAD:P(A;;GX;;;AU)", traverse, false},
		{"directory traversal denial", "O:BAD:P(D;;0x20;;;WD)(A;;GX;;;BU)", traverse, true},
		{"empty DACL", "O:BAD:P", readExecute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateOrdinaryUserWindowsAccess(sd, tc.required)
			if (err != nil) != tc.wantError {
				t.Fatalf("access result %v, expected error=%v", err, tc.wantError)
			}
		})
	}
	if err := validateOrdinaryUserWindowsAccess(nil, readExecute); err == nil {
		t.Fatal("nil descriptor accepted")
	}
}

func TestWindowsHookReadAccessDoesNotReplaceTrustValidation(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrdinaryUserWindowsAccess(sd, windows.ACCESS_MASK(windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE)); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsACL(sd, true); err == nil {
		t.Fatal("world-writable executable must still fail the separate trust check")
	}
}
