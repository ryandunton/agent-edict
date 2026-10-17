//go:build windows

package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestServiceExecutableMustBeTrustedRegularAbsoluteFile(t *testing.T) {
	for _, path := range []string{"edict.exe", filepath.Join(t.TempDir(), "missing.exe"), t.TempDir()} {
		if err := ValidateServiceExecutable(path); err == nil {
			t.Errorf("unsafe executable accepted: %q", path)
		}
	}
}

func TestServiceLogRejectsHardlinkedFileBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, filepath.Join(dir, "service.log")); err != nil {
		t.Fatal(err)
	}
	file, err := OpenServiceLog(dir)
	if err == nil {
		file.Close()
		t.Fatal("hardlinked service log was opened")
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("service log validation modified existing data: %q %v", data, err)
	}
}

func TestWSLPreflightDoesNotSkipMissingManagedProfile(t *testing.T) {
	provider := &WindowsProvider{}
	err := provider.SyncSubsystems(filepath.Join(t.TempDir(), "missing"), "machine", []PolicyTarget{{AgentName: "codex", BundleExt: "codex.toml"}})
	if err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("missing managed source must fail before WSL launch: %v", err)
	}
	if errors.Is(err, ErrSubsystemUnavailable) {
		t.Fatal("missing signed profile must not be downgraded to availability deferral")
	}
}

func TestWSLTokenErrorDefersOnlyUnavailableIdentity(t *testing.T) {
	for _, tc := range []struct {
		cause    error
		deferred bool
	}{
		{windows.ERROR_PRIVILEGE_NOT_HELD, true},
		{windows.ERROR_NO_TOKEN, true},
		{windows.ERROR_ACCESS_DENIED, false},
		{windows.ERROR_INVALID_HANDLE, false},
	} {
		err := wslTokenError(4, tc.cause)
		if errors.Is(err, ErrSubsystemUnavailable) != tc.deferred {
			t.Errorf("unexpected availability classification for %v: %v", tc.cause, err)
		}
		if !errors.Is(err, tc.cause) {
			t.Errorf("original Windows cause not preserved: %v", err)
		}
	}
}

func TestWSLWithoutManagedDistributionsIsDeferred(t *testing.T) {
	for _, output := range []string{"", "docker-desktop\r\ndocker-desktop-data\r\n"} {
		_, err := managedWSLDistros([]byte(output))
		if !errors.Is(err, ErrSubsystemUnavailable) {
			t.Errorf("empty managed distro set reported complete: %v", err)
		}
	}
	distros, err := managedWSLDistros([]byte("Ubuntu\r\ndocker-desktop\r\n"))
	if err != nil || !reflect.DeepEqual(distros, []string{"Ubuntu"}) {
		t.Fatalf("ordinary user distro should be synchronized: %v %v", distros, err)
	}
}

func TestMissingWindowsPolicyIsNotLocked(t *testing.T) {
	locked, detail := InspectPolicyLock(filepath.Join(t.TempDir(), "missing"))
	if locked || detail == "" {
		t.Fatalf("missing policy must provide an unlocked diagnostic: locked=%v detail=%q", locked, detail)
	}
}

func TestWSLCommandUsesRequestedUserIdentity(t *testing.T) {
	token := windows.Token(123)
	env := []string{`USERPROFILE=C:\Users\Operator`, `SystemRoot=C:\Windows`}
	cmd := wslCommand(context.Background(), `C:\Windows\System32\wsl.exe`, token, env, "--list", "--quiet")
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Token != syscall.Token(token) {
		t.Fatal("WSL command must use console user's primary token")
	}
	if !reflect.DeepEqual(cmd.Env, env) {
		t.Fatalf("WSL command inherited service environment: %q", cmd.Env)
	}
	if cmd.Path != `C:\Windows\System32\wsl.exe` {
		t.Fatalf("WSL command resolved through PATH: %q", cmd.Path)
	}
}

func TestUnprivilegedOwnersAreNotTrusted(t *testing.T) {
	for _, sid := range []string{"S-1-5-21-1-2-3-1001", "S-1-5-32-545", ""} {
		if trustedWindowsOwner(sid) {
			t.Errorf("unprivileged owner accepted: %q", sid)
		}
	}
	for _, sid := range []string{"S-1-5-18", "S-1-5-32-544"} {
		if !trustedWindowsOwner(sid) {
			t.Errorf("privileged owner rejected: %q", sid)
		}
	}
}

func TestWindowsRejectsUntrustedWriteACLs(t *testing.T) {
	cases := []struct {
		name      string
		sddl      string
		strict    bool
		wantError bool
	}{
		{"managed file", sddlEnforcedFile, true, false},
		{"owner cannot sanitize world write", "O:SYD:P(A;;FA;;;SY)(A;;FW;;;AU)", true, true},
		{"unsafe parent deletion", "O:SYD:P(A;;FA;;;SY)(A;;0x40;;;AU)", false, true},
		{"parent allows child creation only", "O:SYD:P(A;;FA;;;SY)(A;;0x4;;;AU)", false, false},
		{"managed directory permits child creation", "O:SYD:P(A;;FA;;;SY)(A;;0x4;;;AU)", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateWindowsACL(sd, tc.strict)
			if (err != nil) != tc.wantError {
				t.Fatalf("ACL acceptance mismatch: %v", err)
			}
		})
	}
}

func TestManagedSDDLIncludesAdministratorsOwner(t *testing.T) {
	for name, sddl := range map[string]string{"base": sddlBaseDir, "vault": sddlVaultDir, "target": sddlEnforcedFile} {
		t.Run(name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			owner, _, err := sd.Owner()
			if err != nil || owner == nil || owner.String() != "S-1-5-32-544" {
				t.Fatalf("managed object must assign Administrators ownership usable by elevated admins and SYSTEM: owner=%v err=%v", owner, err)
			}
		})
	}
}

func TestParseWSLDistributionNames(t *testing.T) {
	got := parseUTF16Lines([]byte{0xff, 0xfe, 'U', 0, 'b', 0, 'u', 0, 'n', 0, 't', 0, 'u', 0, '\r', 0, '\n', 0})
	if len(got) != 1 || got[0] != "Ubuntu" {
		t.Fatalf("UTF-16 BOM must not become part of distro name: %q", got)
	}
}
