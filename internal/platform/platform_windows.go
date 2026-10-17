//go:build windows

package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modwtsapi32               = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQueryUserToken     = modwtsapi32.NewProc("WTSQueryUserToken")
	procWTSEnumerateSessionsW = modwtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory         = modwtsapi32.NewProc("WTSFreeMemory")
)

const (
	WTSActive = 0

	// SDDL:
	// D:P = Protected DACL (inheritance blocked)
	// SY = NT AUTHORITY\SYSTEM, BA = Builtin Administrators, AU = Authenticated Users
	// Administrators ownership is assignable by both elevated administrators and
	// LocalSystem without enabling SeRestorePrivilege to assign another identity.
	sddlBaseDir      = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)"
	sddlVaultDir     = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sddlEnforcedFile = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;AU)"
)

type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

type WindowsProvider struct {
	baseDir  string
	vaultDir string
	targets  []PolicyTarget
}

func NewProvider() PlatformProvider {
	base := `C:\ProgramData\AgentEdict`
	return &WindowsProvider{
		baseDir:  base,
		vaultDir: filepath.Join(base, ".vault"),
		targets:  DefaultPolicyTargets(),
	}
}

func (w *WindowsProvider) OSName() string             { return "windows" }
func (w *WindowsProvider) BaseDir() string            { return w.baseDir }
func (w *WindowsProvider) VaultPath() string          { return w.vaultDir }
func (w *WindowsProvider) GetTargets() []PolicyTarget { return w.targets }

func (w *WindowsProvider) EnsureSecureDirectories() error {
	if err := secureWindowsDirectory(w.baseDir, sddlBaseDir); err != nil {
		return fmt.Errorf("secure base directory: %w", err)
	}
	if err := secureWindowsDirectory(w.vaultDir, sddlVaultDir); err != nil {
		return fmt.Errorf("secure vault directory: %w", err)
	}
	vaultPtr, err := windows.UTF16PtrFromString(w.vaultDir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(vaultPtr)
	if err != nil {
		return fmt.Errorf("read vault attributes: %w", err)
	}
	if err := windows.SetFileAttributes(vaultPtr, attrs|windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_ATTRIBUTE_SYSTEM); err != nil {
		return fmt.Errorf("hide vault directory: %w", err)
	}
	return nil
}

func (w *WindowsProvider) PrepareTargetDirectories(targets []PolicyTarget) ([]string, error) {
	seen := map[string]bool{}
	var created []string
	for _, target := range targets {
		dir := target.WindowsDir
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		_, statErr := os.Lstat(dir)
		if err := secureWindowsDirectory(dir, sddlBaseDir); err != nil {
			return created, fmt.Errorf("secure %s target directory: %w", target.AgentName, err)
		}
		if os.IsNotExist(statErr) {
			created = append(created, dir)
		}
	}
	return created, nil
}

func (w *WindowsProvider) RemoveManagedFile(target PolicyTarget) error {
	path := target.WindowsFile
	if err := validateWindowsPath(path, true); err != nil {
		return fmt.Errorf("unsafe target path: %w", err)
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("target %q is not a regular file", path)
	}
	if err := setReadOnlyAttr(path, false); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("unlock %q: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (w *WindowsProvider) GetActiveConsoleUser() (*UserIdentity, error) {
	sessionID, err := getActiveUserSessionID()
	if err != nil {
		return nil, err
	}

	var userToken windows.Token
	r1, _, e1 := procWTSQueryUserToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&userToken)))
	if r1 == 0 {
		// If caller lacks SeTcbPrivilege (e.g. interactive CLI run by admin), inspect current process token
		if pToken, pErr := windows.OpenCurrentProcessToken(); pErr == nil {
			userToken = pToken
		} else {
			return nil, fmt.Errorf("WTSQueryUserToken failed for session %d: %w", sessionID, e1)
		}
	}
	defer userToken.Close()

	tokenUser, err := userToken.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("GetTokenUser failed: %w", err)
	}
	userSID := tokenUser.User.Sid.String()
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	username := userSID
	if err == nil {
		username = fmt.Sprintf(`%s\%s`, domain, account)
	}

	groups, err := extractTokenGroups(userToken)
	if err != nil {
		return nil, fmt.Errorf("extractTokenGroups failed: %w", err)
	}

	return &UserIdentity{
		Username: username,
		SID:      userSID,
		Groups:   groups,
	}, nil
}

func getActiveUserSessionID() (uint32, error) {
	consoleSession := windows.WTSGetActiveConsoleSessionId()
	if consoleSession != 0xFFFFFFFF && consoleSession != 0 {
		return consoleSession, nil
	}

	var pSessionInfo *wtsSessionInfo
	var count uint32
	r1, _, err := procWTSEnumerateSessionsW.Call(
		0, 0, 1,
		uintptr(unsafe.Pointer(&pSessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("WTSEnumerateSessionsW failed: %w", err)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pSessionInfo)))

	sessions := unsafe.Slice(pSessionInfo, count)
	for _, s := range sessions {
		if s.State == WTSActive && s.SessionID != 0 {
			return s.SessionID, nil
		}
	}
	return 0, fmt.Errorf("no active interactive user session found")
}

func extractTokenGroups(token windows.Token) ([]string, error) {
	var needed uint32
	_ = windows.GetTokenInformation(token, windows.TokenGroups, nil, 0, &needed)
	if needed == 0 {
		return nil, fmt.Errorf("GetTokenInformation returned 0 buffer size")
	}

	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(token, windows.TokenGroups, &buf[0], needed, &needed); err != nil {
		return nil, err
	}

	tg := (*windows.Tokenprimarygroup)(unsafe.Pointer(&buf[0]))
	groupCount := *(*uint32)(unsafe.Pointer(tg))
	firstGroupPtr := unsafe.Add(unsafe.Pointer(&buf[0]), unsafe.Offsetof(windows.Tokengroups{}.Groups))
	groupsSlice := unsafe.Slice((*windows.SIDAndAttributes)(firstGroupPtr), groupCount)

	seen := make(map[string]struct{})
	var result []string

	const seGroupEnabled = 0x00000004
	const seGroupUseForDenyOnly = 0x00000010

	for _, g := range groupsSlice {
		if (g.Attributes&seGroupEnabled) == 0 || (g.Attributes&seGroupUseForDenyOnly) != 0 {
			continue
		}
		sidStr := g.Sid.String()
		if _, ok := seen[sidStr]; !ok {
			seen[sidStr] = struct{}{}
			result = append(result, sidStr)
		}

		if name, dom, _, err := g.Sid.LookupAccount(""); err == nil {
			fullName := name
			if dom != "" {
				fullName = fmt.Sprintf(`%s\%s`, dom, name)
			}
			if _, ok := seen[fullName]; !ok {
				seen[fullName] = struct{}{}
				result = append(result, fullName)
			}
		}
	}
	return result, nil
}

func (w *WindowsProvider) AtomicSwapAndLock(target PolicyTarget, sourcePath string) error {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read source file %s: %w", sourcePath, err)
	}

	destPath := target.WindowsFile
	if err := validateWindowsPath(destPath, true); err != nil {
		return fmt.Errorf("unsafe target path: %w", err)
	}

	// If destination already matches byte-for-byte, verify ACL and attribute
	if existing, err := os.ReadFile(destPath); err == nil && bytes.Equal(existing, content) {
		if err := applySDDL(destPath, sddlEnforcedFile); err != nil {
			return fmt.Errorf("repair target ACL: %w", err)
		}
		return setReadOnlyAttr(destPath, true)
	}

	stage, err := os.CreateTemp(filepath.Dir(destPath), "."+filepath.Base(destPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create staging file: %w", err)
	}
	tmpFile := stage.Name()
	defer os.Remove(tmpFile)
	defer stage.Close()
	if _, err := stage.Write(content); err != nil {
		return fmt.Errorf("write staging file: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync staging file: %w", err)
	}
	if err := stage.Close(); err != nil {
		return fmt.Errorf("close staging file: %w", err)
	}
	if err := applySDDL(tmpFile, sddlEnforcedFile); err != nil {
		return fmt.Errorf("apply SDDL to staging file: %w", err)
	}
	if err := setReadOnlyAttr(destPath, false); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("unlock destination: %w", err)
	}

	srcPtr, _ := windows.UTF16PtrFromString(tmpFile)
	dstPtr, _ := windows.UTF16PtrFromString(destPath)
	if err := windows.MoveFileEx(srcPtr, dstPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		relockErr := setReadOnlyAttr(destPath, true)
		return fmt.Errorf("MoveFileEx atomic swap failed for %s: %w", destPath, errors.Join(err, relockErr))
	}

	if err := applySDDL(destPath, sddlEnforcedFile); err != nil {
		return fmt.Errorf("apply SDDL to target file: %w", err)
	}
	return setReadOnlyAttr(destPath, true)
}

func applySDDL(path string, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL %q: %w", sddl, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("managed SDDL must include an owner: %v", err)
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		nil,
		dacl,
		nil,
	)
}

func trustedWindowsOwner(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" ||
		// TrustedInstaller owns standard Program Files / Windows ancestors.
		sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

// ValidateServiceExecutable prevents direct service registration from turning a
// user-writable executable or ancestor into a LocalSystem execution path.
func ValidateServiceExecutable(path string) error {
	if err := validateWindowsPath(path, false); err != nil {
		return fmt.Errorf("unsafe service executable: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect service executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("service executable must be a regular file")
	}
	return nil
}

// OpenServiceLog validates existing paths before opening any file for writing.
// A rejected pre-existing log is never appended to or silently replaced.
func OpenServiceLog(baseDir string) (*os.File, error) {
	logPath := filepath.Join(baseDir, "service.log")
	if err := validateWindowsPath(logPath, true); err != nil {
		return nil, fmt.Errorf("unsafe service log: %w", err)
	}
	info, err := os.Lstat(logPath)
	flags := os.O_WRONLY | os.O_APPEND
	if errors.Is(err, os.ErrNotExist) {
		// Exclusive creation ensures a racing file is rejected, not adopted.
		flags |= os.O_CREATE | os.O_EXCL
	} else if err != nil {
		return nil, fmt.Errorf("inspect service log: %w", err)
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("service log must be a regular file")
	} else if err := applySDDL(logPath, sddlVaultDir); err != nil {
		// Protect the existing log before parent ACL inheritance is updated.
		return nil, fmt.Errorf("protect existing service log: %w", err)
	}
	if err := secureWindowsDirectory(baseDir, sddlBaseDir); err != nil {
		return nil, fmt.Errorf("secure log directory: %w", err)
	}
	file, err := os.OpenFile(logPath, flags, 0600)
	if err != nil {
		return nil, fmt.Errorf("open service log: %w", err)
	}
	actual, err := file.Stat()
	if err != nil || (info != nil && !os.SameFile(info, actual)) {
		file.Close()
		return nil, fmt.Errorf("service log changed while opening: %v", err)
	}
	// Log contents are private to service administrators, like cached policy.
	if err := applySDDL(logPath, sddlVaultDir); err != nil {
		file.Close()
		return nil, fmt.Errorf("protect service log: %w", err)
	}
	return file, nil
}

// validateWindowsPath rejects junctions/symlinks in every existing component,
// and refuses to adopt paths owned by an ordinary account. Such contents must
// be inspected/removed by an administrator before this service can use them.
func validateWindowsPath(path string, allowMissing bool) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return fmt.Errorf("managed path must be absolute: %q", path)
	}
	var components []string
	for current := path; ; current = filepath.Dir(current) {
		components = append(components, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	for i := len(components) - 1; i >= 0; i-- {
		component := components[i]
		ptr, err := windows.UTF16PtrFromString(component)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(ptr)
		if err != nil {
			if allowMissing && (errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)) {
				continue
			}
			return fmt.Errorf("inspect %q: %w", component, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("refusing reparse point %q", component)
		}
		sd, err := windows.GetNamedSecurityInfo(component, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("inspect owner of %q: %w", component, err)
		}
		if sd == nil {
			return fmt.Errorf("missing security descriptor on %q", component)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil || !trustedWindowsOwner(owner.String()) {
			return fmt.Errorf("refusing path with untrusted owner: %q", component)
		}
		if err := validateWindowsACL(sd, i == 0); err != nil {
			return fmt.Errorf("unsafe ACL on %q: %w", component, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			handle, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
			if err != nil {
				return fmt.Errorf("inspect policy links: %w", err)
			}
			var info windows.ByHandleFileInformation
			err = windows.GetFileInformationByHandle(handle, &info)
			windows.CloseHandle(handle)
			if err != nil {
				return err
			}
			if info.NumberOfLinks != 1 {
				return fmt.Errorf("refusing multiply linked policy file %q", component)
			}
		}
	}
	return nil
}

// Ancestors may allow users to create unrelated children (as ProgramData does),
// but may not let them delete this protected directory or replace its security.
// Adopted objects additionally must not have untrusted write/create grants.
func validateWindowsACL(sd *windows.SECURITY_DESCRIPTOR, strict bool) error {
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("missing or unreadable DACL")
	}
	mask := windows.ACCESS_MASK(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE | 0x40) // FILE_DELETE_CHILD
	if strict {
		mask |= windows.ACCESS_MASK(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported ACE type %d", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&mask != 0 && !trustedWindowsOwner(sid.String()) {
			return fmt.Errorf("write/delete grant to untrusted principal %s", sid)
		}
	}
	return nil
}

// ImmutableFileState cannot establish a Windows policy lock. Windows callers
// must inspect the owner, protected DACL, and read-only attribute separately.
func ImmutableFileState(path string) (bool, error) {
	return false, fmt.Errorf("Windows policy protection requires ownership and DACL inspection")
}

// InspectPolicyLock checks the security boundary as well as the advisory
// read-only attribute. It does not claim that an agent consumed the policy.
func InspectPolicyLock(path string) (bool, string) {
	if err := validateWindowsPath(path, false); err != nil {
		return false, err.Error()
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err.Error()
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return false, fmt.Sprintf("cannot inspect policy attributes: %v", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return false, "policy target is a directory"
	}
	if attrs&windows.FILE_ATTRIBUTE_READONLY == 0 {
		return false, "read-only attribute is not set"
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false, fmt.Sprintf("cannot inspect protected DACL: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, fmt.Sprintf("cannot inspect DACL control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, "DACL inheritance is not protected"
	}
	return true, "privileged owner, protected DACL, no untrusted writes, and read-only attribute"
}

func secureWindowsDirectory(path, sddl string) error {
	if err := validateWindowsPath(path, true); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	// Protect the parent before inspecting children. Never silently turn an
	// untrusted pre-existing cache into a trusted cache by only changing its ACL.
	if err := applySDDL(path, sddl); err != nil {
		return err
	}
	return filepath.WalkDir(path, func(child string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := validateWindowsPath(child, false); err != nil {
			return err
		}
		// Cache descendants must remain private even when already protected by
		// an older, permissive ACL. Target files get their own ACL during swap.
		if sddl == sddlVaultDir {
			return applySDDL(child, sddlVaultDir)
		}
		return nil
	})
}

func setReadOnlyAttr(path string, readOnly bool) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if readOnly {
		if attrs&windows.FILE_ATTRIBUTE_READONLY != 0 {
			return nil
		}
		attrs |= windows.FILE_ATTRIBUTE_READONLY
	} else {
		if attrs&windows.FILE_ATTRIBUTE_READONLY == 0 {
			return nil
		}
		attrs &^= windows.FILE_ATTRIBUTE_READONLY
	}
	return windows.SetFileAttributes(ptr, attrs)
}

// SyncSubsystems provisions only the active user's WSL distributions. WSL's
// Windows owner can still start a distro as root, so this is not a tamperproof
// boundary against that owner; callers must report that scope accurately.
func (w *WindowsProvider) SyncSubsystems(linuxProfilesDir string, profileName string, targets []PolicyTarget) error {
	// Validate every required input before changing the first distribution.
	contents := make([][]byte, len(targets))
	for i, target := range targets {
		source := filepath.Join(linuxProfilesDir, profileName+"."+target.BundleExt)
		content, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("WSL profile preflight for %s: %w", target.AgentName, err)
		}
		contents[i] = content
	}
	sessionID, err := getActiveUserSessionID()
	if err != nil {
		return fmt.Errorf("%w: no active WSL owner session: %w", ErrSubsystemUnavailable, err)
	}
	var token windows.Token
	ok, _, queryErr := procWTSQueryUserToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return wslTokenError(sessionID, queryErr)
	}
	defer token.Close()
	env, err := token.Environ(false)
	if err != nil {
		return fmt.Errorf("load WSL owner's environment: %w", err)
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return fmt.Errorf("locate Windows system directory: %w", err)
	}
	wslPath := filepath.Join(systemDir, "wsl.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := wslCommand(ctx, wslPath, token, env, "--list", "--quiet")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("enumerate WSL distributions for session %d: %w", sessionID, err)
	}
	distros, err := managedWSLDistros(out)
	if err != nil {
		return err
	}
	var failures []error
	for _, distro := range distros {
		for i, target := range targets {
			if err := injectIntoWSLDistro(wslPath, token, env, distro, target.UnixFile, contents[i]); err != nil {
				failures = append(failures, fmt.Errorf("WSL %s / %s: %w", distro, target.AgentName, err))
			}
		}
	}
	return errors.Join(failures...)
}

// An elevated installer cannot obtain another session's WTS token without
// LocalSystem privileges. Defer this case to the service without claiming WSL
// completion; malformed tokens and unrelated OS failures remain errors.
func wslTokenError(sessionID uint32, cause error) error {
	if errors.Is(cause, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(cause, windows.ERROR_NO_TOKEN) {
		return fmt.Errorf("%w: WSL requires the active user's token from the SYSTEM service (session %d): %w", ErrSubsystemUnavailable, sessionID, cause)
	}
	return fmt.Errorf("WSL requires console user's token (session %d): %w", sessionID, cause)
}

func managedWSLDistros(output []byte) ([]string, error) {
	var distros []string
	for _, distro := range parseUTF16Lines(output) {
		if !strings.HasPrefix(distro, "docker-desktop") {
			distros = append(distros, distro)
		}
	}
	if len(distros) == 0 {
		return nil, fmt.Errorf("%w: no managed WSL distributions registered for the active user", ErrSubsystemUnavailable)
	}
	return distros, nil
}

func wslCommand(ctx context.Context, executable string, token windows.Token, env []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, Token: syscall.Token(token)}
	cmd.Env = env
	cmd.Dir = filepath.Dir(executable)
	return cmd
}

func injectIntoWSLDistro(executable string, token windows.Token, env []string, distro, targetUnixFile string, content []byte) error {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	dir := path.Dir(targetUnixFile)
	if !path.IsAbs(targetUnixFile) || dir == "/" {
		return fmt.Errorf("invalid WSL policy target %q", targetUnixFile)
	}
	// A failed write, ownership change, rename, or chattr must reach the caller.
	// Bytes are piped to stdin rather than embedded in a shell command.
	script := "set -eu; umask 022; mkdir -p -- " + quote(dir) +
		"; tmp=$(mktemp " + quote(dir+"/.agent-edict.XXXXXX") + "); trap 'rm -f -- \"$tmp\"' EXIT" +
		"; cat > \"$tmp\"; chown 0:0 \"$tmp\"; chmod 0644 \"$tmp\"" +
		"; if [ -e " + quote(targetUnixFile) + " ]; then chattr -i -- " + quote(targetUnixFile) + "; fi" +
		"; mv -f -- \"$tmp\" " + quote(targetUnixFile) + "; chattr +i -- " + quote(targetUnixFile)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := wslCommand(ctx, executable, token, env, "-d", distro, "-u", "root", "--", "sh", "-c", script)
	cmd.Stdin = bytes.NewReader(content)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write/lock policy: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func parseUTF16Lines(b []byte) []string {
	if len(b)%2 == 0 && len(b) >= 2 && (b[1] == 0x00 || b[0] == 0xFF) {
		u16s := make([]uint16, len(b)/2)
		for i := range u16s {
			u16s[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		b = []byte(string(utf16.Decode(u16s)))
	}
	raw := strings.ReplaceAll(string(b), "\x00", "")
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}
