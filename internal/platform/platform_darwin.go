//go:build darwin

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type DarwinProvider struct {
	baseDir  string
	vaultDir string
	targets  []PolicyTarget
}

func NewProvider() PlatformProvider {
	return &DarwinProvider{
		baseDir:  "/etc/agent-edict",
		vaultDir: "/var/lib/agent-edict/vault",
		targets:  DefaultPolicyTargets(),
	}
}

func (d *DarwinProvider) OSName() string             { return "darwin" }
func (d *DarwinProvider) BaseDir() string            { return d.baseDir }
func (d *DarwinProvider) VaultPath() string          { return d.vaultDir }
func (d *DarwinProvider) GetTargets() []PolicyTarget { return d.targets }
func (d *DarwinProvider) ValidateHookRuntime() error { return validateHookRuntime() }

func (d *DarwinProvider) EnsureSecureDirectories() error {
	if err := secureRootDirectory(d.baseDir, 0755); err != nil {
		return fmt.Errorf("secure base directory: %w", err)
	}
	if err := secureRootDirectory(d.vaultDir, 0700); err != nil {
		return fmt.Errorf("secure vault directory: %w", err)
	}
	return nil
}

func (d *DarwinProvider) PrepareTargetDirectories(targets []PolicyTarget) ([]string, error) {
	return prepareUnixTargetDirectories(targets, "darwin")
}

func (d *DarwinProvider) GetActiveConsoleUser() (*UserIdentity, error) {
	username := detectActiveDarwinUser()
	if username == "" {
		return nil, fmt.Errorf("no active console user detected on macOS")
	}

	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("lookup user %q: %w", username, err)
	}

	groups, err := resolveDarwinUserGroups(username, u)
	if err != nil {
		return nil, fmt.Errorf("resolve groups for %q: %w", username, err)
	}

	return &UserIdentity{
		Username: username,
		SID:      u.Uid,
		Groups:   groups,
	}, nil
}

func detectActiveDarwinUser() string {
	// 1. stat -f '%Su' /dev/console (canonical macOS active GUI user)
	if out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output(); err == nil {
		name := strings.TrimSpace(string(out))
		if name != "" && name != "root" && name != "_mbsetupuser" {
			return name
		}
	}

	// 2. scutil SCDynamicStore lookup
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("show State:/Users/ConsoleUser\n")
	if out, err := cmd.Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Name :") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[1])
					if name != "" && name != "loginwindow" && name != "_mbsetupuser" {
						return name
					}
				}
			}
		}
	}

	// 3. Check SUDO_USER if running elevated
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		return sudoUser
	}

	return ""
}

func resolveDarwinUserGroups(username string, u *user.User) ([]string, error) {
	seen := make(map[string]bool)
	var result []string

	add := func(val string) {
		val = strings.TrimSpace(val)
		if val != "" && !seen[val] {
			seen[val] = true
			result = append(result, val)
		}
	}

	// Query DirectoryService groups via 'id -Gn <user>'
	if out, err := exec.Command("id", "-Gn", username).Output(); err == nil {
		for _, g := range strings.Fields(string(out)) {
			add(g)
		}
	}

	// Query os/user group IDs
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			add(gid)
			if g, err := user.LookupGroupId(gid); err == nil {
				add(g.Name)
			}
		}
	}

	return result, nil
}

func (d *DarwinProvider) AtomicSwapAndLock(target PolicyTarget, sourcePath string) error {
	return atomicSwapUnix(target.FilePath("darwin"), sourcePath, setDarwinImmutable)
}

func (d *DarwinProvider) SyncSubsystems(linuxProfilesDir string, profileName string, targets []PolicyTarget) error {
	// macOS does not require WSL2 bridging
	return nil
}

// ImmutableFileState reports the actual filesystem flags. Missing files and
// inspection failures are errors, never evidence that a policy is locked.
func ImmutableFileState(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, fmt.Errorf("inspect immutable flags on %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("policy %q is not a regular file", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("cannot inspect immutable flags on %q", path)
	}
	return stat.Flags&(unix.UF_IMMUTABLE|unix.SF_IMMUTABLE) != 0, nil
}

func hasDarwinFlag(path string) bool {
	locked, err := ImmutableFileState(path)
	return err == nil && locked
}

func setDarwinImmutable(path string, locked bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect flags before setting immutability: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return fmt.Errorf("cannot set immutable flags on nonregular policy %q", path)
	}
	flags := stat.Flags &^ (unix.UF_IMMUTABLE | unix.SF_IMMUTABLE)
	if locked {
		// System immutable may be unavailable; user immutable still prevents a
		// non-root account from changing a root-owned policy file.
		err = syscall.Chflags(path, int(flags|unix.SF_IMMUTABLE))
		if err != nil {
			err = syscall.Chflags(path, int(flags|unix.UF_IMMUTABLE))
		}
	} else {
		err = syscall.Chflags(path, int(flags))
	}
	if err != nil {
		return fmt.Errorf("set immutable=%t on %q: %w", locked, path, err)
	}
	actual, err := ImmutableFileState(path)
	if err != nil {
		return err
	}
	if actual != locked {
		return fmt.Errorf("immutable flag verification failed for %q", path)
	}
	return nil
}

func (d *DarwinProvider) RemoveManagedFile(target PolicyTarget) error {
	return removeManagedFileUnix(target.FilePath("darwin"), setDarwinImmutable)
}
