//go:build linux

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
)

type LinuxProvider struct {
	baseDir  string
	vaultDir string
	targets  []PolicyTarget
}

func NewProvider() PlatformProvider {
	return &LinuxProvider{
		baseDir:  "/etc/agent-edict",
		vaultDir: "/var/lib/agent-edict/vault",
		targets:  DefaultPolicyTargets(),
	}
}

func (l *LinuxProvider) OSName() string             { return "linux" }
func (l *LinuxProvider) BaseDir() string            { return l.baseDir }
func (l *LinuxProvider) VaultPath() string          { return l.vaultDir }
func (l *LinuxProvider) GetTargets() []PolicyTarget { return l.targets }
func (l *LinuxProvider) ValidateHookRuntime() error { return validateHookRuntime() }

func (l *LinuxProvider) EnsureSecureDirectories() error {
	if err := secureRootDirectory(l.baseDir, 0755); err != nil {
		return fmt.Errorf("secure base directory: %w", err)
	}
	if err := secureRootDirectory(l.vaultDir, 0700); err != nil {
		return fmt.Errorf("secure vault directory: %w", err)
	}
	return nil
}

func (l *LinuxProvider) PrepareTargetDirectories(targets []PolicyTarget) ([]string, error) {
	return prepareUnixTargetDirectories(targets, "linux")
}

func (l *LinuxProvider) GetActiveConsoleUser() (*UserIdentity, error) {
	username := detectActiveLinuxUser()
	if username == "" {
		return nil, fmt.Errorf("no active console user detected")
	}

	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("lookup user %q: %w", username, err)
	}

	groups, err := resolveLinuxUserGroups(username, u)
	if err != nil {
		return nil, fmt.Errorf("resolve groups for %q: %w", username, err)
	}

	return &UserIdentity{
		Username: username,
		SID:      u.Uid,
		Groups:   groups,
	}, nil
}

func detectActiveLinuxUser() string {
	// 1. Check systemd loginctl for active graphical or local console session
	if out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				sessionID := fields[0]
				// Inspect session properties
				if showOut, err := exec.Command("loginctl", "show-session", sessionID, "-p", "Active", "-p", "State", "-p", "Name").Output(); err == nil {
					props := parseProperties(string(showOut))
					if props["Active"] == "yes" && (props["State"] == "active" || props["State"] == "online") {
						if name := props["Name"]; name != "" && name != "root" && name != "gdm" && name != "lightdm" && name != "sddm" {
							return name
						}
					}
				}
			}
		}
	}

	// 2. Check /dev/console owner
	if fi, err := os.Stat("/dev/console"); err == nil {
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			if u, err := user.LookupId(fmt.Sprint(stat.Uid)); err == nil {
				return u.Username
			}
		}
	}

	// 3. Check SUDO_USER if running under sudo
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		return sudoUser
	}

	// 4. Check who / w output for local seat
	if out, err := exec.Command("who").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				name := fields[0]
				tty := fields[1]
				if (strings.HasPrefix(tty, ":") || strings.HasPrefix(tty, "tty")) && name != "root" {
					return name
				}
			}
		}
	}

	return ""
}

func resolveLinuxUserGroups(username string, u *user.User) ([]string, error) {
	seen := make(map[string]bool)
	var result []string

	add := func(val string) {
		val = strings.TrimSpace(val)
		if val != "" && !seen[val] {
			seen[val] = true
			result = append(result, val)
		}
	}

	// 1. Use 'id -Gn <user>' to query NSS / SSSD / LDAP / FreeIPA
	if out, err := exec.Command("id", "-Gn", username).Output(); err == nil {
		for _, g := range strings.Fields(string(out)) {
			add(g)
		}
	}

	// 2. Query os/user group IDs
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

func (l *LinuxProvider) AtomicSwapAndLock(target PolicyTarget, sourcePath string) error {
	return atomicSwapUnix(target.FilePath("linux"), sourcePath, setLinuxImmutable)
}

func (l *LinuxProvider) SyncSubsystems(linuxProfilesDir string, profileName string, targets []PolicyTarget) error {
	// Native Linux does not require WSL2 bridging
	return nil
}

// ImmutableFileState returns inspection failures instead of treating an
// unsupported filesystem or missing lsattr utility as a successful lock.
func ImmutableFileState(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, fmt.Errorf("inspect immutable policy %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("policy %q is not a regular file", path)
	}
	out, err := exec.Command("lsattr", "-d", path).Output()
	if err != nil {
		return false, fmt.Errorf("inspect immutable flags on %q: %w", path, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 || len(fields[0]) < 8 {
		return false, fmt.Errorf("unexpected lsattr output for %q", path)
	}
	return strings.Contains(fields[0], "i"), nil
}

func isImmutable(path string) bool {
	locked, err := ImmutableFileState(path)
	return err == nil && locked
}

func setLinuxImmutable(path string, locked bool) error {
	flag := "-i"
	if locked {
		flag = "+i"
	}
	if output, err := exec.Command("chattr", flag, path).CombinedOutput(); err != nil {
		return fmt.Errorf("set immutable=%t on %q: %w (%s)", locked, path, err, strings.TrimSpace(string(output)))
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

func (l *LinuxProvider) RemoveManagedFile(target PolicyTarget) error {
	return removeManagedFileUnix(target.FilePath("linux"), setLinuxImmutable)
}
