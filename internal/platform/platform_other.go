//go:build !windows && !linux && !darwin

package platform

import (
	"fmt"
	"os"
	"path/filepath"
)

type StubProvider struct {
	baseDir  string
	vaultDir string
	targets  []PolicyTarget
}

func NewProvider() PlatformProvider {
	base := "/etc/agent-edict"
	return &StubProvider{
		baseDir:  base,
		vaultDir: filepath.Join(base, ".vault"),
		targets:  DefaultPolicyTargets(),
	}
}

func (s *StubProvider) OSName() string             { return "linux" }
func (s *StubProvider) BaseDir() string            { return s.baseDir }
func (s *StubProvider) VaultPath() string          { return s.vaultDir }
func (s *StubProvider) GetTargets() []PolicyTarget { return s.targets }

func (s *StubProvider) EnsureSecureDirectories() error {
	if err := os.MkdirAll(s.baseDir, 0755); err != nil {
		return fmt.Errorf("mkdir baseDir: %w", err)
	}
	if err := os.MkdirAll(s.vaultDir, 0700); err != nil {
		return fmt.Errorf("mkdir vaultDir: %w", err)
	}
	return nil
}

func (s *StubProvider) PrepareTargetDirectories(targets []PolicyTarget) ([]string, error) {
	var created []string
	for _, target := range targets {
		dir := target.DirPath(s.OSName())
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return created, err
			}
			created = append(created, dir)
		}
	}
	return created, nil
}

func (s *StubProvider) RemoveManagedFile(target PolicyTarget) error {
	if err := os.Remove(target.FilePath(s.OSName())); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *StubProvider) GetActiveConsoleUser() (*UserIdentity, error) {
	// Stub for non-Windows environments
	return &UserIdentity{
		Username: "stub-user",
		SID:      "1000",
		Groups:   []string{"developers", "wheel"},
	}, nil
}

func (s *StubProvider) AtomicSwapAndLock(target PolicyTarget, sourcePath string) error {
	// Stub for non-Windows environments
	destPath := target.UnixFile
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	return os.WriteFile(destPath, content, 0644)
}

func (s *StubProvider) SyncSubsystems(linuxProfilesDir string, profileName string, targets []PolicyTarget) error {
	return nil
}
