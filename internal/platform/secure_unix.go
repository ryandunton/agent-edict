//go:build darwin || linux

package platform

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// secureRootDirectory fails when the requested ownership cannot be established.
func secureRootDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("managed directory %q is not a regular directory", path)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return fmt.Errorf("set root ownership on %q: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set permissions on %q: %w", path, err)
	}
	return nil
}

// atomicSwapUnix keeps the old target locked until the replacement is ready.
// Locking failures are returned even when the replacement's bytes are correct.
func atomicSwapUnix(destPath, sourcePath string, setImmutable func(string, bool) error) error {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read source profile %q: %w", sourcePath, err)
	}
	info, statErr := os.Lstat(destPath)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect target %q: %w", destPath, statErr)
	}
	var wasImmutable bool
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("target %q is not a regular file", destPath)
		}
		wasImmutable, err = ImmutableFileState(destPath)
		if err != nil {
			return err
		}
		existing, err := os.ReadFile(destPath)
		if err != nil {
			return fmt.Errorf("read target %q: %w", destPath, err)
		}
		if bytes.Equal(existing, content) {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot inspect ownership of %q", destPath)
			}
			if stat.Uid == 0 && stat.Gid == 0 && info.Mode().Perm() == 0644 && wasImmutable {
				return nil
			}
			if wasImmutable {
				if err := setImmutable(destPath, false); err != nil {
					return err
				}
			}
			if err := os.Chown(destPath, 0, 0); err != nil {
				if wasImmutable {
					err = errors.Join(err, setImmutable(destPath, true))
				}
				return fmt.Errorf("set target ownership: %w", err)
			}
			if err := os.Chmod(destPath, 0644); err != nil {
				if wasImmutable {
					err = errors.Join(err, setImmutable(destPath, true))
				}
				return fmt.Errorf("set target permissions: %w", err)
			}
			return setImmutable(destPath, true)
		}
	}

	stage, err := os.CreateTemp(filepath.Dir(destPath), "."+filepath.Base(destPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create staging file: %w", err)
	}
	stagePath := stage.Name()
	defer os.Remove(stagePath)
	defer stage.Close()
	if err := stage.Chown(0, 0); err != nil {
		return fmt.Errorf("set staging ownership: %w", err)
	}
	if err := stage.Chmod(0644); err != nil {
		return fmt.Errorf("set staging permissions: %w", err)
	}
	if _, err := stage.Write(content); err != nil {
		return fmt.Errorf("write staging file: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync staging file: %w", err)
	}
	if err := stage.Close(); err != nil {
		return fmt.Errorf("close staging file: %w", err)
	}
	if wasImmutable {
		if err := setImmutable(destPath, false); err != nil {
			return err
		}
	}
	if err := os.Rename(stagePath, destPath); err != nil {
		if wasImmutable {
			err = errors.Join(err, setImmutable(destPath, true))
		}
		return fmt.Errorf("atomic rename to %q: %w", destPath, err)
	}
	return setImmutable(destPath, true)
}

// prepareUnixTargetDirectories secures each target directory once and
// reports the ones that did not exist before.
func prepareUnixTargetDirectories(targets []PolicyTarget, osName string) ([]string, error) {
	seen := map[string]bool{}
	var created []string
	for _, target := range targets {
		dir := target.DirPath(osName)
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		_, statErr := os.Lstat(dir)
		if err := secureRootDirectory(dir, 0755); err != nil {
			return created, fmt.Errorf("secure %s target directory: %w", target.AgentName, err)
		}
		if errors.Is(statErr, os.ErrNotExist) {
			created = append(created, dir)
		}
	}
	return created, nil
}

// removeManagedFileUnix deletes a regular target file, clearing its
// immutable flag only when the first attempt is refused.
func removeManagedFileUnix(path string, setImmutable func(string, bool) error) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("target %q is not a regular file", path)
	}
	if err := os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := setImmutable(path, false); err != nil {
		return fmt.Errorf("unlock %q: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
