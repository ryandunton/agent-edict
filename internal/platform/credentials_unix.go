//go:build darwin || linux

package platform

import (
	"fmt"
	"os"
	"syscall"
)

func validateCredentialFile(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || st.Nlink != 1 {
		return fmt.Errorf("credential file must be owned by the service account, private (0600), and have one link")
	}
	return nil
}
func InspectPolicyLock(path string) (bool, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err.Error()
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Gid != 0 || info.Mode().Perm() != 0644 {
		return false, "policy requires a root-owned regular file with mode 0644"
	}
	locked, err := ImmutableFileState(path)
	if err != nil {
		return false, "lock inspection failed: " + err.Error()
	}
	if !locked {
		return false, "immutable flag missing"
	}
	return true, "root-owned mode 0644; immutable flag verified"
}
