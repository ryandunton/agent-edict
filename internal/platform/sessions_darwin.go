//go:build darwin

package platform

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// darwinSessions returns the console user only; Macs are assumed to be
// single-user. Root owns the console while the login window shows, and a
// system account during Setup Assistant; neither counts as a user.
func darwinSessions() ([]unixSession, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return nil, fmt.Errorf("%w: /dev/console: %v", ErrIncompleteListing, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%w: cannot read /dev/console owner", ErrIncompleteListing)
	}
	if !macConsoleUserCounts(stat.Uid) {
		return nil, nil // login window or a system account such as Setup Assistant
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	u, err := user.LookupId(uid)
	if err != nil {
		return nil, fmt.Errorf("%w: console user %s: %v", ErrIncompleteListing, uid, err)
	}
	return []unixSession{{uid: uid, name: u.Username}}, nil
}

func (d *DarwinProvider) SessionKeys() ([]string, error) {
	sessions, err := darwinSessions()
	if err != nil {
		return nil, err
	}
	return unixSessionKeys(sessions), nil
}

func (d *DarwinProvider) SessionUsers() ([]SessionUser, error) {
	sessions, err := darwinSessions()
	if err != nil {
		return nil, err
	}
	return unixSessionUsers(sessions)
}

var _ SessionLister = (*DarwinProvider)(nil)
