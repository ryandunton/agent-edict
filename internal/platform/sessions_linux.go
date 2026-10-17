//go:build linux

package platform

func (l *LinuxProvider) SessionKeys() ([]string, error) {
	sessions, err := linuxSessions()
	if err != nil {
		return nil, err
	}
	return unixSessionKeys(sessions), nil
}

func (l *LinuxProvider) SessionUsers() ([]SessionUser, error) {
	sessions, err := linuxSessions()
	if err != nil {
		return nil, err
	}
	return unixSessionUsers(sessions)
}

var _ SessionLister = (*LinuxProvider)(nil)
