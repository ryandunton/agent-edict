//go:build windows

package platform

import (
	"errors"
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

const wtsListen = 6

// windowsSessionTokens calls visit with the user token of every session that
// has a logged-on user, active or disconnected. It never falls back to the
// calling process's token, and it closes every handle it opens.
func windowsSessionTokens(visit func(windows.Token) error) error {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return fmt.Errorf("%w: WTSEnumerateSessions: %v", ErrIncompleteListing, err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, session := range unsafe.Slice(sessions, count) {
		if session.SessionID == 0 || session.State == wtsListen {
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(session.SessionID, &token); err != nil {
			if errors.Is(err, windows.ERROR_NO_TOKEN) {
				continue // no user is logged on to this session
			}
			return fmt.Errorf("%w: WTSQueryUserToken(%d): %v", ErrIncompleteListing, session.SessionID, err)
		}
		err := visit(token)
		token.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func tokenUserSID(token windows.Token) (string, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("%w: GetTokenUser: %v", ErrIncompleteListing, err)
	}
	return tokenUser.User.Sid.String(), nil
}

func (w *WindowsProvider) SessionKeys() ([]string, error) {
	seen := map[string]bool{}
	var keys []string
	err := windowsSessionTokens(func(token windows.Token) error {
		sid, err := tokenUserSID(token)
		if err != nil {
			return err
		}
		if !seen[sid] {
			seen[sid] = true
			keys = append(keys, sid)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	return keys, nil
}

func (w *WindowsProvider) SessionUsers() ([]SessionUser, error) {
	computer, err := windows.ComputerName()
	if err != nil {
		return nil, fmt.Errorf("%w: computer name: %v", ErrIncompleteListing, err)
	}
	seen := map[string]bool{}
	var users []SessionUser
	err = windowsSessionTokens(func(token windows.Token) error {
		sid, err := tokenUserSID(token)
		if err != nil || seen[sid] {
			return err
		}
		seen[sid] = true
		user := SessionUser{Key: sid, Name: sid}
		if tokenUser, err := token.GetTokenUser(); err == nil {
			if account, domain, _, err := tokenUser.User.Sid.LookupAccount(""); err == nil {
				user.Name = domain + `\` + account
			}
		}
		groups, err := token.GetTokenGroups()
		if err != nil {
			return fmt.Errorf("%w: GetTokenGroups: %v", ErrIncompleteListing, err)
		}
		var names []string
		for _, group := range groups.AllGroups() {
			if group.Attributes&windows.SE_GROUP_ENABLED == 0 || group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
				continue
			}
			groupSID := group.Sid.String()
			user.Groups = append(user.Groups, groupSID)
			account, domain, _, err := group.Sid.LookupAccount("")
			switch {
			case err == nil && domain != "":
				names = append(names, domain+`\`+account)
			case err == nil:
				names = append(names, account)
			case windowsSIDNeedsName(groupSID):
				user.Untranslated = append(user.Untranslated, groupSID)
			}
		}
		user.Groups = append(user.Groups, windowsGroupNames(computer, names)...)
		users = append(users, user)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

var _ SessionLister = (*WindowsProvider)(nil)
