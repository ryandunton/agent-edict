//go:build darwin || linux

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"time"
)

// commandTimeout bounds each session or group lookup, so a hung directory
// service fails the listing instead of holding the service's lock.
var commandTimeout = 10 * time.Second

// runCommand runs a session or group lookup; tests replace it.
var runCommand = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second // don't wait on pipes held by a killed command's children
	return cmd.Output()
}

type unixSession struct {
	uid, name string
}

// unixSessionUsers resolves the groups of each session's user. Any failed
// lookup makes the whole listing incomplete.
func unixSessionUsers(sessions []unixSession) ([]SessionUser, error) {
	var users []SessionUser
	for _, session := range sessions {
		names, err := runCommand("id", "-Gn", session.name)
		if err != nil {
			return nil, fmt.Errorf("%w: groups of %s: %v", ErrIncompleteListing, session.name, err)
		}
		ids, err := runCommand("id", "-G", session.name)
		if err != nil {
			return nil, fmt.Errorf("%w: group IDs of %s: %v", ErrIncompleteListing, session.name, err)
		}
		users = append(users, SessionUser{Key: session.uid, Name: session.name, Groups: parseIDGroups(names, ids)})
	}
	return users, nil
}

func unixSessionKeys(sessions []unixSession) []string {
	keys := make([]string, 0, len(sessions))
	for _, session := range sessions {
		keys = append(keys, session.uid)
	}
	sort.Strings(keys)
	return keys
}

// linuxSessions lists the human logind sessions, one per UID. A machine
// without logind never produces a complete listing.
func linuxSessions() ([]unixSession, error) {
	out, err := runCommand("loginctl", "list-sessions", "--no-legend", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("%w: loginctl list-sessions: %v", ErrIncompleteListing, err)
	}
	var sessions []unixSession
	seen := map[string]bool{}
	for _, id := range parseLoginctlSessionIDs(out) {
		raw, err := runCommand("loginctl", "show-session", id, "-p", "Name", "-p", "User", "-p", "Class", "-p", "State")
		if err != nil {
			return nil, fmt.Errorf("%w: loginctl show-session %s: %v", ErrIncompleteListing, id, err)
		}
		props := parseProperties(string(raw))
		if !linuxSessionCounts(props) || seen[props["User"]] {
			continue
		}
		if props["Name"] == "" {
			return nil, fmt.Errorf("%w: session %s has no user name", ErrIncompleteListing, id)
		}
		seen[props["User"]] = true
		sessions = append(sessions, unixSession{uid: props["User"], name: props["Name"]})
	}
	return sessions, nil
}
