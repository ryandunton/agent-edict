package platform

import (
	"strings"
)

// parseLoginctlSessionIDs returns the first column of each loginctl
// list-sessions line, once each, tolerating extra columns.
func parseLoginctlSessionIDs(out []byte) []string {
	var ids []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if !containsString(ids, fields[0]) {
			ids = append(ids, fields[0])
		}
	}
	return ids
}

// linuxSessionCounts reports whether a logind session belongs to a human who
// can run programs: a user-class session that still has processes. Greeter,
// lock-screen, manager and background sessions and root are excluded.
func linuxSessionCounts(props map[string]string) bool {
	if props["Class"] != "user" || props["User"] == "" || props["User"] == "0" {
		return false
	}
	switch props["State"] {
	case "active", "online", "closing":
		return true
	}
	return false
}

// parseIDGroups combines `id -Gn` names and `id -G` numeric IDs, once each.
func parseIDGroups(names, ids []byte) []string {
	var groups []string
	for _, field := range append(strings.Fields(string(names)), strings.Fields(string(ids))...) {
		if !containsString(groups, field) {
			groups = append(groups, field)
		}
	}
	return groups
}

// windowsGroupNames adds a machine-independent .\Name alias for every local
// group, whose domain is the computer's own name.
func windowsGroupNames(computer string, names []string) []string {
	var out []string
	for _, name := range names {
		out = append(out, name)
		if domain, group, found := strings.Cut(name, `\`); found && strings.EqualFold(domain, computer) {
			out = append(out, `.\`+group)
		}
	}
	return out
}

// windowsSIDNeedsName reports whether a failed name lookup for a group SID
// could hide a DOMAIN\Name rule match. Only domain and machine SIDs have
// such names; Entra ID groups (S-1-12-1-) are matched by entra: or SID rules
// and do not translate on the device, so they never count.
func windowsSIDNeedsName(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-")
}

// macConsoleUserCounts reports whether the console owner is a human account.
// macOS gives people UIDs from 500 up; root (login window) and system
// accounts such as _mbsetupuser (Setup Assistant) are below that.
func macConsoleUserCounts(uid uint32) bool {
	return uid >= 500
}

// parseProperties reads loginctl's key=value property output.
func parseProperties(raw string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
