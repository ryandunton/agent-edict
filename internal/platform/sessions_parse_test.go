package platform

import (
	"slices"
	"testing"
)

func TestParseLoginctlSessionIDs(t *testing.T) {
	old := []byte("     2   1000 alice seat0 tty2\n    c3   1001 bob\n\n")
	if got := parseLoginctlSessionIDs(old); !slices.Equal(got, []string{"2", "c3"}) {
		t.Errorf("old format = %v", got)
	}
	newer := []byte("  5 1000 alice seat0 1234 user tty2 no -\n  7 1001 bob   -     5678 user -    no -\n  5 1000 alice seat0 1234 user tty2 no -\n")
	if got := parseLoginctlSessionIDs(newer); !slices.Equal(got, []string{"5", "7"}) {
		t.Errorf("extra columns and duplicate = %v", got)
	}
	if got := parseLoginctlSessionIDs(nil); len(got) != 0 {
		t.Errorf("empty output = %v", got)
	}
}

func TestLinuxSessionCounts(t *testing.T) {
	for _, c := range []struct {
		class, state, user string
		want               bool
	}{
		{"user", "active", "1000", true},
		{"user", "online", "1000", true},
		{"user", "closing", "1000", true},
		{"user", "lingering", "1000", false},
		{"greeter", "active", "1000", false},
		{"manager", "active", "1000", false},
		{"background", "active", "1000", false},
		{"lock-screen", "active", "1000", false},
		{"user", "active", "0", false},
		{"user", "active", "", false},
	} {
		props := map[string]string{"Class": c.class, "State": c.state, "User": c.user, "Name": "x"}
		if got := linuxSessionCounts(props); got != c.want {
			t.Errorf("%+v = %v, want %v", c, got, c.want)
		}
	}
}

func TestParseIDGroups(t *testing.T) {
	got := parseIDGroups([]byte("alice engineers wheel\n"), []byte("1000 2000 10\n"))
	if !slices.Equal(got, []string{"alice", "engineers", "wheel", "1000", "2000", "10"}) {
		t.Errorf("parseIDGroups = %v", got)
	}
	if got := parseIDGroups([]byte("dup dup\n"), []byte("5 5")); !slices.Equal(got, []string{"dup", "5"}) {
		t.Errorf("duplicates = %v", got)
	}
}

func TestWindowsGroupNames(t *testing.T) {
	got := windowsGroupNames("laptop-1", []string{`LAPTOP-1\Contractors`, `CORP\Eng`, `BUILTIN\Users`})
	want := []string{`LAPTOP-1\Contractors`, `.\Contractors`, `CORP\Eng`, `BUILTIN\Users`}
	if !slices.Equal(got, want) {
		t.Errorf("windowsGroupNames = %v, want %v", got, want)
	}
}

func TestWindowsSIDNeedsName(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-5-21-1-2-3-1104": true,
		"S-1-12-1-1-2-3-4":    false, // Entra groups match by entra:/SID, never by name
		"S-1-5-5-0-123456":    false,
		"S-1-5-32-545":        false,
		"S-1-16-8192":         false,
		"S-1-15-3-1024-1-2-3": false,
	} {
		if got := windowsSIDNeedsName(sid); got != want {
			t.Errorf("windowsSIDNeedsName(%s) = %v", sid, got)
		}
	}
}

func TestMacConsoleUserCounts(t *testing.T) {
	for uid, want := range map[uint32]bool{0: false, 248: false, 499: false, 501: true, 502: true} {
		if got := macConsoleUserCounts(uid); got != want {
			t.Errorf("macConsoleUserCounts(%d) = %v, want %v", uid, got, want)
		}
	}
}
