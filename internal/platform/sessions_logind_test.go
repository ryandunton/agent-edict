//go:build darwin || linux

package platform

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func stubCommands(t *testing.T, outputs map[string]string) {
	t.Helper()
	previous := runCommand
	runCommand = func(name string, args ...string) ([]byte, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		out, ok := outputs[key]
		if !ok {
			return nil, fmt.Errorf("unexpected command %q", key)
		}
		return []byte(out), nil
	}
	t.Cleanup(func() { runCommand = previous })
}

func TestLinuxSessionUsersWithStubbedCommands(t *testing.T) {
	show := func(id string) string {
		return "loginctl show-session " + id + " -p Name -p User -p Class -p State"
	}
	commands := map[string]string{
		"loginctl list-sessions --no-legend --no-pager": "1 1000 alice seat0 tty2\n2 1000 alice - pts/0\n3 0 root - pts/1\n4 120 gdm seat0 tty1\n",
		show("1"):      "Name=alice\nUser=1000\nClass=user\nState=active\n",
		show("2"):      "Name=alice\nUser=1000\nClass=user\nState=online\n",
		show("3"):      "Name=root\nUser=0\nClass=user\nState=online\n",
		show("4"):      "Name=gdm\nUser=120\nClass=greeter\nState=online\n",
		"id -Gn alice": "alice engineers\n",
		"id -G alice":  "1000 2000\n",
	}
	stubCommands(t, commands)
	sessions, err := linuxSessions()
	if keys := unixSessionKeys(sessions); err != nil || !slices.Equal(keys, []string{"1000"}) {
		t.Fatalf("session keys = %v, %v", keys, err)
	}
	users, err := unixSessionUsers(sessions)
	if err != nil || len(users) != 1 || users[0].Key != "1000" || users[0].Name != "alice" || !slices.Contains(users[0].Groups, "engineers") {
		t.Fatalf("SessionUsers = %+v, %v", users, err)
	}

	delete(commands, "id -G alice")
	if _, err := unixSessionUsers(sessions); !errors.Is(err, ErrIncompleteListing) {
		t.Fatalf("failed group lookup must be an incomplete listing, got %v", err)
	}
	stubCommands(t, map[string]string{})
	if _, err := linuxSessions(); !errors.Is(err, ErrIncompleteListing) {
		t.Fatalf("missing loginctl must be an incomplete listing, got %v", err)
	}
}
