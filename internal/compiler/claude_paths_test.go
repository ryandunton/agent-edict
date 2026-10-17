package compiler

import (
	"strings"
	"testing"
)

func TestClaudePathPattern(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/shadow":                  "//etc/shadow",
		"C:/Windows/System32/config":   "//c/Windows/System32/config",
		`C:\Windows\System32\config`:   "//c/Windows/System32/config",
		"d:/data":                      "//d/data",
		"~/.ssh":                       "~/.ssh",
		"relative/dir":                 "relative/dir",
		"~/AppData/Roaming/GitHub CLI": "~/AppData/Roaming/GitHub CLI",
	} {
		if got := claudePathPattern(in); got != want {
			t.Errorf("claudePathPattern(%q) = %q, want %q", in, got, want)
		}
	}
}

// Claude anchors Read(/x) at the settings file, not the filesystem root, so
// absolute deny paths must use the // prefix to protect anything.
func TestClaudeDenyReadUsesAbsoluteAnchors(t *testing.T) {
	p := &UnifiedPolicy{Version: 1, Name: "anchors", Filesystem: FSConfig{DenyRead: PathGroup{
		Common:  []string{"~/.ssh"},
		Unix:    []string{"/etc/shadow"},
		Windows: []string{"C:/Windows/System32/config"},
	}}}
	linux, err := compileClaude(p, false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"Read(~/.ssh/**)"`, `"Read(//etc/shadow/**)"`} {
		if !strings.Contains(linux, want) {
			t.Errorf("linux Claude settings missing %s:\n%s", want, linux)
		}
	}
	if strings.Contains(linux, `"Read(/etc/shadow/**)"`) {
		t.Errorf("linux Claude settings still use a settings-relative /etc/shadow rule")
	}
	windows, err := compileClaude(p, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(windows, `"Read(//c/Windows/System32/config/**)"`) {
		t.Errorf("windows Claude settings missing drive-anchored rule:\n%s", windows)
	}
}
