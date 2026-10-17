package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/platform"
)

type targetsProvider struct {
	statusProvider
	os string
}

func (p targetsProvider) OSName() string { return p.os }
func (p targetsProvider) GetTargets() []platform.PolicyTarget {
	return platform.DefaultPolicyTargets()
}

func TestTargetsListsEveryManagedFileForUninstall(t *testing.T) {
	for _, osName := range []string{"linux", "darwin", "windows"} {
		var out bytes.Buffer
		p := targetsProvider{os: osName}
		writeTargets(&out, p)
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		if len(lines) != len(p.GetTargets()) {
			t.Fatalf("%s: want one line per target, got %q", osName, out.String())
		}
		hooks := 0
		for i, line := range lines {
			purpose, path, ok := strings.Cut(line, "\t")
			target := p.GetTargets()[i]
			if !ok || path != target.FilePath(osName) || path == "" {
				t.Fatalf("%s: malformed line %q", osName, line)
			}
			if purpose == "hook-registration" {
				hooks++
			} else if purpose != "policy" && purpose != "registration-template" {
				t.Fatalf("%s: unexpected purpose %q", osName, purpose)
			}
		}
		// Each machine hook file runs the edict binary; uninstall must remove it.
		if hooks == 0 {
			t.Fatalf("%s: no hook registrations reported", osName)
		}
	}
}
