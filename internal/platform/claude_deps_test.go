package platform

import (
	"errors"
	"strings"
	"testing"
)

func TestClaudeSandboxDependenciesNamesPackages(t *testing.T) {
	missing := func(string) (string, error) { return "", errors.New("not found") }
	err := claudeSandboxDependencies(missing)
	if err == nil || !strings.Contains(err.Error(), "bubblewrap") || !strings.Contains(err.Error(), "socat") {
		t.Fatalf("error = %v, want both packages named", err)
	}
	onlySocat := func(name string) (string, error) {
		if name == "socat" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + name, nil
	}
	if err := claudeSandboxDependencies(onlySocat); err == nil || strings.Contains(err.Error(), "bubblewrap") {
		t.Fatalf("error = %v, want only socat named", err)
	}
	present := func(name string) (string, error) { return "/usr/bin/" + name, nil }
	if err := claudeSandboxDependencies(present); err != nil {
		t.Fatal(err)
	}
}
