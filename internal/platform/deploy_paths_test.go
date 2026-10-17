package platform

import (
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// The Linux service runs with ProtectSystem=strict, so every target directory
// must be writable in the unit and pre-created by the installer. A missing
// entry makes the daemon fail closed on every pass for that product.
func TestLinuxServiceSandboxCoversEveryTargetDirectory(t *testing.T) {
	unit, err := os.ReadFile("../../deploy/systemd/agent-edict.service")
	if err != nil {
		t.Fatal(err)
	}
	installer, err := os.ReadFile("../../scripts/install-agent.sh")
	if err != nil {
		t.Fatal(err)
	}
	writable := map[string]bool{}
	for _, line := range strings.Split(string(unit), "\n") {
		if rest, ok := strings.CutPrefix(line, "ReadWritePaths="); ok {
			for _, entry := range strings.Fields(rest) {
				writable[strings.TrimPrefix(entry, "-")] = true
			}
		}
	}
	created := map[string]bool{}
	if m := regexp.MustCompile(`(?m)^\s*mkdir -p (/etc/codex .*)$`).FindSubmatch(installer); m != nil {
		for _, dir := range strings.Fields(string(m[1])) {
			created[dir] = true
		}
	}
	for _, target := range DefaultPolicyTargets() {
		// The writable root is the first directory below /etc.
		parts := strings.Split(strings.TrimPrefix(target.DirPath("linux"), "/"), "/")
		root := "/" + path.Join(parts[:2]...)
		if !writable[root] {
			t.Errorf("%s target %s is not in ReadWritePaths", target.AgentName, root)
		}
		if !created[root] {
			t.Errorf("%s target %s is not pre-created by install-agent.sh", target.AgentName, root)
		}
	}
}
