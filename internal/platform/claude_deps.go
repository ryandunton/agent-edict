package platform

import (
	"fmt"
	"strings"
)

// claudeSandboxDependencies reports which packages Claude Code's Linux
// sandbox needs but cannot find. AgentEdict never installs them.
func claudeSandboxDependencies(lookPath func(string) (string, error)) error {
	var missing []string
	for _, dep := range []struct{ command, pkg string }{{"bwrap", "bubblewrap"}, {"socat", "socat"}} {
		if _, err := lookPath(dep.command); err != nil {
			missing = append(missing, dep.pkg)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("Claude sandbox needs %s installed", strings.Join(missing, " and "))
	}
	return nil
}
