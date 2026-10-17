//go:build linux

package platform

import "os/exec"

// ClaudeSandboxDependencies checks the packages Claude Code's sandbox needs.
func ClaudeSandboxDependencies() error { return claudeSandboxDependencies(exec.LookPath) }
