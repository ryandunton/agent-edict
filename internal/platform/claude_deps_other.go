//go:build !linux

package platform

// ClaudeSandboxDependencies is nil where Claude's sandbox needs no packages
// (macOS) or where AgentEdict never requires it (Windows).
func ClaudeSandboxDependencies() error { return nil }
