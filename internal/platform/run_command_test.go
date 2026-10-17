//go:build darwin || linux

package platform

import (
	"testing"
	"time"
)

// A hung lookup (for example `id` waiting on a directory server) must fail
// quickly instead of holding the service's lock.
func TestRunCommandTimesOut(t *testing.T) {
	previous := commandTimeout
	commandTimeout = 100 * time.Millisecond
	t.Cleanup(func() { commandTimeout = previous })
	start := time.Now()
	if _, err := runCommand("sleep", "5"); err == nil {
		t.Fatal("a command that outlives the timeout succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("command was not stopped at the timeout: took %v", elapsed)
	}
}
