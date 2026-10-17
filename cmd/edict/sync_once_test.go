package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ryandunton/agent-edict/internal/agent"
)

// sync-once runs in the installers; skipped agents must not abort them.
func TestEnforcementFailedIgnoresPartialEnforcement(t *testing.T) {
	partial := fmt.Errorf("%w: claude: Claude sandbox needs bubblewrap installed", agent.ErrPartialEnforcement)
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{partial, false},
		{errors.Join(errors.New("bundle server returned HTTP 503"), partial), false},
		{errors.New("no active verified snapshot"), true},
	} {
		if got := enforcementFailed(c.err); got != c.want {
			t.Errorf("enforcementFailed(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
