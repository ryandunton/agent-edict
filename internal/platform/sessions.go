package platform

import "errors"

// SessionUser is one logged-in human identity with its resolved groups.
// Key is the SID on Windows and the UID elsewhere. Untranslated lists
// domain or Entra group SIDs whose names could not be looked up.
type SessionUser struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Groups       []string `json:"groups"`
	Untranslated []string `json:"untranslated,omitempty"`
}

// ErrIncompleteListing means a session or a group lookup failed. A listing
// that returns it is never proof that a machine's policy should change.
var ErrIncompleteListing = errors.New("session listing incomplete")

// SessionLister enumerates every logged-in user. SessionKeys is the cheap
// check run often; SessionUsers also resolves groups.
type SessionLister interface {
	SessionKeys() ([]string, error)
	SessionUsers() ([]SessionUser, error)
}
