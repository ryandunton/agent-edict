package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ryandunton/agent-edict/internal/platform"
)

// listingProvider is a roleProvider that also lists sessions.
type listingProvider struct {
	*roleProvider
	keys       []string
	users      []platform.SessionUser
	usersErr   error
	usersCalls int
}

func (p *listingProvider) SessionKeys() ([]string, error) { return p.keys, nil }
func (p *listingProvider) SessionUsers() ([]platform.SessionUser, error) {
	p.usersCalls++
	return p.users, p.usersErr
}

func TestSessionTickSkipsGroupLookupWhenKeysUnchanged(t *testing.T) {
	h := newRoleHarness(t)
	p := &listingProvider{roleProvider: h.provider, keys: []string{"1001"}, users: []platform.SessionUser{engineer}}
	h.agent.provider = p
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	result, changed, err := h.agent.SessionTick()
	if err != nil || !changed || result.Proof != "fresh" || p.usersCalls != 1 {
		t.Fatalf("first tick: changed=%v proof=%q calls=%d err=%v", changed, result.Proof, p.usersCalls, err)
	}
	if _, changed, err := h.agent.SessionTick(); err != nil || changed || p.usersCalls != 1 {
		t.Fatalf("unchanged keys must not look up groups: changed=%v calls=%d err=%v", changed, p.usersCalls, err)
	}
	p.keys = []string{"1001", "1002"}
	p.users = []platform.SessionUser{engineer, contractor}
	result, changed, err = h.agent.SessionTick()
	if err != nil || !changed || p.usersCalls != 2 || resultFor(t, result, "codex").Profile != "contractor-readonly" {
		t.Fatalf("a new login must reconcile: changed=%v calls=%d err=%v result=%+v", changed, p.usersCalls, err, result)
	}
}

func TestSessionTickIgnoresVersionOneMaps(t *testing.T) {
	h := newRoleHarness(t)
	p := &listingProvider{roleProvider: h.provider, keys: []string{"1001"}}
	h.agent.provider = p
	h.activate(map[string][]byte{"policy-map.yaml": []byte("version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n"), "profiles/linux/restricted.codex.toml": []byte("a = 1\n")})
	if _, changed, err := h.agent.SessionTick(); changed || err != nil || p.usersCalls != 0 {
		t.Fatalf("version 1 maps never consult sessions: changed=%v err=%v", changed, err)
	}
}

func TestUnchangedBundleIsNotRestaged(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := validBundle(t, "setting = true")
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	active, _ := os.ReadFile(filepath.Join(p.VaultPath(), "active"))
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(p.VaultPath(), "snapshots"))
	again, _ := os.ReadFile(filepath.Join(p.VaultPath(), "active"))
	if len(entries) != 1 || string(active) != string(again) {
		t.Fatalf("an unchanged bundle was staged again: %d snapshots, active %q -> %q", len(entries), active, again)
	}
	bundle = validBundle(t, "setting = false")
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	if p.installed["codex"] != "setting = false" {
		t.Fatal("a changed bundle was not applied")
	}
}

func TestNegativeSessionIntervalRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := New(Config{PublicKeyPEM: key, SyncInterval: time.Minute, SessionInterval: -time.Second}, &testProvider{root: t.TempDir()}); err == nil {
		t.Fatal("negative session interval accepted")
	}
	a, err := New(Config{PublicKeyPEM: key, SyncInterval: time.Minute}, &testProvider{root: t.TempDir()})
	if err != nil || a.cfg.SessionInterval != 30*time.Second {
		t.Fatalf("default session interval = %v, %v", a.cfg.SessionInterval, err)
	}
}

// A failed group lookup is retried on the bundle interval, not on every
// 30-second check, and changes no files in between.
func TestFailedGroupLookupIsNotRetriedEveryTick(t *testing.T) {
	h := newRoleHarness(t)
	p := &listingProvider{roleProvider: h.provider, keys: []string{"1001"}, users: []platform.SessionUser{engineer}}
	h.agent.provider = p
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	if _, changed, err := h.agent.SessionTick(); err != nil || !changed {
		t.Fatalf("first tick: changed=%v err=%v", changed, err)
	}
	p.keys = []string{"1001", "1002"}
	p.usersErr = platform.ErrIncompleteListing
	h.provider.ops = nil
	if _, changed, err := h.agent.SessionTick(); err == nil || changed {
		t.Fatalf("a failed lookup must report an error and change nothing: changed=%v err=%v", changed, err)
	}
	if _, changed, err := h.agent.SessionTick(); err != nil || changed || p.usersCalls != 2 {
		t.Fatalf("the same users must not be looked up again every tick: changed=%v calls=%d err=%v", changed, p.usersCalls, err)
	}
	if len(h.provider.ops) != 0 {
		t.Fatalf("files changed after a failed lookup: %v", h.provider.ops)
	}
	p.usersErr = nil
	p.users = []platform.SessionUser{engineer, contractor}
	h.agent.mu.Lock()
	listing := h.agent.currentListing()
	h.agent.mu.Unlock()
	if listing == nil || !listing.Fresh || len(listing.Users) != 2 || p.usersCalls != 3 {
		t.Fatalf("the bundle-interval listing must retry the lookup: %+v calls=%d", listing, p.usersCalls)
	}
}
