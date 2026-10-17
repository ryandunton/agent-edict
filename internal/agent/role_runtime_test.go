package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ryandunton/agent-edict/internal/hookjson"
	"github.com/ryandunton/agent-edict/internal/platform"
)

// roleProvider installs real files under a temp root and logs every
// operation, so tests can check contents and ordering.
type roleProvider struct {
	*testProvider
	ops      []string
	failOnce map[string]error
	hookErr  error
}

func (p *roleProvider) GetTargets() []platform.PolicyTarget {
	at := func(agent, ext, dir, file, purpose string) platform.PolicyTarget {
		d := filepath.Join(p.root, dir)
		f := filepath.Join(d, file)
		return platform.PolicyTarget{AgentName: agent, BundleExt: ext, Purpose: purpose, UnixDir: d, UnixFile: f, DarwinDir: d, DarwinFile: f, WindowsDir: d, WindowsFile: f}
	}
	return []platform.PolicyTarget{
		at("codex", "codex.toml", "codex", "requirements.toml", ""),
		at("claude", "claude.json", "claude", "managed-settings.json", ""),
		at("cursor", "cursor.policy.json", "cursor", "agentedict-policy.json", ""),
		at("cursor", "cursor.hooks.json", "cursor", "hooks.json", "hook-registration"),
		at("cline", "cline.policy.json", "agent-edict", "cline-policy.json", ""),
	}
}

func (p *roleProvider) AtomicSwapAndLock(target platform.PolicyTarget, source string) error {
	dest := target.FilePath(p.OSName())
	if err := p.failOnce[dest]; err != nil {
		delete(p.failOnce, dest)
		return err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	p.ops = append(p.ops, "install "+dest)
	return os.WriteFile(dest, data, 0644)
}

func (p *roleProvider) RemoveManagedFile(target platform.PolicyTarget) error {
	dest := target.FilePath(p.OSName())
	p.ops = append(p.ops, "remove "+dest)
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (p *roleProvider) ValidateHookRuntime() error { return p.hookErr }

type roleHarness struct {
	t        *testing.T
	agent    *Agent
	provider *roleProvider
	snapshot int
}

func newRoleHarness(t *testing.T) *roleHarness {
	t.Helper()
	a, base, _ := newTestAgent(t)
	p := &roleProvider{testProvider: base, failOnce: map[string]error{}}
	a.provider = p
	a.claudeSandboxDeps = func() error { return nil }
	return &roleHarness{t: t, agent: a, provider: p}
}

// activate writes a new verified snapshot into the vault and makes it active.
func (h *roleHarness) activate(files map[string][]byte) string {
	h.t.Helper()
	h.snapshot++
	name := fmt.Sprintf("snapshot-%d", h.snapshot)
	dir := filepath.Join(h.provider.VaultPath(), "snapshots", name)
	writeFiles(h.t, dir, files)
	if err := os.WriteFile(filepath.Join(h.provider.VaultPath(), "active"), []byte(name+"\n"), 0600); err != nil {
		h.t.Fatal(err)
	}
	return dir
}

func (h *roleHarness) reconcile(listing *SessionListing) (EnforcementResult, error) {
	h.agent.mu.Lock()
	defer h.agent.mu.Unlock()
	return h.agent.enforceFromLocalVaultWith(listing)
}

func (h *roleHarness) target(dir, file string) string {
	return filepath.Join(h.provider.root, dir, file)
}

func (h *roleHarness) requireBytes(path, snapshot, compiled string) {
	h.t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatalf("read %s: %v", path, err)
	}
	want, err := os.ReadFile(filepath.Join(snapshot, "profiles", "linux", compiled))
	if err != nil {
		h.t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		h.t.Fatalf("%s does not hold %s", path, compiled)
	}
}

func resultFor(t *testing.T, result EnforcementResult, agent string) AssignmentResult {
	t.Helper()
	for _, r := range result.Assignments {
		if r.Agent == agent {
			return r
		}
	}
	t.Fatalf("no result for %s in %+v", agent, result.Assignments)
	return AssignmentResult{}
}

func fresh(users ...platform.SessionUser) *SessionListing {
	return &SessionListing{Users: users, Fresh: true}
}

func TestColdStartAppliesStandard(t *testing.T) {
	h := newRoleHarness(t)
	snap := h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	result, err := h.reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof != "cold_start" || result.MapVersion != 2 {
		t.Fatalf("result = %+v", result)
	}
	h.requireBytes(h.target("codex", "requirements.toml"), snap, "standard.codex.toml")
	h.requireBytes(h.target("claude", "managed-settings.json"), snap, "standard.claude.json")
	h.requireBytes(h.target("cursor", "hooks.json"), snap, "standard.cursor.hooks.json")
	for _, agent := range []string{"codex", "claude", "cursor"} {
		if r := resultFor(t, result, agent); r.State != "installed" || r.Profile != "standard" {
			t.Errorf("%s = %+v", agent, r)
		}
	}
}

func TestFreshProofSwitchesPerAgent(t *testing.T) {
	h := newRoleHarness(t)
	snap := h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	result, err := h.reconcile(fresh(engineer, contractor))
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof != "fresh" {
		t.Fatalf("proof = %q", result.Proof)
	}
	h.requireBytes(h.target("codex", "requirements.toml"), snap, "contractor-readonly.codex.toml")
	h.requireBytes(h.target("claude", "managed-settings.json"), snap, "contractor-claude.claude.json")
	h.requireBytes(h.target("cursor", "agentedict-policy.json"), snap, "engineering.cursor.policy.json")
}

func TestNoProofKeepsLastKnownUsers(t *testing.T) {
	h := newRoleHarness(t)
	snap := h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	if _, err := h.reconcile(fresh(engineer)); err != nil {
		t.Fatal(err)
	}
	result, err := h.reconcile(fresh())
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof != "last_known" || resultFor(t, result, "codex").Profile != "engineering" {
		t.Fatalf("nobody logged in must keep the engineer's policy: %+v", result)
	}
	h.requireBytes(h.target("codex", "requirements.toml"), snap, "engineering.codex.toml")
}

func TestIncompleteListingKeepsLastKnownUsers(t *testing.T) {
	h := newRoleHarness(t)
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	if _, err := h.reconcile(fresh(engineer)); err != nil {
		t.Fatal(err)
	}
	result, err := h.reconcile(&SessionListing{Users: []platform.SessionUser{contractor}, Fresh: false})
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof != "last_known" || resultFor(t, result, "codex").Profile != "engineering" {
		t.Fatalf("an incomplete listing is not proof: %+v", result)
	}
}

func TestWindowsUntranslatedGroupsAreNotProof(t *testing.T) {
	h := newRoleHarness(t)
	h.provider.osName = "windows"
	h.activate(compileV2Files(t, exampleMapText(t), "windows"))
	if _, err := h.reconcile(fresh(platform.SessionUser{Key: "S-1-5-21-9", Name: `CORP\eve`, Groups: []string{`CORP\SG-Engineers`}})); err != nil {
		t.Fatal(err)
	}
	offline := platform.SessionUser{Key: "S-1-5-21-9", Name: `CORP\eve`, Groups: []string{"S-1-5-21-1-2-3-1107"}, Untranslated: []string{"S-1-5-21-1-2-3-1107"}}
	result, err := h.reconcile(fresh(offline))
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof != "last_known" || resultFor(t, result, "codex").Profile != "engineering" {
		t.Fatalf("untranslated groups with a DOMAIN\\Name rule must not switch: %+v", result)
	}
}

func TestNewBundleWithoutProofUsesLastProvenUsers(t *testing.T) {
	h := newRoleHarness(t)
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	if _, err := h.reconcile(fresh(engineer)); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(exampleMapText(t), "    profile: engineering\n", "    profile: contractor-claude\n", 1)
	changed = strings.Replace(changed, "    agents: [all]\n", "    agents: [claude]\n", 1)
	snap := h.activate(compileV2Files(t, changed, "linux"))
	result, err := h.reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof != "last_known" || resultFor(t, result, "claude").Profile != "contractor-claude" {
		t.Fatalf("the new map must apply to the last proven users: %+v", result)
	}
	h.requireBytes(h.target("claude", "managed-settings.json"), snap, "contractor-claude.claude.json")
}

func TestFirstTakeoverSavesOriginal(t *testing.T) {
	h := newRoleHarness(t)
	foreign := []byte(`{"from":"another admin"}`)
	dest := h.target("claude", "managed-settings.json")
	os.MkdirAll(filepath.Dir(dest), 0755)
	os.WriteFile(dest, foreign, 0644)
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	result, err := h.reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.Originals, dest) {
		t.Fatalf("originals = %v", result.Originals)
	}
	state, err := LoadRoleState(h.provider.VaultPath())
	if err != nil || len(state.Originals) != 1 {
		t.Fatalf("state = %+v, %v", state, err)
	}
	saved, _ := os.ReadFile(filepath.Join(h.provider.VaultPath(), state.Originals[0].Copy))
	if !bytes.Equal(saved, foreign) {
		t.Fatalf("saved original = %q", saved)
	}
	if _, err := h.reconcile(nil); err != nil {
		t.Fatal(err)
	}
	if state, _ := LoadRoleState(h.provider.VaultPath()); len(state.Originals) != 1 {
		t.Fatal("AgentEdict's own installed file was copied as an original")
	}
}

func TestV1ToV2UpgradeDoesNotCopyAgentEdictFiles(t *testing.T) {
	h := newRoleHarness(t)
	v1 := []byte("setting = \"from v1\"\n")
	h.activate(map[string][]byte{"policy-map.yaml": []byte("version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n"), "profiles/linux/restricted.codex.toml": v1})
	dest := h.target("codex", "requirements.toml")
	os.MkdirAll(filepath.Dir(dest), 0755)
	os.WriteFile(dest, v1, 0644)
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	result, err := h.reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Originals) != 0 {
		t.Fatalf("a file installed by version 1 was copied as an original: %v", result.Originals)
	}
}

// clineProfiles copies the example profiles and adds Cline sections, so a
// map can manage Cline and then drop it.
func clineProfiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(exampleProfiles)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(exampleProfiles, e.Name()))
		if strings.HasSuffix(e.Name(), ".native.yaml") {
			data = append(data, []byte("cline:\n  hooks:\n    version: 1\n    tools:\n      read_files: allow\n    commands: []\n")...)
		}
		os.WriteFile(filepath.Join(dir, e.Name()), data, 0600)
	}
	return dir
}

func TestDroppedAgentsRemoveHooksFirstAndReleaseCline(t *testing.T) {
	h := newRoleHarness(t)
	profiles := clineProfiles(t)
	withCline := strings.Replace(exampleMapText(t), "managed_agents: [codex, claude, cursor]", "managed_agents: [codex, claude, cursor, cline]", 1)
	h.activate(compileV2FilesFrom(t, profiles, withCline, "linux"))
	if _, err := h.reconcile(nil); err != nil {
		t.Fatal(err)
	}
	dropped := strings.Replace(exampleMapText(t), "managed_agents: [codex, claude, cursor]", "managed_agents: [codex, claude]", 1)
	dropped = strings.Replace(dropped, "    agents: [all]\n", "    agents: [codex, claude]\n", 1)
	h.provider.ops = nil
	result, err := h.reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Released) != 0 {
		t.Fatalf("an unchanged map released %v", result.Released)
	}
	h.activate(compileV2FilesFrom(t, profiles, dropped, "linux"))
	h.provider.ops = nil
	result, err = h.reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.Released, "cursor") || !slices.Contains(result.Released, "cline") {
		t.Fatalf("released = %v", result.Released)
	}
	hooks := slices.Index(h.provider.ops, "remove "+h.target("cursor", "hooks.json"))
	policy := slices.Index(h.provider.ops, "remove "+h.target("cursor", "agentedict-policy.json"))
	if hooks < 0 || policy < 0 || hooks > policy {
		t.Fatalf("hook registration must be removed before its policy: %v", h.provider.ops)
	}
	cline, _ := os.ReadFile(h.target("agent-edict", "cline-policy.json"))
	if !hookjson.IsReleased(cline) {
		t.Fatalf("cline policy = %q, want the released policy", cline)
	}
	if _, err := os.Stat(filepath.Join(h.provider.root, "cursor")); !os.IsNotExist(err) {
		t.Fatal("the empty cursor directory AgentEdict created was left behind")
	}
	state, _ := LoadRoleState(h.provider.VaultPath())
	for _, a := range state.Assignments {
		if a.Agent == "cursor" || a.Agent == "cline" {
			t.Fatalf("released agent still assigned: %+v", a)
		}
	}
}

func TestPreflightFailureIsPerAgent(t *testing.T) {
	h := newRoleHarness(t)
	snap := h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	if _, err := h.reconcile(nil); err != nil {
		t.Fatal(err)
	}
	h.provider.hookErr = errors.New("edict executable is not protected")
	result, err := h.reconcile(fresh(engineer))
	if err == nil {
		t.Fatal("a skipped agent must be reported as an error")
	}
	if r := resultFor(t, result, "cursor"); r.State != "skipped" || !strings.Contains(r.Reason, "not protected") {
		t.Fatalf("cursor = %+v", r)
	}
	h.requireBytes(h.target("cursor", "agentedict-policy.json"), snap, "standard.cursor.policy.json")
	h.requireBytes(h.target("codex", "requirements.toml"), snap, "engineering.codex.toml")
	state, _ := LoadRoleState(h.provider.VaultPath())
	for _, a := range state.Assignments {
		if a.Agent == "cursor" && a.Profile != "standard" {
			t.Fatalf("a skipped agent's recorded assignment changed: %+v", a)
		}
	}
}

func TestClaudeSandboxDepsMissingSkipsClaude(t *testing.T) {
	h := newRoleHarness(t)
	h.agent.claudeSandboxDeps = func() error { return errors.New("Claude sandbox needs bubblewrap and socat installed") }
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	result, err := h.reconcile(nil)
	if err == nil {
		t.Fatal("a skipped agent must be reported as an error")
	}
	if r := resultFor(t, result, "claude"); r.State != "skipped" || !strings.Contains(r.Reason, "bubblewrap") {
		t.Fatalf("claude = %+v", r)
	}
	if _, err := os.Stat(h.target("claude", "managed-settings.json")); !os.IsNotExist(err) {
		t.Fatal("a Claude file that needs the sandbox was installed without its packages")
	}
	if r := resultFor(t, result, "codex"); r.State != "installed" {
		t.Fatalf("codex = %+v", r)
	}
}

func TestPartialSwitchIsRetried(t *testing.T) {
	h := newRoleHarness(t)
	snap := h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	dest := h.target("claude", "managed-settings.json")
	h.provider.failOnce[dest] = errors.New("disk full")
	result, err := h.reconcile(fresh(engineer))
	if err == nil || resultFor(t, result, "claude").State != "incomplete" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	result, err = h.reconcile(nil)
	if err != nil || resultFor(t, result, "claude").State != "installed" {
		t.Fatalf("retry = %+v, %v", result, err)
	}
	h.requireBytes(dest, snap, "engineering.claude.json")
}

func TestCorruptRoleStateKeepsInstalledFiles(t *testing.T) {
	h := newRoleHarness(t)
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	if _, err := h.reconcile(fresh(engineer)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(h.target("codex", "requirements.toml"))
	os.WriteFile(filepath.Join(h.provider.VaultPath(), "role-state.json"), []byte(`{"version":9}`), 0600)
	h.provider.ops = nil
	if _, err := h.reconcile(fresh(contractor)); err == nil {
		t.Fatal("a corrupt role state was ignored")
	}
	after, _ := os.ReadFile(h.target("codex", "requirements.toml"))
	if !bytes.Equal(before, after) || len(h.provider.ops) != 0 {
		t.Fatalf("files changed despite a corrupt role state: %v", h.provider.ops)
	}
}

// A version 2 map that manages fewer agents than the version 1 bundle before
// it must release the dropped agents' files, not leave them locked.
func TestV1AgentsOutsideV2ScopeAreReleased(t *testing.T) {
	h := newRoleHarness(t)
	codexV1, claudeV1 := []byte("setting = \"v1\"\n"), []byte(`{"permissions":{}}`)
	h.activate(map[string][]byte{
		"policy-map.yaml":                       []byte("version: 1\nmachine_profile: restricted\nmanaged_agents: [codex, claude]\n"),
		"profiles/linux/restricted.codex.toml":  codexV1,
		"profiles/linux/restricted.claude.json": claudeV1,
	})
	for path, data := range map[string][]byte{h.target("codex", "requirements.toml"): codexV1, h.target("claude", "managed-settings.json"): claudeV1} {
		os.MkdirAll(filepath.Dir(path), 0755)
		os.WriteFile(path, data, 0644)
	}
	foreign := h.target("cursor", "hooks.json")
	os.MkdirAll(filepath.Dir(foreign), 0755)
	os.WriteFile(foreign, []byte(`{"hooks":"someone else's"}`), 0644)
	codexOnly := "version: 2\nmanaged_agents: [codex]\nstandard:\n  profile: standard\n  priority: 100\nrules:\n  - priority: 10\n    profile: contractor-readonly\n    agents: [codex]\n    match_groups:\n      linux: [contractors]\n"
	h.activate(compileV2Files(t, codexOnly, "linux"))
	result, err := h.reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Released, []string{"claude"}) {
		t.Fatalf("released = %v, want the version 1 claude files released", result.Released)
	}
	if _, err := os.Stat(h.target("claude", "managed-settings.json")); !os.IsNotExist(err) {
		t.Fatal("version 1 claude file still installed")
	}
	if data, _ := os.ReadFile(foreign); string(data) != `{"hooks":"someone else's"}` {
		t.Fatal("a file AgentEdict never wrote was removed")
	}
}

// One skipped agent is retried later; it must not look like a fatal failure.
func TestSkippedAgentIsPartialEnforcement(t *testing.T) {
	h := newRoleHarness(t)
	h.agent.claudeSandboxDeps = func() error { return errors.New("Claude sandbox needs bubblewrap installed") }
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	if _, err := h.reconcile(nil); !errors.Is(err, ErrPartialEnforcement) {
		t.Fatalf("a skipped agent must be partial enforcement, got %v", err)
	}
	os.WriteFile(filepath.Join(h.provider.VaultPath(), "role-state.json"), []byte(`{"version":9}`), 0600)
	if _, err := h.reconcile(nil); err == nil || errors.Is(err, ErrPartialEnforcement) {
		t.Fatalf("an unreadable role state is not partial enforcement, got %v", err)
	}
}

func TestRunContinuesAfterPartialEnforcement(t *testing.T) {
	h := newRoleHarness(t)
	h.agent.claudeSandboxDeps = func() error { return errors.New("Claude sandbox needs bubblewrap installed") }
	h.activate(compileV2Files(t, exampleMapText(t), "linux"))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := h.agent.Run(ctx, make(chan struct{})); err != nil {
		t.Fatalf("the service must keep running and retry skipped agents, got %v", err)
	}
}
