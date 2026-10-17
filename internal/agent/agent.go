package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
	"gopkg.in/yaml.v3"
)

type Config struct {
	GitLabBundleURL string
	DeployToken     string
	PublicKeyPEM    string
	SyncInterval    time.Duration
	// SessionInterval is how often the cheap logged-in user check runs for
	// version 2 maps. Zero means 30 seconds.
	SessionInterval time.Duration
}

const defaultSessionInterval = 30 * time.Second

type PolicyMap struct {
	MachineProfile string       `yaml:"machine_profile"`
	ManagedAgents  []string     `yaml:"managed_agents"`
	SyncWSL        bool         `yaml:"sync_wsl,omitempty"`
	Version        int          `yaml:"version"`
	DefaultProfile string       `yaml:"default_profile"`
	Rules          []PolicyRule `yaml:"rules"`
}

type PolicyRule struct {
	Priority    int                 `yaml:"priority"`
	Profile     string              `yaml:"profile"`
	Description string              `yaml:"description"`
	MatchGroups map[string][]string `yaml:"match_groups"`
}

type Agent struct {
	cfg      Config
	provider platform.PlatformProvider
	pubKey   ed25519.PublicKey
	mu       sync.Mutex
	client   *http.Client
	// claudeSandboxDeps reports missing packages for Claude's OS sandbox.
	claudeSandboxDeps func() error
	// lastSessionKeys is the logged-in set at the last complete listing.
	lastSessionKeys []string
	haveSessionKeys bool
}

func New(cfg Config, provider platform.PlatformProvider) (*Agent, error) {
	if cfg.SyncInterval <= 0 {
		return nil, fmt.Errorf("sync interval must be positive")
	}
	if cfg.SessionInterval < 0 {
		return nil, fmt.Errorf("session interval must not be negative")
	}
	if cfg.SessionInterval == 0 {
		cfg.SessionInterval = defaultSessionInterval
	}
	if cfg.GitLabBundleURL != "" {
		if _, err := validateBundleURL(cfg.GitLabBundleURL); err != nil {
			return nil, err
		}
	}
	pubKey, err := parseEd25519PublicKey(cfg.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return &Agent{
		cfg:      cfg,
		provider: provider,
		pubKey:   pubKey,
		client:   &http.Client{},

		claudeSandboxDeps: platform.ClaudeSandboxDependencies,
	}, nil
}

func (a *Agent) Run(ctx context.Context, sessionChangeCh <-chan struct{}) error {
	if err := a.provider.EnsureSecureDirectories(); err != nil {
		return fmt.Errorf("secure directories init: %w", err)
	}

	// Initial sync & enforcement
	initial, err := a.SyncAndEnforce()
	if errors.Is(err, ErrPartialEnforcement) {
		// Skipped agents are retried by the loop; exiting would only make the
		// service manager restart us and download the bundle again.
		log.Printf("[Agent] Initial enforcement incomplete; retrying: %v", err)
	} else if err != nil {
		return fmt.Errorf("initial enforcement: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify init: %w", err)
	}
	defer watcher.Close()

	// Watch the base directory and the directories of installed targets only;
	// unmanaged products' folders may not exist and are never repaired.
	watched := map[string]bool{}
	syncWatches := func(installed []string) error {
		want := watchDirs(a.provider.BaseDir(), installed)
		keep := map[string]bool{}
		var failures []error
		for _, dir := range want {
			keep[dir] = true
			if watched[dir] {
				continue
			}
			if err := watcher.Add(dir); err != nil {
				failures = append(failures, fmt.Errorf("watch %s: %w", dir, err))
				continue
			}
			watched[dir] = true
		}
		for dir := range watched {
			if !keep[dir] {
				_ = watcher.Remove(dir)
				delete(watched, dir)
			}
		}
		return errors.Join(failures...)
	}
	if err := syncWatches(initial.Installed); err != nil {
		return err
	}
	enforced := func(result EnforcementResult, err error) {
		if err != nil {
			log.Printf("[Agent] Sync/enforcement failed: %v", err)
		}
		if len(result.Installed) > 0 {
			if err := syncWatches(result.Installed); err != nil {
				log.Printf("[Agent] %v", err)
			}
		}
	}

	ticker := time.NewTicker(a.cfg.SyncInterval)
	defer ticker.Stop()
	sessionTicker := time.NewTicker(a.cfg.SessionInterval)
	defer sessionTicker.Stop()

	log.Printf("[Agent] Running AgentEdict daemon on %s (sync interval: %v)...", a.provider.OSName(), a.cfg.SyncInterval)

	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return nil
		case <-ticker.C:
			enforced(a.SyncAndEnforce())
		case <-sessionTicker.C:
			result, changed, err := a.SessionTick()
			if changed {
				enforced(result, err)
			} else if err != nil {
				log.Printf("[Agent] Session check failed: %v", err)
			}
		case <-sessionChangeCh:
			log.Println("[Agent] Session change detected; reapplying signed machine policy and requested subsystem sync...")
			enforced(a.RefreshSessions())
		case ev, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("filesystem watcher closed")
			}
			if a.isTargetFile(ev.Name) {
				if ev.Has(fsnotify.Create) || ev.Has(fsnotify.Write) || ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Chmod) {
					if debounceTimer != nil {
						if !debounceTimer.Stop() {
							select {
							case <-debounceTimer.C:
							default:
							}
						}
					}
					debounceTimer = time.NewTimer(250 * time.Millisecond)
					debounceCh = debounceTimer.C
				}
			}
		case <-debounceCh:
			debounceTimer = nil
			debounceCh = nil
			log.Println("[Agent] Policy tamper or modification detected; restoring policy from local vault...")
			enforced(a.EnforceFromLocalVault())
		case err, ok := <-watcher.Errors:
			if ok {
				log.Printf("[Agent] Watcher error: %v", err)
			}
		}
	}
}

// watchDirs is the base directory plus each installed file's directory.
func watchDirs(base string, installed []string) []string {
	seen := map[string]bool{base: true}
	dirs := []string{base}
	for _, file := range installed {
		dir := filepath.Dir(file)
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	return dirs
}

func (a *Agent) isTargetFile(path string) bool {
	cleanPath := filepath.Clean(strings.ToLower(path))
	osName := a.provider.OSName()
	for _, target := range a.provider.GetTargets() {
		file := target.FilePath(osName)
		if cleanPath == filepath.Clean(strings.ToLower(file)) {
			return true
		}
	}
	return false
}

// EnforcementResult reports file installation, not consumer runtime enforcement.
type EnforcementResult struct {
	Profile              string                      `json:"machine_profile"`
	ManagedAgents        []string                    `json:"managed_agents"`
	Installed            []string                    `json:"installed_files"`
	Snapshot             string                      `json:"snapshot"`
	SyncError            string                      `json:"sync_error,omitempty"`
	SubsystemError       string                      `json:"subsystem_error,omitempty"`
	SubsystemStatus      string                      `json:"subsystem_status"`
	ConsumerVerification string                      `json:"consumer_verification"`
	NativeCapabilities   []compiler.NativeCapability `json:"native_capabilities,omitempty"`
	RegistrationStatus   string                      `json:"registration_status,omitempty"`
	MapVersion           int                         `json:"map_version"`
	Assignments          []AssignmentResult          `json:"assignments,omitempty"`
	Proof                string                      `json:"proof,omitempty"`
	Released             []string                    `json:"released_agents,omitempty"`
	Originals            []string                    `json:"saved_originals,omitempty"`
}

func (a *Agent) SyncAndEnforce() (EnforcementResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var syncErr error
	if a.cfg.GitLabBundleURL != "" {
		syncErr = a.pullAndVerifyBundle()
		if syncErr != nil {
			log.Printf("[Agent] Bundle update rejected; attempting previous verified snapshot: %v", syncErr)
		}
	}
	// The bundle interval also refreshes group memberships for version 2.
	result, err := a.enforceFromLocalVaultWith(a.currentListing())
	if syncErr != nil {
		result.SyncError = syncErr.Error()
		if err != nil {
			return result, errors.Join(syncErr, err)
		}
	}
	return result, err
}

// RefreshSessions re-lists logged-in users with their groups and enforces.
func (a *Agent) RefreshSessions() (EnforcementResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enforceFromLocalVaultWith(a.currentListing())
}

// SessionTick is the frequent, cheap check: it lists who is logged in and
// reconciles only when that set changed since the last complete listing.
func (a *Agent) SessionTick() (EnforcementResult, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	lister, ok := a.provider.(platform.SessionLister)
	if !ok || !a.activeMapIsV2() {
		return EnforcementResult{}, false, nil
	}
	keys, err := lister.SessionKeys()
	if err != nil {
		return EnforcementResult{}, false, fmt.Errorf("list sessions: %w", err)
	}
	if a.haveSessionKeys && slices.Equal(keys, a.lastSessionKeys) {
		return EnforcementResult{}, false, nil
	}
	// Remember this set even when its groups can't be resolved: a failed
	// lookup is not proof, and the bundle interval retries it.
	a.lastSessionKeys, a.haveSessionKeys = keys, true
	users, err := lister.SessionUsers()
	if err != nil {
		return EnforcementResult{}, false, fmt.Errorf("resolve session users: %w", err)
	}
	result, err := a.enforceFromLocalVaultWith(&SessionListing{Users: users, Fresh: true})
	return result, true, err
}

// currentListing resolves logged-in users for a version 2 snapshot. It is
// nil for version 1 maps and providers that cannot list sessions.
func (a *Agent) currentListing() *SessionListing {
	lister, ok := a.provider.(platform.SessionLister)
	if !ok || !a.activeMapIsV2() {
		return nil
	}
	users, err := lister.SessionUsers()
	if err != nil {
		log.Printf("[Agent] Session listing incomplete; keeping the last known users: %v", err)
		return &SessionListing{Fresh: false}
	}
	keys := make([]string, 0, len(users))
	for _, user := range users {
		if !slices.Contains(keys, user.Key) {
			keys = append(keys, user.Key)
		}
	}
	sort.Strings(keys)
	a.lastSessionKeys, a.haveSessionKeys = keys, true
	return &SessionListing{Users: users, Fresh: true}
}

func (a *Agent) activeMapIsV2() bool {
	snapshot, err := ActiveVaultPath(a.provider.VaultPath())
	if err != nil {
		return false
	}
	bm, err := LoadBundleMap(snapshot)
	return err == nil && bm.V2 != nil
}

func (a *Agent) EnforceFromLocalVault() (EnforcementResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enforceFromLocalVault()
}

func (a *Agent) enforceFromLocalVault() (EnforcementResult, error) {
	return a.enforceFromLocalVaultWith(nil)
}

// enforceFromLocalVaultWith enforces the active snapshot. listing is the
// latest look at who is logged in; version 1 maps ignore it.
func (a *Agent) enforceFromLocalVaultWith(listing *SessionListing) (EnforcementResult, error) {
	result := EnforcementResult{ConsumerVerification: "not_performed", SubsystemStatus: "not_requested", MapVersion: 1}
	snapshot, err := ActiveVaultPath(a.provider.VaultPath())
	if err != nil {
		return result, err
	}
	if bm, err := LoadBundleMap(snapshot); err == nil && bm.V2 != nil {
		m, err := validateSnapshotV2(snapshot, a.provider.OSName(), a.provider.GetTargets())
		if err != nil {
			result.MapVersion = 2
			return result, err
		}
		return a.reconcileV2(snapshot, m, listing)
	}
	pm, targets, err := validateSnapshot(snapshot, a.provider.OSName(), a.provider.GetTargets())
	if err != nil {
		return result, err
	}
	result.Profile = pm.MachineProfile
	result.ManagedAgents = pm.ManagedAgents
	result.Snapshot = filepath.Base(snapshot)
	result.NativeCapabilities, err = NativeCapabilities(snapshot, a.provider.OSName(), pm)
	if err != nil {
		return result, err
	}
	result.RegistrationStatus = registrationStatus(pm)
	if err := a.preflightNativeRuntime(pm); err != nil {
		return result, err
	}
	// Preflight the entire selected policy before modifying any target.
	var failures []error
	sortSidecarsFirst(targets)
	if _, err := a.provider.PrepareTargetDirectories(targets); err != nil {
		return result, fmt.Errorf("prepare target directories: %w", err)
	}
	for _, target := range targets {
		sourcePath := filepath.Join(snapshot, "profiles", a.provider.OSName(), pm.MachineProfile+"."+target.BundleExt)
		if err := a.provider.AtomicSwapAndLock(target, sourcePath); err != nil {
			failures = append(failures, fmt.Errorf("install %s: %w", target.BundleExt, err))
			continue
		}
		result.Installed = append(result.Installed, target.FilePath(a.provider.OSName()))
	}
	if pm.SyncWSL && a.provider.OSName() == "windows" {
		result.SubsystemStatus = "synchronization_failed"
		if err := a.provider.SyncSubsystems(filepath.Join(snapshot, "profiles", "linux"), pm.MachineProfile, targets); err != nil {
			result.SubsystemError = err.Error()
			if errors.Is(err, platform.ErrSubsystemUnavailable) {
				result.SubsystemStatus = "deferred"
				log.Printf("[Agent] WSL provisioning deferred: %v", err)
			} else {
				failures = append(failures, fmt.Errorf("WSL synchronization: %w", err))
			}
		} else {
			result.SubsystemStatus = "active_user_distributions_copied; owner_root_not_contained"
		}
	}
	return result, errors.Join(failures...)
}

// MatchProfile evaluates user identity against policy map rules and returns the matched profile, rule, and matched group.
func MatchProfile(user *platform.UserIdentity, pm *PolicyMap, osKey string) (profile string, matchedRule *PolicyRule, matchedGroup string) {
	if pm == nil {
		return "contractor-readonly", nil, ""
	}
	if user == nil {
		return pm.DefaultProfile, nil, ""
	}

	rules := make([]PolicyRule, len(pm.Rules))
	copy(rules, pm.Rules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	userGroupsUpper := make([]string, len(user.Groups))
	for i, g := range user.Groups {
		userGroupsUpper[i] = strings.ToUpper(strings.TrimSpace(g))
	}

	for _, rule := range rules {
		for _, candidate := range rule.MatchGroups[osKey] {
			if slices.Contains(userGroupsUpper, strings.ToUpper(strings.TrimSpace(candidate))) {
				r := rule
				return rule.Profile, &r, candidate
			}
		}
	}
	return pm.DefaultProfile, nil, ""
}

// LoadPolicyMap reads and parses policy-map.yaml from the given vault directory.
func LoadPolicyMap(snapshotPath string) (*PolicyMap, error) {
	data, err := readRegularFile(filepath.Join(snapshotPath, "policy-map.yaml"), 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("read policy map: %w", err)
	}
	if mapVersion(data) == 2 {
		return nil, fmt.Errorf("version 2 map: use LoadBundleMap")
	}
	return parsePolicyMapV1(data)
}

func parsePolicyMapV1(data []byte) (*PolicyMap, error) {
	var pm PolicyMap
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pm); err != nil {
		return nil, fmt.Errorf("decode policy map: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("policy map must contain exactly one YAML document")
	}
	if pm.Version != 1 || !profileNamePattern.MatchString(pm.MachineProfile) {
		return nil, fmt.Errorf("policy map requires version 1 and a safe explicit machine_profile")
	}
	if len(pm.ManagedAgents) == 0 {
		return nil, fmt.Errorf("policy map requires an explicit nonempty managed_agents list")
	}
	seen := map[string]bool{}
	for _, name := range pm.ManagedAgents {
		if name != "codex" && name != "claude" && name != "opencode" && !nativeProduct(name) {
			return nil, fmt.Errorf("unsupported managed agent %q", name)
		}
		if pm.SyncWSL && slices.Contains(hookProducts, name) {
			return nil, fmt.Errorf("sync_wsl cannot provision %s hook runtime; install and manage AgentEdict inside each distribution separately", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate managed agent %q", name)
		}
		seen[name] = true
	}
	return &pm, nil
}

func matchProfile(user *platform.UserIdentity, pm PolicyMap, osKey string) string {
	prof, _, _ := MatchProfile(user, &pm, osKey)
	return prof
}

func parseEd25519PublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}
	return edPub, nil
}
