package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ryandunton/agent-edict/internal/hookjson"
	"github.com/ryandunton/agent-edict/internal/platform"
)

// ErrPartialEnforcement marks a pass where some agents were skipped or left
// incomplete while the rest installed. Those agents are retried; the error
// must not stop the service or an installer.
var ErrPartialEnforcement = errors.New("some agents were not fully installed")

// SessionListing is one look at who is logged in. Only a Fresh listing with
// at least one user is proof that a machine's policy should change.
type SessionListing struct {
	Users []platform.SessionUser
	Fresh bool
}

// AssignmentResult reports what happened to one agent's assignment. State is
// installed, incomplete (some files failed) or skipped (preflight failed).
type AssignmentResult struct {
	Assignment
	State         string   `json:"state"`
	Reason        string   `json:"reason,omitempty"`
	ToolLevelOnly []string `json:"tool_level_only,omitempty"`
}

// reconcileV2 installs each managed agent's selected policy and releases
// agents the map no longer manages. It only writes, locks and removes files.
func (a *Agent) reconcileV2(snapshot string, m *PolicyMapV2, listing *SessionListing) (EnforcementResult, error) {
	osName := a.provider.OSName()
	vault := a.provider.VaultPath()
	result := EnforcementResult{ConsumerVerification: "not_performed", SubsystemStatus: "not_requested", MapVersion: 2, ManagedAgents: m.ManagedAgents, Snapshot: filepath.Base(snapshot)}
	state, err := LoadRoleState(vault)
	if err != nil {
		return result, fmt.Errorf("role state unreadable; keeping installed files: %w", err)
	}
	firstRun := state == nil
	if firstRun {
		state = &RoleState{Version: roleStateVersion}
	}
	if state.Installed == nil {
		state.Installed = map[string]string{}
	}
	if hash, err := readRegularFile(filepath.Join(vault, "active.sha256"), 128); err == nil {
		state.BundleHash = strings.TrimSpace(string(hash))
	}

	var users []platform.SessionUser
	switch {
	case isProof(listing, osName, m):
		users = listing.Users
		state.Users = listing.Users
		state.ProvenAt = time.Now().UTC()
		result.Proof = "fresh"
	case len(state.Users) > 0:
		users = state.Users
		result.Proof = "last_known"
	default:
		result.Proof = "cold_start"
	}

	previous := map[string]Assignment{}
	for _, assignment := range state.Assignments {
		previous[assignment.Agent] = assignment
	}
	available := a.provider.GetTargets()
	if firstRun {
		// A version 1 bundle may have managed agents this map drops; release
		// them like any agent that leaves managed_agents.
		for _, agent := range a.agentsWithAgentEdictFiles(osName, available) {
			if _, tracked := previous[agent]; !tracked && !slices.Contains(m.ManagedAgents, agent) {
				previous[agent] = Assignment{Agent: agent, Source: "version1"}
			}
		}
	}
	var failures []error
	var kept []Assignment
	for _, assignment := range SelectAssignments(m, osName, users) {
		outcome, err := a.installAssignment(snapshot, osName, state, assignment, available)
		result.Assignments = append(result.Assignments, outcome)
		result.Installed = append(result.Installed, outcomeInstalled(outcome, osName, available)...)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", assignment.Agent, err))
			if prior, ok := previous[assignment.Agent]; ok {
				kept = append(kept, prior)
			}
		} else {
			kept = append(kept, assignment)
			state.Released = slices.DeleteFunc(state.Released, func(name string) bool { return name == assignment.Agent })
		}
		state.Assignments = mergeAssignments(kept, previous, m.ManagedAgents)
		if err := SaveRoleState(vault, state); err != nil {
			return result, errors.Join(append(failures, fmt.Errorf("save role state: %w", err))...)
		}
	}

	for _, prior := range previous {
		if slices.Contains(m.ManagedAgents, prior.Agent) {
			continue
		}
		if err := a.releaseAgent(state, prior.Agent, available); err != nil {
			failures = append(failures, fmt.Errorf("release %s: %w", prior.Agent, err))
			continue
		}
		result.Released = append(result.Released, prior.Agent)
		state.Released = append(state.Released, prior.Agent)
		state.Assignments = slices.DeleteFunc(state.Assignments, func(as Assignment) bool { return as.Agent == prior.Agent })
	}
	sort.Strings(result.Released)
	for _, original := range state.Originals {
		result.Originals = append(result.Originals, original.Path)
	}
	if err := SaveRoleState(vault, state); err != nil {
		return result, errors.Join(append(failures, fmt.Errorf("save role state: %w", err))...)
	}
	if len(failures) > 0 {
		return result, fmt.Errorf("%w: %w", ErrPartialEnforcement, errors.Join(failures...))
	}
	return result, nil
}

// isProof reports whether a listing may change the machine's policy. On
// Windows, unnamed domain groups count as a failed lookup whenever a rule
// matches by DOMAIN\Name.
func isProof(listing *SessionListing, osName string, m *PolicyMapV2) bool {
	if listing == nil || !listing.Fresh || len(listing.Users) == 0 {
		return false
	}
	if osName == "windows" && m.UsesWindowsNames() {
		for _, user := range listing.Users {
			if len(user.Untranslated) > 0 {
				return false
			}
		}
	}
	return true
}

// mergeAssignments keeps the order of managed_agents, using a new assignment
// where one completed and the previous one otherwise.
func mergeAssignments(kept []Assignment, previous map[string]Assignment, managed []string) []Assignment {
	byAgent := map[string]Assignment{}
	for agent, assignment := range previous {
		byAgent[agent] = assignment
	}
	for _, assignment := range kept {
		byAgent[assignment.Agent] = assignment
	}
	var out []Assignment
	for _, agent := range managed {
		if assignment, ok := byAgent[agent]; ok {
			out = append(out, assignment)
		}
	}
	for agent, assignment := range byAgent {
		if !slices.Contains(managed, agent) {
			out = append(out, assignment)
		}
	}
	return out
}

func outcomeInstalled(outcome AssignmentResult, osName string, available []platform.PolicyTarget) []string {
	if outcome.State != "installed" {
		return nil
	}
	var paths []string
	for _, target := range targetsFor(outcome.Agent, available) {
		paths = append(paths, target.FilePath(osName))
	}
	return paths
}

// sortSidecarsFirst installs rule and instruction sidecars before the
// consumers and hook registrations that reference them.
func sortSidecarsFirst(targets []platform.PolicyTarget) {
	sort.SliceStable(targets, func(i, j int) bool {
		rank := func(target platform.PolicyTarget) int {
			if strings.HasSuffix(target.BundleExt, ".instructions.md") || strings.Contains(target.BundleExt, ".policy.") {
				return 0
			}
			return 1
		}
		return rank(targets[i]) < rank(targets[j])
	})
}

func (a *Agent) installAssignment(snapshot, osName string, state *RoleState, assignment Assignment, available []platform.PolicyTarget) (AssignmentResult, error) {
	outcome := AssignmentResult{Assignment: assignment}
	targets := targetsFor(assignment.Agent, available)
	if err := a.preflightAssignment(snapshot, osName, assignment, targets); err != nil {
		outcome.State, outcome.Reason = "skipped", err.Error()
		return outcome, err
	}
	notes, err := ToolLevelNotes(snapshot, osName, ProfileAgent{assignment.Profile, assignment.Agent})
	if err != nil {
		outcome.State, outcome.Reason = "skipped", err.Error()
		return outcome, err
	}
	outcome.ToolLevelOnly = notes
	created, err := a.provider.PrepareTargetDirectories(targets)
	for _, dir := range created {
		if !slices.Contains(state.CreatedDirs, dir) {
			state.CreatedDirs = append(state.CreatedDirs, dir)
		}
	}
	if err != nil {
		outcome.State, outcome.Reason = "incomplete", err.Error()
		return outcome, err
	}
	sortSidecarsFirst(targets)
	for _, target := range targets {
		dest := target.FilePath(osName)
		source := filepath.Join(snapshot, "profiles", osName, assignment.Profile+"."+target.BundleExt)
		if err := a.copyOriginalIfForeign(state, osName, target, dest); err != nil {
			outcome.State, outcome.Reason = "incomplete", err.Error()
			return outcome, err
		}
		content, err := readRegularFile(source, maxMemberBytes)
		if err != nil {
			outcome.State, outcome.Reason = "incomplete", err.Error()
			return outcome, err
		}
		if err := a.provider.AtomicSwapAndLock(target, source); err != nil {
			outcome.State, outcome.Reason = "incomplete", fmt.Sprintf("install %s: %v", dest, err)
			return outcome, fmt.Errorf("install %s: %w", dest, err)
		}
		state.Installed[dest] = sha256Hex(content)
	}
	outcome.State = "installed"
	return outcome, nil
}

// preflightAssignment checks everything an agent needs before any of its
// files change. A failure skips only this agent. The source files were
// already checked by validateSnapshotV2, which always runs first.
func (a *Agent) preflightAssignment(snapshot, osName string, assignment Assignment, targets []platform.PolicyTarget) error {
	if len(targets) == 0 {
		return fmt.Errorf("no supported target for managed agent %q", assignment.Agent)
	}
	if slices.Contains(hookProducts, assignment.Agent) {
		validator, ok := a.provider.(platform.HookRuntimeValidator)
		if !ok {
			return fmt.Errorf("platform cannot validate the required hook executable")
		}
		if err := validator.ValidateHookRuntime(); err != nil {
			return err
		}
	}
	if assignment.Agent == "claude" && osName == "linux" {
		data, err := readRegularFile(filepath.Join(snapshot, "profiles", osName, assignment.Profile+".claude.json"), maxMemberBytes)
		if err != nil {
			return err
		}
		var settings struct {
			Sandbox *struct {
				FailIfUnavailable bool `json:"failIfUnavailable"`
			} `json:"sandbox"`
		}
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("read Claude settings: %w", err)
		}
		if settings.Sandbox != nil && settings.Sandbox.FailIfUnavailable {
			if err := a.claudeSandboxDeps(); err != nil {
				return err
			}
		}
	}
	return nil
}

// copyOriginalIfForeign saves a file AgentEdict did not write before it is
// first replaced. Files AgentEdict installed, including under version 1,
// match its install records or a retained snapshot and are not copied.
func (a *Agent) copyOriginalIfForeign(state *RoleState, osName string, target platform.PolicyTarget, dest string) error {
	if _, known := state.Installed[dest]; known {
		return nil
	}
	for _, original := range state.Originals {
		if original.Path == dest {
			return nil
		}
	}
	info, err := os.Lstat(dest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil // the swap refuses unsafe targets itself
	}
	data, err := readRegularFile(dest, maxOriginalBytes)
	if err != nil {
		return fmt.Errorf("read existing %s: %w", dest, err)
	}
	if a.matchesRetainedSnapshot(osName, target.BundleExt, data) {
		return nil
	}
	original, err := SaveOriginal(a.provider.VaultPath(), dest, data)
	if err != nil {
		return fmt.Errorf("save original %s: %w", dest, err)
	}
	state.Originals = append(state.Originals, original)
	return nil
}

func (a *Agent) matchesRetainedSnapshot(osName, bundleExt string, data []byte) bool {
	pattern := filepath.Join(a.provider.VaultPath(), "snapshots", "snapshot-*", "profiles", osName, "*."+bundleExt)
	matches, _ := filepath.Glob(pattern)
	for _, candidate := range matches {
		if existing, err := readRegularFile(candidate, maxMemberBytes); err == nil && bytes.Equal(existing, data) {
			return true
		}
	}
	return false
}

// agentsWithAgentEdictFiles lists agents with a target file whose bytes
// match a retained snapshot, which is how version 1 installs are recognized.
func (a *Agent) agentsWithAgentEdictFiles(osName string, available []platform.PolicyTarget) []string {
	var agents []string
	for _, target := range available {
		if slices.Contains(agents, target.AgentName) {
			continue
		}
		data, err := readRegularFile(target.FilePath(osName), maxMemberBytes)
		if err == nil && a.matchesRetainedSnapshot(osName, target.BundleExt, data) {
			agents = append(agents, target.AgentName)
		}
	}
	return agents
}

// releaseAgent takes an agent out of AgentEdict's hands: hook registrations
// first, a released policy for per-user hook products, then its other files
// and any empty directories AgentEdict created for it.
func (a *Agent) releaseAgent(state *RoleState, agent string, available []platform.PolicyTarget) error {
	remover, ok := a.provider.(platform.TargetRemover)
	if !ok {
		return fmt.Errorf("platform cannot remove managed files")
	}
	osName := a.provider.OSName()
	targets := targetsFor(agent, available)
	perUserHooks := agent == "antigravity" || agent == "cline"
	isReleasedPolicy := func(target platform.PolicyTarget) bool {
		return perUserHooks && strings.HasSuffix(target.BundleExt, ".policy.json")
	}
	for _, target := range targets {
		if target.Purpose != "hook-registration" {
			continue
		}
		if err := remover.RemoveManagedFile(target); err != nil {
			return err
		}
		delete(state.Installed, target.FilePath(osName))
	}
	for _, target := range targets {
		if !isReleasedPolicy(target) {
			continue
		}
		staged := filepath.Join(a.provider.VaultPath(), "released-policy.json")
		if err := writePrivateFile(a.provider.VaultPath(), "released-policy.json", hookjson.ReleasedPolicy); err != nil {
			return err
		}
		if err := a.provider.AtomicSwapAndLock(target, staged); err != nil {
			return fmt.Errorf("write released policy: %w", err)
		}
		state.Installed[target.FilePath(osName)] = sha256Hex(hookjson.ReleasedPolicy)
	}
	for _, target := range targets {
		if target.Purpose == "hook-registration" || isReleasedPolicy(target) {
			continue
		}
		if err := remover.RemoveManagedFile(target); err != nil {
			return err
		}
		delete(state.Installed, target.FilePath(osName))
	}
	for _, target := range targets {
		dir := target.DirPath(osName)
		if !slices.Contains(state.CreatedDirs, dir) {
			continue
		}
		if err := os.Remove(dir); err == nil {
			state.CreatedDirs = slices.DeleteFunc(state.CreatedDirs, func(d string) bool { return d == dir })
		}
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
