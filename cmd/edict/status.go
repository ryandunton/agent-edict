package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
)

// TargetReport encapsulates the security status of an individual AI coding agent configuration.
type TargetReport struct {
	AgentName      string `json:"agent_name"`
	DisplayName    string `json:"display_name"`
	TargetFile     string `json:"target_file"`
	FileExists     bool   `json:"file_exists"`
	IsLocked       bool   `json:"is_locked"`
	LockDetails    string `json:"lock_details"`
	ContentMatches bool   `json:"content_matches"`
	Status         string `json:"status"` // INSTALLED, DRIFT, UNLOCKED, MISSING, UNMANAGED, UNVERIFIED
	Profile        string `json:"profile"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
	ModTime        string `json:"mod_time,omitempty"`
	Purpose        string `json:"purpose,omitempty"`
}

// ComplianceReport represents the complete system compliance and agent status report.
type ComplianceReport struct {
	ManagedAgents        []string                    `json:"managed_agents"`
	UnsupportedAgents    map[string]string           `json:"unsupported_agents"`
	ScopeError           string                      `json:"scope_error,omitempty"`
	ConsumerVerification string                      `json:"consumer_verification"`
	NativeCapabilities   []compiler.NativeCapability `json:"native_capabilities,omitempty"`
	RegistrationStatus   string                      `json:"registration_status,omitempty"`
	SubsystemScope       string                      `json:"subsystem_scope"`
	Timestamp            string                      `json:"timestamp"`
	OS                   string                      `json:"os"`
	Arch                 string                      `json:"arch"`
	DaemonStatus         string                      `json:"daemon_status"`
	DaemonService        string                      `json:"daemon_service"`
	VaultPath            string                      `json:"vault_path"`
	VaultExists          bool                        `json:"vault_exists"`
	VaultReadable        bool                        `json:"vault_readable"`
	ElevatedRequired     bool                        `json:"elevated_required,omitempty"`
	ActiveUser           string                      `json:"active_user,omitempty"`
	ActiveUserSID        string                      `json:"active_user_sid,omitempty"`
	GroupsDetected       []string                    `json:"groups_detected,omitempty"`
	MatchedProfile       string                      `json:"matched_profile"`
	RulePriority         int                         `json:"rule_priority,omitempty"`
	RuleDesc             string                      `json:"rule_description,omitempty"`
	MatchedGroup         string                      `json:"matched_group,omitempty"`
	Targets              []TargetReport              `json:"targets"`
	OverallStatus        string                      `json:"overall_status"`
	SecureCount          int                         `json:"verified_file_count"`
	TotalTargets         int                         `json:"total_targets"`
	MapVersion           int                         `json:"map_version"`
	Assignments          []agent.AssignmentResult    `json:"assignments,omitempty"`
	ProvenAt             string                      `json:"proven_at,omitempty"`
	Proof                string                      `json:"proof,omitempty"`
	Users                []string                    `json:"users,omitempty"`
	SavedOriginals       []string                    `json:"saved_originals,omitempty"`
	ReleasedAgents       []string                    `json:"released_agents,omitempty"`
}

// Status lists other users only for administrators; tests replace these.
var (
	isElevated        = platform.IsElevated
	inspectTargetLock = func(osName string, filePath string, info os.FileInfo) (bool, string) {
		return platform.InspectPolicyLock(filePath)
	}
)

var agentDisplayNames = map[string]string{"codex": "OpenAI Codex", "claude": "Claude Code", "opencode": "OpenCode", "gemini": "Gemini CLI", "cursor": "Cursor", "antigravity": "Antigravity", "copilot": "GitHub Copilot", "kiro": "Kiro", "windsurf": "Windsurf / Devin Desktop", "cline": "Cline"}

// statusExitCode is 0 only when every required file is verified, so
// compliance tooling can detect incomplete or unverifiable machines.
func statusExitCode(r ComplianceReport) int {
	if strings.HasPrefix(r.OverallStatus, "FILES VERIFIED") {
		return 0
	}
	return 1
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output status report in structured JSON format")
	_ = fs.Parse(args)

	report := collectPolicyStatus(platform.NewProvider())
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		printHumanReport(report)
	}
	os.Exit(statusExitCode(report))
}

func collectPolicyStatus(provider platform.PlatformProvider) ComplianceReport {
	osName := provider.OSName()
	report := ComplianceReport{Timestamp: time.Now().UTC().Format(time.RFC3339), OS: osName, Arch: runtime.GOARCH, VaultPath: provider.VaultPath(), MatchedProfile: "unavailable", ConsumerVerification: "not_performed", SubsystemScope: "not_requested", UnsupportedAgents: map[string]string{}}
	report.DaemonService, report.DaemonStatus = checkDaemonStatus(osName)
	if _, err := os.Stat(provider.VaultPath()); err == nil {
		report.VaultExists = true
	}
	snapshot, err := agent.ActiveVaultPath(provider.VaultPath())
	var pm *agent.PolicyMap
	if err == nil {
		var bm *agent.BundleMap
		bm, err = agent.LoadBundleMap(snapshot)
		if err == nil && bm.V2 != nil {
			return collectV2Status(provider, report, snapshot, bm.V2)
		}
		if err == nil {
			pm = bm.V1
		}
	}
	report.MapVersion = 1
	// Identity is diagnostic only. It never selects a version 1 machine policy.
	if user, err := provider.GetActiveConsoleUser(); err == nil && user != nil {
		report.ActiveUser = user.Username
		report.ActiveUserSID = user.SID
		report.GroupsDetected = user.Groups
	}
	if err != nil {
		report.ScopeError = err.Error()
		report.ElevatedRequired = os.IsPermission(err)
	} else {
		report.VaultReadable = true
		report.MatchedProfile = pm.MachineProfile
		report.ManagedAgents = pm.ManagedAgents
		var nativeErr error
		report.NativeCapabilities, nativeErr = agent.NativeCapabilities(snapshot, osName, pm)
		if nativeErr != nil {
			report.ScopeError = nativeErr.Error()
		}
		var perUser []string
		for _, name := range []string{"antigravity", "cline"} {
			if slices.Contains(pm.ManagedAgents, name) {
				perUser = append(perUser, name)
			}
		}
		if len(perUser) > 0 {
			report.RegistrationStatus = strings.Join(perUser, " and ") + " require `edict install-hook <product>` per user; registration and client acceptance not verified"
		}
		selected, scopeErr := agent.SelectTargets(pm, provider.GetTargets())
		if scopeErr != nil {
			report.ScopeError = scopeErr.Error()
		} else {
			report.TotalTargets = len(selected)
		}
		if pm.SyncWSL && osName == "windows" {
			report.SubsystemScope = "active console user's distributions requested; copy status unverified; distro owner root is not contained"
		}
	}
	for _, target := range provider.GetTargets() {
		tr, info, statErr := newTargetReport(target, osName, report.MatchedProfile)
		file := tr.TargetFile
		if pm == nil {
			tr.Status = "UNVERIFIED"
			tr.LockDetails = "Signed machine scope unavailable"
			report.Targets = append(report.Targets, tr)
			continue
		}
		if !slices.Contains(pm.ManagedAgents, target.AgentName) {
			tr.Status = "UNMANAGED"
			tr.LockDetails = "Outside the signed managed_agents scope"
			report.Targets = append(report.Targets, tr)
			continue
		}
		if verifyTarget(&tr, osName, file, info, statErr, filepath.Join(snapshot, "profiles", osName, pm.MachineProfile+"."+target.BundleExt)) {
			report.SecureCount++
		}
		report.Targets = append(report.Targets, tr)
	}
	setOverallStatus(&report)
	return report
}

func newTargetReport(target platform.PolicyTarget, osName, profile string) (TargetReport, os.FileInfo, error) {
	file := target.FilePath(osName)
	tr := TargetReport{AgentName: target.AgentName, DisplayName: agentDisplayNames[target.AgentName], TargetFile: file, Profile: profile, Purpose: target.Purpose}
	if target.Purpose == "registration-template" {
		tr.DisplayName += " registration template"
	}
	if strings.HasSuffix(target.BundleExt, ".instructions.md") {
		tr.DisplayName += " instructions"
	}
	info, statErr := os.Lstat(file)
	if statErr == nil {
		tr.FileExists = true
		tr.SizeBytes = info.Size()
		tr.ModTime = info.ModTime().Format(time.RFC3339)
	}
	return tr, info, statErr
}

// verifyTarget compares an installed file with its snapshot source and lock
// state. It reports true only for an installed, matching, locked file.
func verifyTarget(tr *TargetReport, osName, file string, info os.FileInfo, statErr error, expected string) bool {
	if statErr != nil {
		tr.Status = "MISSING"
		tr.LockDetails = statErr.Error()
		return false
	}
	tr.IsLocked, tr.LockDetails = inspectTargetLock(osName, file, info)
	vaultBytes, vaultErr := os.ReadFile(expected)
	actual, actualErr := os.ReadFile(file)
	if vaultErr == nil && actualErr == nil {
		tr.ContentMatches = bytes.Equal(vaultBytes, actual)
	}
	switch {
	case vaultErr != nil || actualErr != nil:
		tr.Status = "UNVERIFIED"
		tr.LockDetails = "Required snapshot or installed file missing or unreadable"
	case !tr.ContentMatches:
		tr.Status = "DRIFT"
	case !tr.IsLocked:
		tr.Status = "UNLOCKED"
	default:
		tr.Status = "INSTALLED"
		return true
	}
	return false
}

func setOverallStatus(report *ComplianceReport) {
	switch {
	case report.ScopeError != "":
		report.OverallStatus = "UNVERIFIED: signed machine policy unavailable"
	case report.TotalTargets > 0 && report.SecureCount == report.TotalTargets:
		report.OverallStatus = fmt.Sprintf("FILES VERIFIED (%d/%d); consumer enforcement unverified", report.SecureCount, report.TotalTargets)
	default:
		report.OverallStatus = fmt.Sprintf("INCOMPLETE (%d/%d required files verified); consumer enforcement unverified", report.SecureCount, report.TotalTargets)
	}
}

// collectV2Status reports each managed agent's assigned profile from the
// vault's role state and verifies its files against that profile.
func collectV2Status(provider platform.PlatformProvider, report ComplianceReport, snapshot string, m *agent.PolicyMapV2) ComplianceReport {
	osName := provider.OSName()
	report.MapVersion = 2
	report.VaultReadable = true
	report.ManagedAgents = m.ManagedAgents
	report.MatchedProfile = "per agent (see assignments)"
	state, err := agent.LoadRoleState(provider.VaultPath())
	if err != nil {
		report.ScopeError = err.Error()
		report.ElevatedRequired = os.IsPermission(err)
		setOverallStatus(&report)
		return report
	}
	if state == nil {
		state = &agent.RoleState{}
	}
	assigned := map[string]agent.Assignment{}
	for _, assignment := range state.Assignments {
		assigned[assignment.Agent] = assignment
	}
	if state.ProvenAt.IsZero() {
		report.Proof = "cold_start"
	} else {
		report.Proof = "proven"
		report.ProvenAt = state.ProvenAt.Format(time.RFC3339)
	}
	if isElevated() {
		for _, user := range state.Users {
			report.Users = append(report.Users, user.Name)
		}
	}
	for _, original := range state.Originals {
		report.SavedOriginals = append(report.SavedOriginals, original.Path)
	}
	report.ReleasedAgents = state.Released
	var perUser []string
	for _, name := range []string{"antigravity", "cline"} {
		if slices.Contains(m.ManagedAgents, name) {
			perUser = append(perUser, name)
		}
	}
	if len(perUser) > 0 {
		report.RegistrationStatus = strings.Join(perUser, " and ") + " require `edict install-hook <product>` per user; registration and client acceptance not verified"
	}

	agentVerified := map[string]bool{}
	nativeByProfile := map[string][]string{}
	for _, name := range m.ManagedAgents {
		agentVerified[name] = true
	}
	for _, target := range provider.GetTargets() {
		assignment, ok := assigned[target.AgentName]
		tr, info, statErr := newTargetReport(target, osName, assignment.Profile)
		switch {
		case slices.Contains(state.Released, target.AgentName):
			tr.Status = "RELEASED"
			tr.LockDetails = "Dropped from managed_agents; AgentEdict removed or released its files"
		case !slices.Contains(m.ManagedAgents, target.AgentName):
			tr.Status = "UNMANAGED"
			tr.LockDetails = "Outside the signed managed_agents scope"
		case !ok:
			report.TotalTargets++
			agentVerified[target.AgentName] = false
			tr.Status = "UNVERIFIED"
			tr.LockDetails = "No assignment installed yet"
		default:
			report.TotalTargets++
			if verifyTarget(&tr, osName, tr.TargetFile, info, statErr, filepath.Join(snapshot, "profiles", osName, assignment.Profile+"."+target.BundleExt)) {
				report.SecureCount++
			} else {
				agentVerified[target.AgentName] = false
			}
		}
		report.Targets = append(report.Targets, tr)
	}
	for _, name := range m.ManagedAgents {
		assignment, ok := assigned[name]
		if !ok {
			report.Assignments = append(report.Assignments, agent.AssignmentResult{Assignment: agent.Assignment{Agent: name}, State: "not_installed"})
			continue
		}
		result := agent.AssignmentResult{Assignment: assignment, State: "installed"}
		if !agentVerified[name] {
			result.State = "incomplete"
		}
		notes, err := agent.ToolLevelNotes(snapshot, osName, agent.ProfileAgent{Profile: assignment.Profile, Agent: name})
		if err != nil {
			report.ScopeError = err.Error()
		}
		result.ToolLevelOnly = notes
		report.Assignments = append(report.Assignments, result)
		if compiler.IsNativeProduct(name) {
			nativeByProfile[assignment.Profile] = append(nativeByProfile[assignment.Profile], name)
		}
	}
	profiles := make([]string, 0, len(nativeByProfile))
	for profile := range nativeByProfile {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	for _, profile := range profiles {
		capabilities, err := agent.NativeCapabilitiesFor(snapshot, osName, profile, nativeByProfile[profile])
		if err != nil {
			report.ScopeError = err.Error()
		}
		report.NativeCapabilities = append(report.NativeCapabilities, capabilities...)
	}
	setOverallStatus(&report)
	return report
}

func checkDaemonStatus(osName string) (serviceName string, status string) {
	switch osName {
	case "windows":
		serviceName = "AgentEdictService (SCM)"
		out, err := exec.Command("sc.exe", "query", "AgentEdictService").Output()
		if err != nil {
			return serviceName, "Not Registered"
		}
		if strings.Contains(string(out), "RUNNING") {
			return serviceName, "● Active (Running)"
		}
		if strings.Contains(string(out), "STOPPED") {
			return serviceName, "○ Stopped"
		}
		return serviceName, "Unknown"

	case "linux":
		serviceName = "agent-edict.service (systemd)"
		out, err := exec.Command("systemctl", "is-active", "agent-edict.service").Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return serviceName, "● Active (Running)"
		}
		return serviceName, "○ Inactive / Stopped"

	case "darwin":
		serviceName = "io.github.ryandunton.agent-edict (launchd)"
		out, err := exec.Command("launchctl", "list", "io.github.ryandunton.agent-edict").Output()
		if err == nil && len(out) > 0 {
			return serviceName, "● Active (Running)"
		}
		return serviceName, "○ Inactive / Not Loaded"

	default:
		return "standalone", "Unknown"
	}
}

func printHumanReport(r ComplianceReport) {
	cyan := "\033[1;36m"
	green := "\033[1;32m"
	yellow := "\033[1;33m"
	red := "\033[1;31m"
	reset := "\033[0m"
	bold := "\033[1m"

	// If stdout is redirected or no color requested, strip formatting
	if !isTerminal() {
		cyan = ""
		green = ""
		yellow = ""
		red = ""
		reset = ""
		bold = ""
	}

	fmt.Println()
	fmt.Printf("%sAgentEdict Policy Installation Status%s\n", bold, reset)
	fmt.Println("================================================================================")
	fmt.Printf("%-20s %s (%s)\n", "Platform:", r.OS, r.Arch)
	daemonColor := green
	if !strings.Contains(r.DaemonStatus, "Active") {
		daemonColor = red
	}
	fmt.Printf("%-20s %s%s%s [%s]\n", "Daemon Status:", daemonColor, r.DaemonStatus, reset, r.DaemonService)
	fmt.Printf("%-20s %s\n", "Vault Path:", r.VaultPath)
	fmt.Println()

	if r.MapVersion == 2 {
		printRoleAssignments(r, bold, reset, cyan, yellow)
	} else {
		printConsoleIdentity(r, bold, reset, cyan, green, yellow)
	}

	fmt.Printf("%sMANAGED AGENT TARGETS%s\n", bold, reset)
	fmt.Println("--------------------------------------------------------------------------------")
	for _, t := range r.Targets {
		var badge string
		switch t.Status {
		case "INSTALLED":
			badge = fmt.Sprintf("%s[INSTALLED]%s", green, reset)
		case "LOCKED":
			badge = fmt.Sprintf("%s[LOCKED]%s", green, reset)
		case "DRIFT":
			badge = fmt.Sprintf("%s[DRIFT]%s", yellow, reset)
		case "UNLOCKED":
			badge = fmt.Sprintf("%s[UNLOCKED]%s", yellow, reset)
		case "MISSING":
			badge = fmt.Sprintf("%s[MISSING]%s", red, reset)
		default:
			badge = fmt.Sprintf("[%s]", t.Status)
		}

		fmt.Printf("  %-18s %s%s%s\n", badge, bold, t.DisplayName, reset)
		fmt.Printf("            Path:   %s\n", t.TargetFile)
		if t.FileExists {
			if t.Status == "UNMANAGED" || t.Status == "UNVERIFIED" {
				fmt.Printf("            State:  Present; %s\n", t.LockDetails)
			} else if t.Status == "LOCKED" {
				fmt.Printf("            State:  %sFile lock observed; content unverified%s\n", green, reset)
			} else if t.ContentMatches {
				fmt.Printf("            State:  %sInstalled bytes match %s%s\n", green, t.Profile, reset)
			} else {
				fmt.Printf("            State:  %sPolicy content does not match vault profile!%s\n", red, reset)
			}
			fmt.Printf("            Lock:   %s\n", t.LockDetails)
		} else {
			fmt.Printf("            State:  %sNot found on disk%s\n", red, reset)
		}
		fmt.Println()
	}

	fmt.Printf("Consumer runtime verification: %s\n", r.ConsumerVerification)
	if r.RegistrationStatus != "" {
		fmt.Printf("User registration: %s\n", r.RegistrationStatus)
	}
	for _, capability := range r.NativeCapabilities {
		fmt.Printf("%s.%s: %s — %s\n", capability.Product, capability.Control, capability.Level, capability.Details)
	}
	fmt.Printf("WSL scope: %s\n", r.SubsystemScope)
	for name, reason := range r.UnsupportedAgents {
		fmt.Printf("%s: %s\n", name, reason)
	}
	if r.ScopeError != "" {
		fmt.Printf("Scope error: %s\n", r.ScopeError)
	}
	complianceColor := green
	if r.SecureCount < r.TotalTargets {
		complianceColor = yellow
	}
	fmt.Printf("%sInstallation Status:%s %s%s%s\n", bold, reset, complianceColor, r.OverallStatus, reset)
	if r.ElevatedRequired {
		fmt.Printf("%sTip:%s Run with 'sudo edict status' (or Administrator prompt on Windows) to inspect the protected snapshot and compare installed bytes.\n", yellow, reset)
	}
	fmt.Println()
}

func isTerminal() bool {
	if fileInfo, err := os.Stdout.Stat(); err == nil && (fileInfo.Mode()&os.ModeCharDevice) != 0 {
		return true
	}
	return false
}

func printConsoleIdentity(r ComplianceReport, bold, reset, cyan, green, yellow string) {
	fmt.Printf("%sACTIVE CONSOLE IDENTITY (DIAGNOSTIC ONLY)%s\n", bold, reset)
	fmt.Println("--------------------------------------------------------------------------------")
	if r.ActiveUser != "" {
		fmt.Printf("%-20s %s\n", "Username:", r.ActiveUser)
		if r.ActiveUserSID != "" {
			fmt.Printf("%-20s %s\n", "User SID/UID:", r.ActiveUserSID)
		}
		if len(r.GroupsDetected) > 0 {
			displayGroups := strings.Join(r.GroupsDetected, ", ")
			if len(displayGroups) > 65 {
				displayGroups = displayGroups[:62] + "..."
			}
			fmt.Printf("%-20s %s\n", "Groups Detected:", displayGroups)
		}
	} else {
		fmt.Printf("%-20s %s(No interactive session detected; machine policy is unchanged)%s\n", "User Session:", yellow, reset)
	}
	fmt.Println()

	fmt.Printf("%sPOLICY EVALUATION%s\n", bold, reset)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("%-20s %s%s%s", "Machine Profile:", cyan, r.MatchedProfile, reset)
	if r.RulePriority > 0 {
		fmt.Printf(" (Rule Priority: %d)", r.RulePriority)
	}
	fmt.Println()
	if r.RuleDesc != "" {
		fmt.Printf("%-20s %s\n", "Rule Description:", r.RuleDesc)
	}
	if r.MatchedGroup != "" {
		fmt.Printf("%-20s %s%s%s (matched user group)\n", "Trigger Group:", green, r.MatchedGroup, reset)
	}
	fmt.Println()

}

func printRoleAssignments(r ComplianceReport, bold, reset, cyan, yellow string) {
	fmt.Printf("%sROLE ASSIGNMENTS (VERSION 2 MAP)%s\n", bold, reset)
	fmt.Println("--------------------------------------------------------------------------------")
	if r.ProvenAt != "" {
		fmt.Printf("%-20s %s\n", "Last proof:", r.ProvenAt)
	} else {
		fmt.Printf("%-20s %s(none yet; the standard policy applies until users are listed)%s\n", "Last proof:", yellow, reset)
	}
	if len(r.Users) > 0 {
		fmt.Printf("%-20s %s\n", "Users:", strings.Join(r.Users, ", "))
	}
	for _, a := range r.Assignments {
		if a.State == "not_installed" {
			fmt.Printf("  %-12s %snot installed yet%s\n", a.Agent, yellow, reset)
			continue
		}
		fmt.Printf("  %-12s %s%s%s (%s %d) %s\n", a.Agent, cyan, a.Profile, reset, a.Source, a.Priority, a.State)
		for _, setting := range a.ToolLevelOnly {
			fmt.Printf("               %s: %s is enforced in Claude's own tools only\n", a.Agent, setting)
		}
	}
	if len(r.ReleasedAgents) > 0 {
		fmt.Printf("%-20s %s\n", "Released agents:", strings.Join(r.ReleasedAgents, ", "))
	}
	if len(r.SavedOriginals) > 0 {
		fmt.Printf("%-20s %s\n", "Saved originals:", strings.Join(r.SavedOriginals, ", "))
	}
	fmt.Println()
}
