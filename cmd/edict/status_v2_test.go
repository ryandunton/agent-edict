package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/platform"
)

// v2StatusFixture installs a compiled version 2 bundle as the active
// snapshot, records contractor assignments, and installs matching files.
func v2StatusFixture(t *testing.T, elevated bool) statusProvider {
	t.Helper()
	p := statusProvider{t.TempDir()}
	example, err := os.ReadFile(filepath.Join(exampleDir, "policy-map.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	mapText := strings.Replace(string(example), "managed_agents: [codex, claude, cursor]", "managed_agents: [codex, claude]", 1)
	snapshot := filepath.Join(p.VaultPath(), "snapshots", "snapshot-1")
	var out bytes.Buffer
	if err := compileBundleCommand([]string{"-map", writeMap(t, mapText), "-profiles-dir", filepath.Join(exampleDir, "profiles"), "-target-os", "linux", "-output-dir", snapshot}, &out); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(p.VaultPath(), "active"), []byte("snapshot-1\n"), 0600)
	state := &agent.RoleState{
		Version:  1,
		ProvenAt: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC),
		Users:    []platform.SessionUser{{Key: "1002", Name: "carl", Groups: []string{"contractors"}}},
		Assignments: []agent.Assignment{
			{Agent: "codex", Profile: "contractor-readonly", Priority: 10, Source: "rule", Users: []string{"carl"}},
			{Agent: "claude", Profile: "contractor-claude", Priority: 11, Source: "rule", Users: []string{"carl"}},
		},
		Installed: map[string]string{},
		Released:  []string{"cursor"},
	}
	if err := agent.SaveRoleState(p.VaultPath(), state); err != nil {
		t.Fatal(err)
	}
	for _, copy := range [][2]string{{"contractor-readonly.codex.toml", "codex.toml"}, {"contractor-claude.claude.json", "claude.json"}} {
		data, _ := os.ReadFile(filepath.Join(snapshot, "profiles", "linux", copy[0]))
		os.WriteFile(filepath.Join(p.root, copy[1]), data, 0644)
	}
	previousLock, previousElevated := inspectTargetLock, isElevated
	inspectTargetLock = func(string, string, os.FileInfo) (bool, string) { return true, "immutable" }
	isElevated = func() bool { return elevated }
	t.Cleanup(func() { inspectTargetLock, isElevated = previousLock, previousElevated })
	return p
}

func TestStatusV2ReportsPerAgentProfiles(t *testing.T) {
	report := collectPolicyStatus(v2StatusFixture(t, true))
	if report.ScopeError != "" || report.MapVersion != 2 {
		t.Fatalf("report = %+v", report)
	}
	for _, target := range report.Targets {
		want := map[string]string{"codex": "contractor-readonly", "claude": "contractor-claude"}[target.AgentName]
		if target.Profile != want || target.Status != "INSTALLED" {
			t.Errorf("%s target = %+v", target.AgentName, target)
		}
	}
	if !strings.HasPrefix(report.OverallStatus, "FILES VERIFIED") || statusExitCode(report) != 0 {
		t.Errorf("overall = %q", report.OverallStatus)
	}
	var claude agent.AssignmentResult
	for _, a := range report.Assignments {
		if a.Agent == "claude" {
			claude = a
		}
	}
	if claude.Profile != "contractor-claude" || claude.State != "installed" || len(claude.ToolLevelOnly) != 0 {
		t.Errorf("claude assignment = %+v", claude)
	}
	if !slices.Equal(report.ReleasedAgents, []string{"cursor"}) || report.ProvenAt == "" || report.ActiveUser != "" {
		t.Errorf("released=%v proven=%q console=%q", report.ReleasedAgents, report.ProvenAt, report.ActiveUser)
	}
}

func TestStatusV2DetectsDrift(t *testing.T) {
	p := v2StatusFixture(t, true)
	os.WriteFile(filepath.Join(p.root, "claude.json"), []byte(`{"edited":true}`), 0644)
	report := collectPolicyStatus(p)
	if !strings.HasPrefix(report.OverallStatus, "INCOMPLETE") || statusExitCode(report) != 1 {
		t.Fatalf("overall = %q", report.OverallStatus)
	}
}

func TestStatusHidesUsersUnlessElevated(t *testing.T) {
	if users := collectPolicyStatus(v2StatusFixture(t, false)).Users; len(users) != 0 {
		t.Fatalf("an unprivileged status listed users: %v", users)
	}
	if users := collectPolicyStatus(v2StatusFixture(t, true)).Users; !slices.Equal(users, []string{"carl"}) {
		t.Fatalf("users = %v", users)
	}
}

func TestStatusExitCode(t *testing.T) {
	for status, want := range map[string]int{
		"FILES VERIFIED (2/2); consumer enforcement unverified":                     0,
		"INCOMPLETE (1/2 required files verified); consumer enforcement unverified": 1,
		"UNVERIFIED: signed machine policy unavailable":                             1,
	} {
		if got := statusExitCode(ComplianceReport{OverallStatus: status}); got != want {
			t.Errorf("%q -> %d, want %d", status, got, want)
		}
	}
}

func TestSyncOnceV2Lines(t *testing.T) {
	var out bytes.Buffer
	writeV2Result(&out, agent.EnforcementResult{MapVersion: 2, Proof: "fresh", Released: []string{"cursor"}, Assignments: []agent.AssignmentResult{
		{Assignment: agent.Assignment{Agent: "codex", Profile: "contractor-readonly", Priority: 10, Source: "rule"}, State: "installed"},
		{Assignment: agent.Assignment{Agent: "claude", Profile: "standard", Priority: 100, Source: "standard"}, State: "skipped", Reason: "Claude sandbox needs bubblewrap installed", ToolLevelOnly: []string{"filesystem.deny_read"}},
	}})
	for _, want := range []string{
		"codex: contractor-readonly (rule 10) installed",
		"claude: standard (standard 100) skipped: Claude sandbox needs bubblewrap installed",
		"claude: filesystem.deny_read is enforced in Claude's own tools only",
		"released: cursor",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestHumanStatusShowsRoleAssignments(t *testing.T) {
	report := collectPolicyStatus(v2StatusFixture(t, true))
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = write
	printHumanReport(report)
	os.Stdout = stdout
	write.Close()
	var out bytes.Buffer
	out.ReadFrom(read)
	for _, want := range []string{"ROLE ASSIGNMENTS (VERSION 2 MAP)", "contractor-claude", "Released agents:", "carl"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "ACTIVE CONSOLE IDENTITY") {
		t.Error("version 2 status must not present the console user as the policy source")
	}
}
