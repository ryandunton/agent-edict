package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const designExampleMap = `version: 2
managed_agents: [codex, claude, cursor]
sync_wsl: false
standard:
  profile: standard
  priority: 100
rules:
  - priority: 10
    profile: contractor-readonly
    agents: [codex]
    match_groups:
      windows: ['S-1-5-21-1111111111-2222222222-3333333333-1104', 'entra:3f2a8c1e-5b7d-4e2a-9c1f-0a1b2c3d4e5f', '.\Contractors']
      linux: [contractors]
      darwin: [contractors]
  - priority: 11
    profile: contractor-claude
    agents: [claude]
    match_groups:
      windows: ['S-1-5-21-1111111111-2222222222-3333333333-1104', '.\Contractors']
      linux: [contractors]
      darwin: [contractors]
  - priority: 20
    profile: engineering
    agents: [all]
    match_groups:
      windows: ['CORP\SG-Engineers']
      linux: [engineers]
      darwin: [engineers]
`

func TestParsePolicyMapV2AcceptsDesignExample(t *testing.T) {
	m, err := ParsePolicyMapV2([]byte(designExampleMap))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Rules[2].Agents; !slices.Equal(got, []string{"codex", "claude", "cursor"}) {
		t.Errorf("[all] expanded to %v", got)
	}
	if !slices.Contains(m.Rules[0].MatchGroups["windows"], "S-1-12-1-1059752990-1311398781-453648284-1598962988") {
		t.Errorf("entra group not converted: %v", m.Rules[0].MatchGroups["windows"])
	}
	want := []ProfileAgent{
		{"contractor-claude", "claude"}, {"contractor-readonly", "codex"},
		{"engineering", "claude"}, {"engineering", "codex"}, {"engineering", "cursor"},
		{"standard", "claude"}, {"standard", "codex"}, {"standard", "cursor"},
	}
	if got := m.Pairs(); !reflect.DeepEqual(got, want) {
		t.Errorf("Pairs() = %v", got)
	}
	if !m.UsesWindowsNames() {
		t.Error("CORP\\SG-Engineers is a name-based Windows rule")
	}
}

func TestUsesWindowsNamesIgnoresSIDsAndLocalGroups(t *testing.T) {
	m, err := ParsePolicyMapV2([]byte(strings.Replace(designExampleMap, `'CORP\SG-Engineers'`, `'S-1-5-21-1-2-3-1107'`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if m.UsesWindowsNames() {
		t.Error("SIDs, entra IDs and .\\Name never need SID-to-name translation")
	}
}

func TestParsePolicyMapV2Rejects(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(designExampleMap, old) {
			t.Fatalf("fixture text %q not found", old)
		}
		return strings.Replace(designExampleMap, old, new, 1)
	}
	for _, c := range []struct{ name, body, want string }{
		{"empty managed", replace("managed_agents: [codex, claude, cursor]", "managed_agents: []"), "managed_agents"},
		{"all in managed", replace("managed_agents: [codex, claude, cursor]", "managed_agents: [all]"), "managed_agents"},
		{"duplicate managed", replace("managed_agents: [codex, claude, cursor]", "managed_agents: [codex, codex]"), "duplicate"},
		{"unsupported managed", replace("managed_agents: [codex, claude, cursor]", "managed_agents: [codex, emacs]"), "unsupported"},
		{"missing standard", replace("standard:\n  profile: standard\n  priority: 100\n", ""), "standard"},
		{"unsafe standard", replace("profile: standard", "profile: ../standard"), "profile"},
		{"unsafe rule profile", replace("profile: engineering", "profile: eng/ineering"), "profile"},
		{"empty agents", replace("agents: [codex]", "agents: []"), "agents"},
		{"mixed all", replace("agents: [all]", "agents: [all, codex]"), "all"},
		{"agent not managed", replace("agents: [codex]", "agents: [opencode]"), "managed_agents"},
		{"duplicate priority", replace("priority: 11", "priority: 10"), "priority"},
		{"missing standard priority", replace("  profile: standard\n  priority: 100\n", "  profile: standard\n"), "standard priority must be 1 or higher"},
		{"zero rule priority", replace("priority: 20", "priority: 0"), "priority must be 1 or higher"},
		{"negative rule priority", replace("priority: 20", "priority: -5"), "priority must be 1 or higher"},
		{"priority equals standard", replace("priority: 20", "priority: 100"), "priority"},
		{"empty match groups", replace("    match_groups:\n      windows: ['CORP\\SG-Engineers']\n      linux: [engineers]\n      darwin: [engineers]\n", "    match_groups: {}\n"), "match_groups"},
		{"bad os key", replace("      linux: [engineers]", "      solaris: [engineers]"), "solaris"},
		{"empty group", replace("linux: [engineers]", "linux: ['']"), "empty"},
		{"bare windows name", replace(`'CORP\SG-Engineers'`, `'SG-Engineers'`), "windows group"},
		{"bad entra id", replace("entra:3f2a8c1e-5b7d-4e2a-9c1f-0a1b2c3d4e5f", "entra:nope"), "entra"},
		{"sync_wsl", replace("sync_wsl: false", "sync_wsl: true"), "sync_wsl is not supported with version 2"},
		{"unknown field", replace("sync_wsl: false", "sync_wsl: false\nmachine_profile: legacy"), "machine_profile"},
		{"two documents", designExampleMap + "---\nversion: 2\n", "exactly one"},
		{"wrong version", replace("version: 2", "version: 3"), "version 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePolicyMapV2([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestEntraObjectIDToSID(t *testing.T) {
	sid, err := EntraObjectIDToSID("3f2a8c1e-5b7d-4e2a-9c1f-0a1b2c3d4e5f")
	if err != nil || sid != "S-1-12-1-1059752990-1311398781-453648284-1598962988" {
		t.Fatalf("EntraObjectIDToSID = %q, %v", sid, err)
	}
	if _, err := EntraObjectIDToSID("not-a-guid"); err == nil {
		t.Fatal("invalid object ID accepted")
	}
}

func TestLoadBundleMapDispatchesByVersion(t *testing.T) {
	v1 := t.TempDir()
	os.WriteFile(filepath.Join(v1, "policy-map.yaml"), []byte("version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n"), 0600)
	got, err := LoadBundleMap(v1)
	if err != nil || got.V1 == nil || got.V2 != nil {
		t.Fatalf("v1 LoadBundleMap = %+v, %v", got, err)
	}
	v2 := t.TempDir()
	os.WriteFile(filepath.Join(v2, "policy-map.yaml"), []byte(designExampleMap), 0600)
	got, err = LoadBundleMap(v2)
	if err != nil || got.V2 == nil || got.V1 != nil {
		t.Fatalf("v2 LoadBundleMap = %+v, %v", got, err)
	}
	if _, err := LoadPolicyMap(v2); err == nil || !strings.Contains(err.Error(), "use LoadBundleMap") {
		t.Fatalf("LoadPolicyMap on a v2 map = %v", err)
	}
}
