package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var allOS = []string{"windows", "linux", "darwin"}

func TestValidateBundleV2AcceptsCompleteBundle(t *testing.T) {
	dir := writeV2Snapshot(t, exampleMapText(t), allOS...)
	for _, osName := range allOS {
		if err := ValidateBundleDirectory(dir, osName); err != nil {
			t.Errorf("%s: %v", osName, err)
		}
	}
}

// No CI identity matches the engineering rule, but a machine could select it
// later, so its files are required before signing.
func TestValidateBundleV2RejectsMissingDormantRuleFile(t *testing.T) {
	dir := writeV2Snapshot(t, exampleMapText(t), allOS...)
	if err := os.Remove(filepath.Join(dir, "profiles", "linux", "engineering.claude.json")); err != nil {
		t.Fatal(err)
	}
	err := ValidateBundleDirectory(dir, "linux")
	if err == nil || !strings.Contains(err.Error(), "engineering") || !strings.Contains(err.Error(), "claude.json") {
		t.Fatalf("error = %v", err)
	}
	if err := ValidateBundleDirectory(dir, "darwin"); err != nil {
		t.Fatalf("darwin files are intact: %v", err)
	}
}

func TestValidateBundleV2RejectsChangedNativeArtifact(t *testing.T) {
	dir := writeV2Snapshot(t, exampleMapText(t), allOS...)
	artifact := filepath.Join(dir, "profiles", "windows", "engineering.cursor.policy.json")
	if err := os.WriteFile(artifact, []byte(`{"version":1,"tools_allow":["*"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundleDirectory(dir, "windows"); err == nil || !strings.Contains(err.Error(), "cursor.policy.json") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBundleV2RejectsDeclarationNameMismatch(t *testing.T) {
	dir := writeV2Snapshot(t, exampleMapText(t), allOS...)
	declaration := filepath.Join(dir, "profiles", "linux", "standard.native.yaml")
	data, _ := os.ReadFile(declaration)
	if err := os.WriteFile(declaration, []byte(strings.Replace(string(data), "name: standard", "name: engineering", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundleDirectory(dir, "linux"); err == nil || !strings.Contains(err.Error(), "differs from profile") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBundleV2RejectsMalformedNotes(t *testing.T) {
	dir := writeV2Snapshot(t, exampleMapText(t), allOS...)
	notes := filepath.Join(dir, "profiles", "windows", "standard.claude.notes.json")
	if err := os.WriteFile(notes, []byte(`{"tool_level_only":"everything"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundleDirectory(dir, "windows"); err == nil || !strings.Contains(err.Error(), "notes") {
		t.Fatalf("error = %v", err)
	}
}
