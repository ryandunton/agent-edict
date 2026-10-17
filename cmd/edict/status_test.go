package main

import (
	"github.com/ryandunton/agent-edict/internal/platform"
	"os"
	"path/filepath"
	"testing"
)

type statusProvider struct{ root string }

func (p statusProvider) OSName() string                 { return "linux" }
func (p statusProvider) BaseDir() string                { return p.root }
func (p statusProvider) VaultPath() string              { return filepath.Join(p.root, "vault") }
func (p statusProvider) EnsureSecureDirectories() error { return nil }
func (p statusProvider) GetActiveConsoleUser() (*platform.UserIdentity, error) {
	return &platform.UserIdentity{Username: "principal", Groups: []string{"administrators"}}, nil
}
func (p statusProvider) GetTargets() []platform.PolicyTarget {
	return []platform.PolicyTarget{{AgentName: "codex", BundleExt: "codex.toml", UnixFile: filepath.Join(p.root, "codex.toml")}, {AgentName: "claude", BundleExt: "claude.json", UnixFile: filepath.Join(p.root, "claude.json")}}
}
func (p statusProvider) AtomicSwapAndLock(platform.PolicyTarget, string) error        { return nil }
func (p statusProvider) SyncSubsystems(string, string, []platform.PolicyTarget) error { return nil }
func (p statusProvider) PrepareTargetDirectories([]platform.PolicyTarget) ([]string, error) {
	return nil, nil
}
func TestStatusDoesNotCallUninspectedFilesMissing(t *testing.T) {
	p := statusProvider{t.TempDir()}
	os.WriteFile(filepath.Join(p.root, "codex.toml"), []byte("present"), 0600)
	report := collectPolicyStatus(p)
	if !report.Targets[0].FileExists || report.Targets[0].Status != "UNVERIFIED" {
		t.Fatalf("unscoped existing file: %+v", report.Targets[0])
	}
	if report.SecureCount != 0 || report.ConsumerVerification != "not_performed" {
		t.Fatal("unsupported compliance claim")
	}
}
func TestStatusReportsMachineProfileAndUnmanagedFilePresence(t *testing.T) {
	p := statusProvider{t.TempDir()}
	snap := filepath.Join(p.VaultPath(), "snapshots", "snapshot-123")
	os.MkdirAll(snap, 0700)
	os.WriteFile(filepath.Join(p.VaultPath(), "active"), []byte("snapshot-123"), 0600)
	os.WriteFile(filepath.Join(snap, "policy-map.yaml"), []byte("version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n"), 0600)
	os.WriteFile(filepath.Join(p.root, "claude.json"), []byte("{}"), 0600)
	report := collectPolicyStatus(p)
	if report.MatchedProfile != "restricted" {
		t.Fatal("console identity selected machine policy")
	}
	if !report.Targets[1].FileExists || report.Targets[1].Status != "UNMANAGED" {
		t.Fatalf("unmanaged existing file: %+v", report.Targets[1])
	}
	if report.TotalTargets != 1 || len(report.UnsupportedAgents) != 0 {
		t.Fatal("incorrect supported scope")
	}
}
