package agent

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
)

type antigravityIntegrationProvider struct{ nativeIntegrationProvider }

func (p *antigravityIntegrationProvider) GetTargets() []platform.PolicyTarget {
	var targets []platform.PolicyTarget
	for _, target := range platform.DefaultPolicyTargets() {
		if target.AgentName != "antigravity" {
			continue
		}
		dir := filepath.Join(p.root, "targets")
		filename := filepath.Join(dir, target.BundleExt)
		target.WindowsDir, target.UnixDir, target.DarwinDir = dir, dir, dir
		target.WindowsFile, target.UnixFile, target.DarwinFile = filename, filename, filename
		targets = append(targets, target)
	}
	return targets
}

func TestAntigravitySignedMachineRulesDoNotClaimUserEnrollment(t *testing.T) {
	declaration := "version: 1\nname: workstation\nantigravity:\n  hooks:\n    version: 1\n    tools:\n      ask_question: allow\n"
	for _, osName := range []string{"linux", "darwin", "windows"} {
		t.Run(osName, func(t *testing.T) {
			a, base, key := newTestAgent(t)
			base.osName = osName
			provider := &antigravityIntegrationProvider{nativeIntegrationProvider{testProvider: base, artifactData: map[string]string{}}}
			a.provider = provider
			p, err := compiler.DecodeNativePolicy([]byte(declaration))
			if err != nil {
				t.Fatal(err)
			}
			out, err := compiler.CompileNative(p, osName, "antigravity")
			if err != nil {
				t.Fatal(err)
			}
			prefix := "profiles/" + osName + "/workstation."
			entries := []archiveEntry{{name: "policy-map.yaml", body: "version: 1\nmachine_profile: workstation\nmanaged_agents: [antigravity]\n"}, {name: prefix + "native.yaml", body: declaration}}
			for _, artifact := range out.Artifacts {
				entries = append(entries, archiveEntry{name: prefix + artifact.Extension, body: artifact.Content})
			}
			body := archiveBytes(t, entries...)
			serveBundle(t, a, key, &body)
			result, err := a.SyncAndEnforce()
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Installed) != 2 || provider.identityCalls != 0 || !strings.Contains(result.RegistrationStatus, "per_user") || result.ConsumerVerification != "not_performed" {
				t.Fatalf("incorrect enrollment claim: %+v", result)
			}
			if len(result.NativeCapabilities) == 0 {
				t.Fatal("capability limits missing")
			}
			if provider.order[0] != "antigravity.policy.json" {
				t.Fatal("registration precedes protected rules")
			}
			for _, name := range result.Installed {
				if strings.Contains(name, ".gemini") {
					t.Fatal("privileged install unexpectedly wrote a user hook")
				}
			}
		})
	}
}
