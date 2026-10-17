package agent

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
)

const nativeIntegrationDeclaration = `version: 1
name: workstation
gemini:
  default_decision: deny
  rules:
    - tool_name: read_file
      decision: allow
      priority: 100
cursor:
  hooks:
    version: 1
    shell:
      allow: [git status]
      ask: []
      deny: []
    mcp: []
`

const nativeIntegrationMap = "version: 1\nmachine_profile: workstation\nmanaged_agents: [gemini, cursor]\n"

func nativeIntegrationEntries(t *testing.T, osName string) ([]archiveEntry, *compiler.NativeOutput) {
	t.Helper()
	p, err := compiler.DecodeNativePolicy([]byte(nativeIntegrationDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	out, err := compiler.CompileNative(p, osName, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Artifacts) != 4 {
		t.Fatalf("fixture requires exactly two native files per product, got %d", len(out.Artifacts))
	}
	prefix := "profiles/" + osName + "/workstation."
	entries := []archiveEntry{
		{name: "policy-map.yaml", body: nativeIntegrationMap},
		{name: prefix + "native.yaml", body: nativeIntegrationDeclaration},
	}
	for _, artifact := range out.Artifacts {
		entries = append(entries, archiveEntry{name: prefix + artifact.Extension, body: artifact.Content})
	}
	return entries, out
}

func writeNativeIntegrationSnapshot(t *testing.T, entries []archiveEntry) string {
	t.Helper()
	dir := t.TempDir()
	for _, entry := range entries {
		name := filepath.Join(dir, filepath.FromSlash(entry.name))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(entry.body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestNativeBundleDirectoryValidatesEveryTargetOS(t *testing.T) {
	for _, osName := range []string{"linux", "darwin", "windows"} {
		t.Run(osName, func(t *testing.T) {
			entries, out := nativeIntegrationEntries(t, osName)
			dir := writeNativeIntegrationSnapshot(t, entries)
			if err := ValidateBundleDirectory(dir, osName); err != nil {
				t.Fatalf("complete native bundle rejected: %v", err)
			}
			pm, err := LoadPolicyMap(dir)
			if err != nil {
				t.Fatal(err)
			}
			caps, err := NativeCapabilities(dir, osName, pm)
			if err != nil || !reflect.DeepEqual(caps, out.Capabilities) {
				t.Fatalf("native capability regeneration disagrees with compiler: %#v, %v", caps, err)
			}
			targets, err := SelectTargets(pm, platform.DefaultPolicyTargets())
			if err != nil || len(targets) != 4 {
				t.Fatalf("native target scope lost a required file: %#v, %v", targets, err)
			}
			for _, artifact := range out.Artifacts {
				found := false
				for _, target := range targets {
					if target.BundleExt == artifact.Extension {
						found = true
						if target.FilePath(osName) != artifact.Destination {
							t.Errorf("compiler/endpoint destination mismatch for %s: %q != %q", artifact.Extension, target.FilePath(osName), artifact.Destination)
						}
					}
				}
				if !found {
					t.Errorf("no endpoint target for %s", artifact.Extension)
				}
			}
		})
	}
}

func TestNativeBundleRejectsMissingOrChangedDeclarationAndArtifacts(t *testing.T) {
	for _, osName := range []string{"linux", "darwin", "windows"} {
		t.Run(osName, func(t *testing.T) {
			entries, out := nativeIntegrationEntries(t, osName)
			prefix := "profiles/" + osName + "/workstation."
			type mutation struct {
				name, filename, replacement string
				remove                      bool
			}
			cases := []mutation{
				{name: "missing declaration", filename: prefix + "native.yaml", remove: true},
				{name: "declaration name differs", filename: prefix + "native.yaml", replacement: strings.Replace(nativeIntegrationDeclaration, "name: workstation", "name: different", 1)},
				{name: "missing selected product", filename: prefix + "native.yaml", replacement: strings.Split(nativeIntegrationDeclaration, "cursor:")[0]},
				{name: "unknown declaration control", filename: prefix + "native.yaml", replacement: nativeIntegrationDeclaration + "invented_security_boundary: true\n"},
			}
			for _, artifact := range out.Artifacts {
				cases = append(cases,
					mutation{name: "missing " + artifact.Extension, filename: prefix + artifact.Extension, remove: true},
					mutation{name: "modified " + artifact.Extension, filename: prefix + artifact.Extension, replacement: artifact.Content + "\n"},
				)
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					dir := writeNativeIntegrationSnapshot(t, entries)
					filename := filepath.Join(dir, filepath.FromSlash(tc.filename))
					var err error
					if tc.remove {
						err = os.Remove(filename)
					} else {
						err = os.WriteFile(filename, []byte(tc.replacement), 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					if err := ValidateBundleDirectory(dir, osName); err == nil {
						t.Fatal("incomplete or mismatched native contract accepted")
					}
				})
			}
		})
	}
}

type nativeIntegrationProvider struct {
	*testProvider
	order        []string
	hookChecks   int
	hookError    error
	artifactData map[string]string
}

func (p *nativeIntegrationProvider) GetTargets() []platform.PolicyTarget {
	var targets []platform.PolicyTarget
	for _, target := range platform.DefaultPolicyTargets() {
		if target.AgentName != "gemini" && target.AgentName != "cursor" {
			continue
		}
		// Real target metadata and required files, with harmless temporary paths.
		dir := filepath.Join(p.root, "targets")
		filename := filepath.Join(dir, target.BundleExt)
		target.WindowsDir, target.UnixDir, target.DarwinDir = dir, dir, dir
		target.WindowsFile, target.UnixFile, target.DarwinFile = filename, filename, filename
		targets = append(targets, target)
	}
	// Force the agent to establish sidecar ordering, rather than relying on the
	// provider's declaration order happening to be safe.
	slices.Reverse(targets)
	return targets
}

func (p *nativeIntegrationProvider) AtomicSwapAndLock(target platform.PolicyTarget, source string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	p.order = append(p.order, target.BundleExt)
	p.artifactData[target.BundleExt] = string(data)
	return nil
}

func (p *nativeIntegrationProvider) ValidateHookRuntime() error {
	p.hookChecks++
	return p.hookError
}

func TestNativeSignedBundleActivatesAndInstallsAllFiles(t *testing.T) {
	for _, osName := range []string{"linux", "darwin", "windows"} {
		t.Run(osName, func(t *testing.T) {
			a, base, key := newTestAgent(t)
			base.osName = osName
			provider := &nativeIntegrationProvider{testProvider: base, artifactData: map[string]string{}}
			a.provider = provider
			entries, out := nativeIntegrationEntries(t, osName)
			body := archiveBytes(t, entries...)
			serveBundle(t, a, key, &body)
			result, err := a.SyncAndEnforce()
			if err != nil {
				t.Fatal(err)
			}
			active, err := ActiveVaultPath(provider.VaultPath())
			if err != nil || result.Snapshot != filepath.Base(active) {
				t.Fatalf("signed snapshot was not activated: %#v, %v", result, err)
			}
			if len(result.Installed) != 4 || len(provider.artifactData) != 4 || result.Profile != "workstation" || !reflect.DeepEqual(result.ManagedAgents, []string{"gemini", "cursor"}) {
				t.Fatalf("native deployment incomplete: %#v; files=%#v", result, provider.artifactData)
			}
			if !reflect.DeepEqual(result.NativeCapabilities, out.Capabilities) || result.ConsumerVerification != "not_performed" {
				t.Fatalf("incorrect native capability or consumer-verification claims: %#v", result)
			}
			for _, artifact := range out.Artifacts {
				if provider.artifactData[artifact.Extension] != artifact.Content {
					t.Errorf("installed bytes differ for %s", artifact.Extension)
				}
			}
			for _, pair := range [][2]string{{"gemini.policy.toml", "gemini.json"}, {"cursor.policy.json", "cursor.hooks.json"}} {
				if slices.Index(provider.order, pair[0]) >= slices.Index(provider.order, pair[1]) {
					t.Errorf("sidecar %s installed after its consumer: %v", pair[0], provider.order)
				}
			}
			if provider.hookChecks == 0 {
				t.Error("hook executable was not preflighted")
			}
			if provider.identityCalls != 0 {
				t.Error("native machine policy unexpectedly consulted console identity")
			}
		})
	}
}

func TestNativeSignedButMismatchedArtifactIsRejectedBeforeActivation(t *testing.T) {
	a, base, key := newTestAgent(t)
	provider := &nativeIntegrationProvider{testProvider: base, artifactData: map[string]string{}}
	a.provider = provider
	entries, _ := nativeIntegrationEntries(t, "linux")
	for i := range entries {
		if strings.HasSuffix(entries[i].name, ".cursor.hooks.json") {
			entries[i].body = `{"version":1,"hooks":{}}`
		}
	}
	body := archiveBytes(t, entries...)
	serveBundle(t, a, key, &body)
	result, err := a.SyncAndEnforce()
	if err == nil || !strings.Contains(result.SyncError, "does not match") {
		t.Fatalf("valid signature incorrectly bypassed declaration contract: %#v, %v", result, err)
	}
	if len(provider.order) != 0 || len(result.Installed) != 0 {
		t.Fatal("rejected bundle modified endpoint files")
	}
	if _, err := ActiveVaultPath(provider.VaultPath()); err == nil {
		t.Fatal("rejected bundle activated a snapshot")
	}
}

func TestNativeSignedScopeInstallsOnlyDeclaredProduct(t *testing.T) {
	for _, product := range []string{"gemini", "cursor"} {
		t.Run(product, func(t *testing.T) {
			a, base, key := newTestAgent(t)
			provider := &nativeIntegrationProvider{testProvider: base, artifactData: map[string]string{}}
			a.provider = provider
			entries, _ := nativeIntegrationEntries(t, "linux")
			entries[0].body = strings.Replace(nativeIntegrationMap, "[gemini, cursor]", "["+product+"]", 1)
			body := archiveBytes(t, entries...)
			serveBundle(t, a, key, &body)
			result, err := a.SyncAndEnforce()
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Installed) != 2 || len(provider.artifactData) != 2 {
				t.Fatalf("selected native product must install exactly two files: %#v", result)
			}
			for extension := range provider.artifactData {
				if !strings.HasPrefix(extension, product+".") {
					t.Errorf("undeclared product installed: %s", extension)
				}
			}
			for _, capability := range result.NativeCapabilities {
				if capability.Product != product {
					t.Errorf("undeclared product capability reported: %#v", capability)
				}
			}
			if product == "gemini" && provider.hookChecks != 0 {
				t.Error("Gemini-only deployment unexpectedly requires the Cursor hook executable")
			}
		})
	}
}

func TestNativeHookRuntimeFailurePreventsTargetWrites(t *testing.T) {
	a, base, key := newTestAgent(t)
	provider := &nativeIntegrationProvider{testProvider: base, artifactData: map[string]string{}, hookError: errors.New("untrusted hook executable")}
	a.provider = provider
	entries, _ := nativeIntegrationEntries(t, "linux")
	body := archiveBytes(t, entries...)
	serveBundle(t, a, key, &body)
	result, err := a.SyncAndEnforce()
	if err == nil || !strings.Contains(err.Error(), "untrusted hook executable") {
		t.Fatalf("unsafe hook dependency did not fail enforcement: %#v, %v", result, err)
	}
	if len(provider.order) != 0 || len(result.Installed) != 0 {
		t.Fatal("hook runtime failure occurred after target writes")
	}
}

func TestMissingHookRuntimePreservesUsableActiveSnapshot(t *testing.T) {
	a, base, key := newTestAgent(t)
	provider := &nativeIntegrationProvider{testProvider: base, artifactData: map[string]string{}}
	a.provider = provider
	entries, _ := nativeIntegrationEntries(t, "linux")
	entries[0].body = strings.Replace(nativeIntegrationMap, "[gemini, cursor]", "[gemini]", 1)
	body := archiveBytes(t, entries...)
	serveBundle(t, a, key, &body)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	previous, err := ActiveVaultPath(provider.VaultPath())
	if err != nil {
		t.Fatal(err)
	}
	provider.hookError = errors.New("required evaluator is not installed")
	entries[0].body = nativeIntegrationMap
	body = archiveBytes(t, entries...)
	for i := 0; i < 3; i++ {
		result, err := a.SyncAndEnforce()
		if err != nil || result.SyncError == "" {
			t.Fatalf("expected rejected update with usable prior policy: %+v, %v", result, err)
		}
		active, err := ActiveVaultPath(provider.VaultPath())
		if err != nil || active != previous {
			t.Fatalf("unusable update replaced active snapshot: %s, %v", active, err)
		}
		if len(result.ManagedAgents) != 1 || result.ManagedAgents[0] != "gemini" {
			t.Fatalf("wrong fallback scope: %+v", result)
		}
	}
}

const extendedNativeDeclaration = `version: 1
name: workstation
copilot:
  permissions:
    deny: ["Shell(rm -rf *)"]
  mcp:
    allowed: []
kiro:
  rules:
    - capability: shell
      match: ["sudo *"]
      effect: deny
windsurf:
  hooks:
    version: 1
    commands: [git status]
cline:
  hooks:
    version: 1
    tools: {read_files: allow}
`

// destinationProvider records installs by their real destination path, so two
// targets sharing one bundle file (Windsurf's hook locations) stay distinct.
type destinationProvider struct {
	*testProvider
	installed  map[string]string
	order      []string
	hookChecks int
}

func (p *destinationProvider) GetTargets() []platform.PolicyTarget {
	return platform.DefaultPolicyTargets()
}

func (p *destinationProvider) AtomicSwapAndLock(target platform.PolicyTarget, source string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	path := target.FilePath(p.OSName())
	p.installed[path] = string(data)
	p.order = append(p.order, path)
	return nil
}

func (p *destinationProvider) ValidateHookRuntime() error {
	p.hookChecks++
	return nil
}

func extendedNativeEntries(t *testing.T, osName string) []archiveEntry {
	t.Helper()
	p, err := compiler.DecodeNativePolicy([]byte(extendedNativeDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	out, err := compiler.CompileNative(p, osName, "all")
	if err != nil {
		t.Fatal(err)
	}
	prefix := "profiles/" + osName + "/workstation."
	entries := []archiveEntry{
		{name: "policy-map.yaml", body: "version: 1\nmachine_profile: workstation\nmanaged_agents: [copilot, kiro, windsurf, cline]\n"},
		{name: prefix + "native.yaml", body: extendedNativeDeclaration},
	}
	for _, artifact := range out.Artifacts {
		entries = append(entries, archiveEntry{name: prefix + artifact.Extension, body: artifact.Content})
	}
	return entries
}

func TestExtendedNativeProductsInstallAtDocumentedDestinations(t *testing.T) {
	want := map[string][]string{
		"linux":   {"/etc/github-copilot/managed-settings.json", "/etc/kiro/managed-settings.json", "/etc/agent-edict/windsurf-policy.json", "/etc/devin/hooks.json", "/etc/windsurf/hooks.json", "/etc/agent-edict/cline-policy.json"},
		"darwin":  {"/Library/Application Support/GitHubCopilot/managed-settings.json", "/Library/Application Support/Kiro/managed-settings.json", "/etc/agent-edict/windsurf-policy.json", "/Library/Application Support/Devin/hooks.json", "/Library/Application Support/Windsurf/hooks.json", "/etc/agent-edict/cline-policy.json"},
		"windows": {`C:\Program Files\GitHubCopilot\managed-settings.json`, `C:\ProgramData\Kiro\managed-settings.json`, `C:\ProgramData\AgentEdict\windsurf-policy.json`, `C:\ProgramData\Devin\hooks.json`, `C:\ProgramData\Windsurf\hooks.json`, `C:\ProgramData\AgentEdict\cline-policy.json`},
	}
	for osName, paths := range want {
		t.Run(osName, func(t *testing.T) {
			a, base, key := newTestAgent(t)
			base.osName = osName
			provider := &destinationProvider{testProvider: base, installed: map[string]string{}}
			a.provider = provider
			body := archiveBytes(t, extendedNativeEntries(t, osName)...)
			serveBundle(t, a, key, &body)
			result, err := a.SyncAndEnforce()
			if err != nil {
				t.Fatal(err)
			}
			if len(provider.installed) != len(paths) {
				t.Fatalf("installed %v, want %v", provider.order, paths)
			}
			for _, path := range paths {
				if provider.installed[path] == "" {
					t.Errorf("missing %s", path)
				}
			}
			// Both Cascade locations receive the same hook registration.
			if provider.installed[paths[3]] != provider.installed[paths[4]] {
				t.Error("Devin and legacy Windsurf hooks differ")
			}
			if slices.Index(provider.order, paths[2]) > slices.Index(provider.order, paths[3]) {
				t.Errorf("Windsurf policy installed after its hooks: %v", provider.order)
			}
			if provider.hookChecks == 0 {
				t.Error("hook executable was not preflighted")
			}
			if !strings.Contains(result.RegistrationStatus, "cline_requires_install-hook_per_user") {
				t.Errorf("per-user Cline enrollment not reported: %q", result.RegistrationStatus)
			}
		})
	}
}

func TestExtendedNativeTamperedHookIsRejectedBeforeActivation(t *testing.T) {
	a, base, key := newTestAgent(t)
	provider := &destinationProvider{testProvider: base, installed: map[string]string{}}
	a.provider = provider
	entries := extendedNativeEntries(t, "linux")
	for i := range entries {
		if strings.HasSuffix(entries[i].name, ".windsurf.hooks.json") {
			entries[i].body = `{"hooks":{}}`
		}
	}
	body := archiveBytes(t, entries...)
	serveBundle(t, a, key, &body)
	result, err := a.SyncAndEnforce()
	if err == nil || !strings.Contains(result.SyncError, "does not match") || len(provider.installed) != 0 {
		t.Fatalf("tampered signed hook was accepted: %#v %v", result, err)
	}
}

func TestHookProductsCannotBeProvisionedIntoWSL(t *testing.T) {
	for _, product := range []string{"windsurf", "cline"} {
		dir := t.TempDir()
		map_ := "version: 1\nmachine_profile: workstation\nmanaged_agents: [" + product + "]\nsync_wsl: true\n"
		if err := os.WriteFile(filepath.Join(dir, "policy-map.yaml"), []byte(map_), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicyMap(dir); err == nil || !strings.Contains(err.Error(), "sync_wsl") {
			t.Errorf("%s: WSL hook provisioning accepted: %v", product, err)
		}
	}
}
