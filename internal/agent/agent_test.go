package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ryandunton/agent-edict/internal/platform"
)

type testProvider struct {
	root          string
	prepared      []string
	installed     map[string]string
	fail          error
	identityCalls int
	subsystemErr  error
	osName        string
}

func (p *testProvider) OSName() string {
	if p.osName != "" {
		return p.osName
	}
	return "linux"
}
func (p *testProvider) BaseDir() string                { return p.root }
func (p *testProvider) VaultPath() string              { return filepath.Join(p.root, "vault") }
func (p *testProvider) EnsureSecureDirectories() error { return os.MkdirAll(p.VaultPath(), 0700) }
func (p *testProvider) GetActiveConsoleUser() (*platform.UserIdentity, error) {
	p.identityCalls++
	return &platform.UserIdentity{Username: "principal", Groups: []string{"admin"}}, nil
}
func (p *testProvider) GetTargets() []platform.PolicyTarget {
	return []platform.PolicyTarget{{AgentName: "codex", BundleExt: "codex.toml", UnixDir: filepath.Join(p.root, "target"), UnixFile: filepath.Join(p.root, "target", "requirements.toml")}}
}
func (p *testProvider) AtomicSwapAndLock(target platform.PolicyTarget, src string) error {
	if p.fail != nil {
		return p.fail
	}
	data, err := os.ReadFile(src)
	if err == nil {
		p.installed[target.AgentName] = string(data)
	}
	return err
}
func (p *testProvider) SyncSubsystems(string, string, []platform.PolicyTarget) error {
	return p.subsystemErr
}

// PrepareTargetDirectories records each requested directory and creates only
// those under the test root, so real system paths are never touched.
func (p *testProvider) PrepareTargetDirectories(targets []platform.PolicyTarget) ([]string, error) {
	var created []string
	for _, target := range targets {
		dir := target.DirPath(p.OSName())
		p.prepared = append(p.prepared, dir)
		if !strings.HasPrefix(dir, p.root) {
			continue
		}
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return created, err
			}
			created = append(created, dir)
		}
	}
	return created, nil
}
func newTestAgent(t *testing.T) (*Agent, *testProvider, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	p := &testProvider{root: t.TempDir(), installed: map[string]string{}}
	if err := p.EnsureSecureDirectories(); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), SyncInterval: time.Minute}, p)
	if err != nil {
		t.Fatal(err)
	}
	return a, p, priv
}

type archiveEntry struct {
	name, body string
	kind       byte
}

func archiveBytes(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0600, Typeflag: kind, Size: int64(len(e.body))}
		if kind != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func validBundle(t *testing.T, content string) []byte {
	return archiveBytes(t, archiveEntry{name: "policy-map.yaml", body: "version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\ndefault_profile: principal\nrules:\n  - priority: 1\n    profile: principal\n    match_groups:\n      linux: [admin]\n"}, archiveEntry{name: "profiles/linux/restricted.codex.toml", body: content})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func handlerClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		response := rec.Result()
		response.Request = r
		return response, nil
	})}
}
func serveBundle(t *testing.T, a *Agent, priv ed25519.PrivateKey, body *[]byte) {
	t.Helper()
	a.cfg.GitLabBundleURL = "https://registry.example.test/bundle.tar.gz"
	a.client = handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.Write(ed25519.Sign(priv, *body))
		} else {
			w.Write(*body)
		}
	}))
}

func TestEmptyCacheFails(t *testing.T) {
	a, _, _ := newTestAgent(t)
	if _, err := a.SyncAndEnforce(); err == nil {
		t.Fatal("empty cache reported success")
	}
}

func TestSubsystemAvailabilityDoesNotHideFailures(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		err          error
		wantError    bool
	}{
		{"unavailable", "deferred", platform.ErrSubsystemUnavailable, false},
		{"injection failed", "synchronization_failed", errors.New("injection failed"), true},
		{"copied", "active_user_distributions_copied; owner_root_not_contained", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, p, key := newTestAgent(t)
			p.osName, p.subsystemErr = "windows", tc.err
			bundle := archiveBytes(t,
				archiveEntry{name: "policy-map.yaml", body: "version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\nsync_wsl: true\n"},
				archiveEntry{name: "profiles/windows/restricted.codex.toml", body: "setting = true"},
				archiveEntry{name: "profiles/linux/restricted.codex.toml", body: "setting = true"})
			serveBundle(t, a, key, &bundle)
			result, err := a.SyncAndEnforce()
			if (err != nil) != tc.wantError || result.SubsystemStatus != tc.status {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if tc.err != nil && result.SubsystemError == "" {
				t.Fatal("subsystem error was not reported")
			}
			if len(p.installed) != 1 {
				t.Fatal("native policy was not installed")
			}
		})
	}
}

func TestValidateBundleDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy-map.yaml"), []byte("version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, osName := range []string{"windows", "linux", "darwin"} {
		if err := ValidateBundleDirectory(dir, osName); err == nil {
			t.Fatal("missing required profile accepted")
		}
		profiles := filepath.Join(dir, "profiles", osName)
		if err := os.MkdirAll(profiles, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(profiles, "restricted.codex.toml"), []byte("setting = true"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateBundleDirectory(dir, osName); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateBundleDirectory(dir, "typo"); err == nil {
		t.Fatal("unknown operating system accepted")
	}
}
func TestSignedMachinePolicyIgnoresConsoleRole(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := validBundle(t, "setting = \"restricted\"")
	serveBundle(t, a, key, &bundle)
	result, err := a.SyncAndEnforce()
	if err != nil {
		t.Fatal(err)
	}
	if p.installed["codex"] != "setting = \"restricted\"" || result.Profile != "restricted" {
		t.Fatalf("wrong machine profile: %+v %v", result, p.installed)
	}
	if p.identityCalls != 0 {
		t.Fatal("enforcement consulted console identity")
	}
}
func TestFailedUpdatePreservesVerifiedSnapshot(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := validBundle(t, "setting = \"old\"")
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	before, err := ActiveVaultPath(p.VaultPath())
	if err != nil {
		t.Fatal(err)
	}
	bundle = archiveBytes(t, archiveEntry{name: "policy-map.yaml", body: "version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n"}, archiveEntry{name: "profiles/linux/restricted.codex.toml", body: "setting = \"unactivated\""}, archiveEntry{name: "../vault-escape/file", body: "escape"})
	result, err := a.SyncAndEnforce()
	if err != nil {
		t.Fatal(err)
	}
	if result.SyncError == "" {
		t.Fatal("failed update not reported")
	}
	after, _ := ActiveVaultPath(p.VaultPath())
	if before != after || p.installed["codex"] != "setting = \"old\"" {
		t.Fatal("failed extraction changed active policy")
	}
}
func TestMissingProfileRejectedBeforeAnyInstall(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := archiveBytes(t, archiveEntry{name: "policy-map.yaml", body: "version: 1\nmachine_profile: missing\nmanaged_agents: [codex]\n"})
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err == nil {
		t.Fatal("missing profile accepted")
	}
	if len(p.installed) != 0 {
		t.Fatal("partial installation")
	}
}
func TestEnforcementFailureReturned(t *testing.T) {
	a, p, key := newTestAgent(t)
	p.fail = errors.New("write denied")
	bundle := validBundle(t, `setting = "policy"`)
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err == nil || !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("missing target error: %v", err)
	}
}
func TestBadSignatureDoesNotActivate(t *testing.T) {
	a, p, _ := newTestAgent(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bundle := validBundle(t, `setting = "policy"`)
	serveBundle(t, a, other, &bundle)
	if _, err := a.SyncAndEnforce(); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := ActiveVaultPath(p.VaultPath()); err == nil {
		t.Fatal("bad signature activated")
	}
}
func TestArchiveRejectsUnsafeMembers(t *testing.T) {
	for _, entry := range []archiveEntry{{name: "../vault-sibling/file", body: "x"}, {name: "/absolute", body: "x"}, {name: `..\escape`, body: "x"}, {name: "link", kind: tar.TypeSymlink}, {name: "large", body: strings.Repeat("x", 5*1024*1024+1)}} {
		t.Run(entry.name, func(t *testing.T) {
			if err := extractTarGzSecure(archiveBytes(t, entry), t.TempDir()); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}
func TestArchiveRejectsDuplicateAndExistingFiles(t *testing.T) {
	b := archiveBytes(t, archiveEntry{name: "file", body: "one"}, archiveEntry{name: "file", body: "two"})
	if err := extractTarGzSecure(b, t.TempDir()); err == nil {
		t.Fatal("duplicate accepted")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file"), []byte("original"), 0600)
	if err := extractTarGzSecure(archiveBytes(t, archiveEntry{name: "file", body: "replacement"}), dir); err == nil {
		t.Fatal("existing file overwritten")
	}
}
func TestCrossOriginRedirectDoesNotReceiveCredentials(t *testing.T) {
	a, _, _ := newTestAgent(t)
	received := false
	a.client = handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "registry.example.test" {
			received = true
			return
		}
		if r.Header.Get("Deploy-Token") != "fake-package-token" {
			t.Error("missing source token")
		}
		http.Redirect(w, r, "https://foreign.example.test/collect", http.StatusFound)
	}))
	a.cfg.DeployToken = "fake-package-token"
	if _, err := a.httpGet("https://registry.example.test/bundle"); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
	if received {
		t.Fatal("foreign origin received a request")
	}
}
func TestHTTPAndCredentialURLsRejected(t *testing.T) {
	a, _, _ := newTestAgent(t)
	calls := 0
	a.client = handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; io.WriteString(w, "should not fetch") }))
	for _, u := range []string{"http://registry.example.test/bundle", "https://user:password@registry.example.test/bundle", "https://registry.example.test/bundle?token=fake"} {
		if _, err := a.httpGet(u); err == nil {
			t.Fatalf("unsafe URL accepted: %s", u)
		}
	}
	if calls != 0 {
		t.Fatal("unsafe URL reached transport")
	}
}
func TestSameOriginRedirectRetainsScopedToken(t *testing.T) {
	a, _, _ := newTestAgent(t)
	a.cfg.DeployToken = "fake-package-token"
	calls := 0
	a.client = handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Deploy-Token") != "fake-package-token" {
			t.Error("token missing")
		}
		if r.Header.Get("PRIVATE-TOKEN") != "" || r.Header.Get("Authorization") != "" {
			t.Error("redundant credential headers")
		}
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusFound)
		} else {
			io.WriteString(w, "bundle")
		}
	}))
	data, err := a.httpGet("https://registry.example.test/old")
	if err != nil || string(data) != "bundle" || calls != 2 {
		t.Fatalf("same origin redirect: %q %v calls=%d", data, err, calls)
	}
}

// A GitHub token reads a private repository file through the contents API,
// which returns the raw bytes only with GitHub's raw media type.
func TestGitHubTokenUsesBearerAndRawContent(t *testing.T) {
	for _, token := range []string{"github_pat_11FAKE0example", "ghp_fakeClassicToken"} {
		a, _, _ := newTestAgent(t)
		a.cfg.DeployToken = token
		a.client = handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer "+token {
				t.Errorf("%s: Authorization = %q", token, got)
			}
			if got := r.Header.Get("Accept"); got != "application/vnd.github.raw+json" {
				t.Errorf("%s: Accept = %q", token, got)
			}
			if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
				t.Errorf("%s: X-GitHub-Api-Version = %q", token, got)
			}
			if r.Header.Get("Deploy-Token") != "" || r.Header.Get("PRIVATE-TOKEN") != "" {
				t.Errorf("%s: GitLab headers sent to GitHub", token)
			}
			io.WriteString(w, "bundle")
		}))
		data, err := a.httpGet("https://api.github.com/repos/example/agentedict-bundles/contents/policy-bundle.tar.gz")
		if err != nil || string(data) != "bundle" {
			t.Fatalf("%s: %q %v", token, data, err)
		}
	}
}

func TestGitLabTokensKeepGitLabHeaders(t *testing.T) {
	for token, header := range map[string]string{"gldt-fakeDeployToken": "Deploy-Token", "glpat-fakePersonalToken": "PRIVATE-TOKEN"} {
		a, _, _ := newTestAgent(t)
		a.cfg.DeployToken = token
		a.client = handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(header) != token || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") == "application/vnd.github.raw+json" {
				t.Errorf("%s: wrong headers %v", token, r.Header)
			}
			io.WriteString(w, "bundle")
		}))
		if _, err := a.httpGet("https://gitlab.example.test/bundle"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestActivePointerRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "active"), []byte("../escape"), 0600)
	if _, err := ActiveVaultPath(root); err == nil {
		t.Fatal("unsafe pointer accepted")
	}
}
func TestPolicyMapRequiresExplicitMachineScope(t *testing.T) {
	for _, body := range []string{"version: 1\ndefault_profile: principal\n", "version: 1\nmachine_profile: ../escape\nmanaged_agents: [codex]\n", "version: 1\nmachine_profile: restricted\nmanaged_agents: [unknown]\n", "version: 1\nmachine_profile: restricted\nmanaged_agents: [gemini, gemini]\n", "version: 1\nmachine_profile: restricted\nmanaged_agents: []\n", "version: 1\nmachine_profile: restricted\nmanaged_agents: [codex]\n---\nmachine_profile: other\n"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "policy-map.yaml"), []byte(body), 0600)
		if _, err := LoadPolicyMap(dir); err == nil {
			t.Fatalf("unsafe map accepted: %s", body)
		}
	}
}
func TestSuccessfulSnapshotDoesNotRetainOmittedFiles(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := validBundle(t, `setting = "old"`)
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	old, _ := ActiveVaultPath(p.VaultPath())
	os.WriteFile(filepath.Join(old, "obsolete"), []byte("old"), 0600)
	bundle = validBundle(t, `setting = "new"`)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	current, _ := ActiveVaultPath(p.VaultPath())
	if _, err := os.Stat(filepath.Join(current, "obsolete")); !os.IsNotExist(err) {
		t.Fatal("obsolete file retained")
	}
}

func TestMalformedTOMLPreservesPreviousSnapshot(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := validBundle(t, `setting = "valid"`)
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	before, _ := ActiveVaultPath(p.VaultPath())
	bundle = validBundle(t, "[unterminated")
	result, err := a.SyncAndEnforce()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := ActiveVaultPath(p.VaultPath())
	if result.SyncError == "" || after != before || p.installed["codex"] != `setting = "valid"` {
		t.Fatal("malformed TOML replaced working policy")
	}
}
func TestSnapshotRetentionIsBounded(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := validBundle(t, `setting = "valid"`)
	serveBundle(t, a, key, &bundle)
	for i := 0; i < 5; i++ {
		if _, err := a.SyncAndEnforce(); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(p.VaultPath(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 2 {
		t.Fatalf("retained %d snapshots", len(entries))
	}
}
func TestTruncatedGzipDoesNotActivate(t *testing.T) {
	a, p, key := newTestAgent(t)
	bundle := validBundle(t, `setting = "valid"`)
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	before, _ := ActiveVaultPath(p.VaultPath())
	bundle = bundle[:len(bundle)-4]
	result, err := a.SyncAndEnforce()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := ActiveVaultPath(p.VaultPath())
	if result.SyncError == "" || after != before {
		t.Fatal("truncated gzip activated")
	}
}

// twoAgentProvider offers codex and claude targets in separate directories.
type twoAgentProvider struct{ *testProvider }

func (p twoAgentProvider) GetTargets() []platform.PolicyTarget {
	codex := p.testProvider.GetTargets()[0]
	claudeDir := filepath.Join(p.root, "claude")
	return []platform.PolicyTarget{codex, {AgentName: "claude", BundleExt: "claude.json", UnixDir: claudeDir, UnixFile: filepath.Join(claudeDir, "managed-settings.json")}}
}

func TestV1EnforcementPreparesOnlyManagedDirectories(t *testing.T) {
	a, base, key := newTestAgent(t)
	p := twoAgentProvider{base}
	a.provider = p
	bundle := validBundle(t, "setting = true")
	serveBundle(t, a, key, &bundle)
	if _, err := a.SyncAndEnforce(); err != nil {
		t.Fatal(err)
	}
	codexDir := filepath.Join(p.root, "target")
	if len(p.prepared) != 1 || p.prepared[0] != codexDir {
		t.Fatalf("prepared %v, want only the managed codex directory", p.prepared)
	}
	if _, err := os.Stat(filepath.Join(p.root, "claude")); !os.IsNotExist(err) {
		t.Fatal("an unmanaged agent's directory was created")
	}
}

func TestWatchDirsCoversBaseAndInstalledTargets(t *testing.T) {
	got := watchDirs("/etc/agent-edict", []string{"/etc/codex/requirements.toml", "/etc/codex/other.toml", "/etc/claude-code/managed-settings.json"})
	want := []string{"/etc/agent-edict", "/etc/claude-code", "/etc/codex"}
	if !slices.Equal(got, want) {
		t.Fatalf("watchDirs = %v, want %v", got, want)
	}
}
