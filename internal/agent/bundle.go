package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
)

const maxBundleBytes int64 = 15 * 1024 * 1024
const maxMemberBytes int64 = 5 * 1024 * 1024
const maxExpandedBytes int64 = 64 * 1024 * 1024

var profileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)
var snapshotNamePattern = regexp.MustCompile(`^snapshot-[0-9]+$`)

func validateBundleURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("bundle URL must be HTTPS with a host and no userinfo, query, or fragment")
	}
	return u, nil
}

// setTokenHeaders sends the bundle credential the way its host expects:
// GitHub tokens read a repository file through the contents API, which needs
// its raw media type; GitLab tokens use the package registry's headers.
func setTokenHeaders(req *http.Request, token string) {
	switch {
	case token == "":
	case strings.HasPrefix(token, "github_pat_") || strings.HasPrefix(token, "ghp_"):
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github.raw+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	case strings.HasPrefix(token, "glpat-"):
		req.Header.Set("PRIVATE-TOKEN", token)
	default:
		req.Header.Set("Deploy-Token", token)
	}
}

func (a *Agent) httpGet(raw string) ([]byte, error) {
	origin, err := validateBundleURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.String(), nil)
	if err != nil {
		return nil, err
	}
	setTokenHeaders(req, a.cfg.DeployToken)
	client := *a.client
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		u, err := validateBundleURL(next.URL.String())
		if err != nil {
			return err
		}
		if !strings.EqualFold(u.Host, origin.Host) {
			return fmt.Errorf("cross-origin bundle redirect rejected")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle server returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBundleBytes {
		return nil, fmt.Errorf("bundle response exceeds size limit")
	}
	return data, nil
}

func (a *Agent) pullAndVerifyBundle() error {
	bundle, err := a.httpGet(a.cfg.GitLabBundleURL)
	if err != nil {
		return err
	}
	sig, err := a.httpGet(a.cfg.GitLabBundleURL + ".sig")
	if err != nil {
		return err
	}
	if !ed25519.Verify(a.pubKey, bundle, sig) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	bundleHash := sha256Hex(bundle)
	previous, _ := ActiveVaultPath(a.provider.VaultPath())
	if previous != "" {
		// Re-staging an identical bundle every poll would rotate snapshots
		// for nothing; the active one already holds these exact bytes.
		recorded, err := readRegularFile(filepath.Join(a.provider.VaultPath(), "active.sha256"), 128)
		if err == nil && strings.TrimSpace(string(recorded)) == bundleHash {
			return nil
		}
	}
	root := filepath.Join(a.provider.VaultPath(), "snapshots")
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe snapshots directory")
	}
	staging, err := os.MkdirTemp(root, "snapshot-")
	if err != nil {
		return err
	}
	activated := false
	defer func() {
		if !activated {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := extractTarGzSecure(bundle, staging); err != nil {
		return fmt.Errorf("extract staged bundle: %w", err)
	}
	if bm, err := LoadBundleMap(staging); err == nil && bm.V2 != nil {
		// Version 2 preflights hook runtimes per agent at install time, so a
		// missing runtime skips that agent instead of blocking the bundle.
		if _, err := validateSnapshotV2(staging, a.provider.OSName(), a.provider.GetTargets()); err != nil {
			return fmt.Errorf("validate staged bundle: %w", err)
		}
	} else {
		pm, _, err := validateSnapshot(staging, a.provider.OSName(), a.provider.GetTargets())
		if err != nil {
			return fmt.Errorf("validate staged bundle: %w", err)
		}
		if err := a.preflightNativeRuntime(pm); err != nil {
			return fmt.Errorf("native runtime prerequisite: %w", err)
		}
	}
	pointer, err := os.CreateTemp(a.provider.VaultPath(), ".active-")
	if err != nil {
		return err
	}
	pointerPath := pointer.Name()
	defer os.Remove(pointerPath)
	if _, err := pointer.WriteString(filepath.Base(staging) + "\n"); err != nil {
		pointer.Close()
		return err
	}
	if err := pointer.Sync(); err != nil {
		pointer.Close()
		return err
	}
	if err := pointer.Close(); err != nil {
		return err
	}
	if err := os.Rename(pointerPath, filepath.Join(a.provider.VaultPath(), "active")); err != nil {
		return fmt.Errorf("activate snapshot: %w", err)
	}
	activated = true
	if err := writePrivateFile(a.provider.VaultPath(), "active.sha256", []byte(bundleHash+"\n")); err != nil {
		log.Printf("[Agent] Cannot record active bundle hash; the next poll restages it: %v", err)
	}
	// Retain the current and previous complete snapshot; repeated polls are bounded.
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		log.Printf("[Agent] Snapshot retention inspection failed: %v", readErr)
	}
	for _, entry := range entries {
		candidate := filepath.Join(root, entry.Name())
		if snapshotNamePattern.MatchString(entry.Name()) && entry.IsDir() && candidate != staging && candidate != previous {
			if err := os.RemoveAll(candidate); err != nil {
				log.Printf("[Agent] Cannot remove obsolete snapshot %s: %v", entry.Name(), err)
			}
		}
	}
	return nil
}

// ActiveVaultPath resolves only snapshots created by verified bundle activation.
// Legacy loose caches must be reseeded from a signed bundle.
func ActiveVaultPath(vault string) (string, error) {
	data, err := readRegularFile(filepath.Join(vault, "active"), 128)
	if err != nil {
		return "", fmt.Errorf("no active verified snapshot: %w", err)
	}
	name := strings.TrimSpace(string(data))
	if !snapshotNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid active snapshot name")
	}
	root := filepath.Join(vault, "snapshots")
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("unsafe snapshot root")
	}
	selected := filepath.Join(root, name)
	info, err := os.Lstat(selected)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("active snapshot missing or unsafe")
	}
	return selected, nil
}

// SelectTargets requires a supported destination for every explicitly managed agent.
func SelectTargets(pm *PolicyMap, available []platform.PolicyTarget) ([]platform.PolicyTarget, error) {
	var selected []platform.PolicyTarget
	for _, name := range pm.ManagedAgents {
		found := false
		for _, target := range available {
			if target.AgentName == name {
				selected = append(selected, target)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("no supported target for managed agent %q", name)
		}
	}
	return selected, nil
}

// ValidateBundleDirectory checks the signed-map contract and required native files
// before a publisher signs a bundle. It does not verify native consumer behavior.
func ValidateBundleDirectory(dir, osName string) error {
	switch osName {
	case "windows", "linux", "darwin":
	default:
		return fmt.Errorf("unsupported target operating system %q", osName)
	}
	if bm, err := LoadBundleMap(dir); err == nil && bm.V2 != nil {
		_, err := validateSnapshotV2(dir, osName, platform.DefaultPolicyTargets())
		return err
	}
	_, _, err := validateSnapshot(dir, osName, platform.DefaultPolicyTargets())
	return err
}

func validateSnapshot(snapshot, osName string, available []platform.PolicyTarget) (*PolicyMap, []platform.PolicyTarget, error) {
	pm, err := LoadPolicyMap(snapshot)
	if err != nil {
		return nil, nil, err
	}
	targets, err := SelectTargets(pm, available)
	if err != nil {
		return nil, nil, err
	}
	platforms := []string{osName}
	if pm.SyncWSL && osName == "windows" {
		platforms = append(platforms, "linux")
	}
	for _, osKey := range platforms {
		if _, err := NativeCapabilities(snapshot, osKey, pm); err != nil {
			return nil, nil, fmt.Errorf("native controls for %s: %w", osKey, err)
		}
		for _, target := range targets {
			if err := checkProfileFile(snapshot, osKey, pm.MachineProfile, target); err != nil {
				return nil, nil, err
			}
		}
	}
	return pm, targets, nil
}

// checkProfileFile requires profile's compiled file for target in a valid format.
func checkProfileFile(snapshot, osKey, profile string, target platform.PolicyTarget) error {
	filename := filepath.Join(snapshot, "profiles", osKey, profile+"."+target.BundleExt)
	if err := rejectSymlinkComponents(snapshot, filename); err != nil {
		return err
	}
	data, err := readRegularFile(filename, maxMemberBytes)
	if err != nil {
		return fmt.Errorf("required %s.%s profile missing or unreadable: %w", profile, target.BundleExt, err)
	}
	if strings.HasSuffix(target.BundleExt, ".json") {
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil || value == nil {
			return fmt.Errorf("invalid JSON profile %s.%s", profile, target.BundleExt)
		}
	} else if strings.HasSuffix(target.BundleExt, ".toml") {
		var value map[string]any
		if err := toml.Unmarshal(data, &value); err != nil || len(value) == 0 {
			return fmt.Errorf("invalid or empty TOML profile %s.%s", profile, target.BundleExt)
		}
		if target.BundleExt == "codex.toml" {
			if err := compiler.ValidateCodexGatewayTOML(data); err != nil {
				return fmt.Errorf("invalid Codex gateway settings in %s.%s: %w", profile, target.BundleExt, err)
			}
		}
	} else if !strings.HasSuffix(target.BundleExt, ".instructions.md") {
		return fmt.Errorf("unsupported profile format %s", target.BundleExt)
	}
	return nil
}

// validateSnapshotV2 checks every profile-agent pair the map can select on
// osName, whether or not any current user would select it.
func validateSnapshotV2(snapshot, osName string, available []platform.PolicyTarget) (*PolicyMapV2, error) {
	bm, err := LoadBundleMap(snapshot)
	if err != nil {
		return nil, err
	}
	if bm.V2 == nil {
		return nil, fmt.Errorf("snapshot does not carry a version 2 map")
	}
	nativeByProfile := map[string][]string{}
	var profiles []string
	for _, pair := range bm.V2.Pairs() {
		targets := targetsFor(pair.Agent, available)
		if len(targets) == 0 {
			return nil, fmt.Errorf("no supported target for managed agent %q", pair.Agent)
		}
		for _, target := range targets {
			if err := checkProfileFile(snapshot, osName, pair.Profile, target); err != nil {
				return nil, err
			}
		}
		if _, err := ToolLevelNotes(snapshot, osName, pair); err != nil {
			return nil, err
		}
		if nativeProduct(pair.Agent) {
			if _, seen := nativeByProfile[pair.Profile]; !seen {
				profiles = append(profiles, pair.Profile)
			}
			nativeByProfile[pair.Profile] = append(nativeByProfile[pair.Profile], pair.Agent)
		}
	}
	for _, profile := range profiles {
		if _, err := NativeCapabilitiesFor(snapshot, osName, profile, nativeByProfile[profile]); err != nil {
			return nil, fmt.Errorf("native controls for %s %s: %w", profile, osName, err)
		}
	}
	return bm.V2, nil
}

// targetsFor lists the fixed destinations for one agent.
func targetsFor(agent string, available []platform.PolicyTarget) []platform.PolicyTarget {
	var targets []platform.PolicyTarget
	for _, target := range available {
		if target.AgentName == agent {
			targets = append(targets, target)
		}
	}
	return targets
}

// ToolLevelNotes reads the settings a pair enforces only in the agent's own
// tools. A missing notes file means there are none.
func ToolLevelNotes(snapshot, osName string, pair ProfileAgent) ([]string, error) {
	filename := filepath.Join(snapshot, "profiles", osName, pair.Profile+"."+pair.Agent+".notes.json")
	if _, err := os.Lstat(filename); os.IsNotExist(err) {
		return nil, nil
	}
	if err := rejectSymlinkComponents(snapshot, filename); err != nil {
		return nil, err
	}
	data, err := readRegularFile(filename, 64*1024)
	if err != nil {
		return nil, fmt.Errorf("read %s.%s notes: %w", pair.Profile, pair.Agent, err)
	}
	var notes struct {
		ToolLevelOnly []string `json:"tool_level_only"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&notes); err != nil {
		return nil, fmt.Errorf("invalid %s.%s notes: %w", pair.Profile, pair.Agent, err)
	}
	return notes.ToolLevelOnly, nil
}

func readRegularFile(filename string, limit int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("file is not a regular file within size limit")
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, actual) {
		return nil, fmt.Errorf("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds size limit")
	}
	return data, err
}

func rejectSymlinkComponents(root, filename string) error {
	rel, err := filepath.Rel(root, filename)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes snapshot")
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in snapshot path")
		}
	}
	return nil
}

func extractTarGzSecure(bundle []byte, destDir string) error {
	if int64(len(bundle)) > maxBundleBytes {
		return fmt.Errorf("compressed bundle exceeds size limit")
	}
	gz, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var expanded int64
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		count++
		if count > 4096 {
			return fmt.Errorf("too many archive entries")
		}
		name := hdr.Name
		if strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return fmt.Errorf("archive path traversal")
			}
		}
		name = path.Clean(name)
		if name == "." && hdr.Typeflag == tar.TypeDir {
			continue
		}
		if name == "." || name == "" {
			return fmt.Errorf("empty archive path")
		}
		target := filepath.Join(destDir, filepath.FromSlash(name))
		if hdr.Size < 0 || hdr.Size > maxMemberBytes {
			return fmt.Errorf("archive member exceeds size limit")
		}
		expanded += hdr.Size
		if expanded > maxExpandedBytes {
			return fmt.Errorf("expanded archive exceeds size limit")
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0700); err != nil {
				return err
			}
			if err := rejectSymlinkComponents(destDir, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return err
			}
			if err := rejectSymlinkComponents(destDir, filepath.Dir(target)); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tr, hdr.Size)
			syncErr := f.Sync()
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if syncErr != nil {
				return syncErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unsupported archive entry type %d", hdr.Typeflag)
		}
	}
	// Consume the gzip trailer so checksum/truncation failures cannot activate.
	remaining, err := io.ReadAll(io.LimitReader(gz, maxExpandedBytes-expanded+1))
	if err != nil {
		return err
	}
	if int64(len(remaining))+expanded > maxExpandedBytes {
		return fmt.Errorf("expanded archive exceeds size limit")
	}
	if len(bytes.Trim(remaining, "\x00")) != 0 {
		return fmt.Errorf("unexpected data after tar archive")
	}
	return nil
}
