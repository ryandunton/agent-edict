package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
	"github.com/ryandunton/agent-edict/internal/version"
)

// defaultPublicKeyPEM is the Ed25519 public key this binary trusts. Replace
// the placeholder with your organization's key before building (see
// docs/deployment/README.md); until then edict refuses to sync.
const defaultPublicKeyPEM = `REPLACE WITH YOUR ED25519 PUBLIC KEY (PEM)`

// trustedPublicKey returns the key bundles must be signed with: the -pubkey
// file when one is given, otherwise the key built into the binary.
func trustedPublicKey(path, builtIn string) (string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read public key: %w", err)
		}
		return string(data), nil
	}
	if !strings.Contains(builtIn, "BEGIN PUBLIC KEY") {
		return "", errors.New("this edict build has no trusted public key: put your Ed25519 public key in defaultPublicKeyPEM in cmd/edict/main.go and rebuild, or pass -pubkey (see docs/deployment/README.md)")
	}
	return builtIn, nil
}

func main() {
	// Hooks are short-lived protocol handlers, including when spawned by a
	// service-launched application. Never route their stdin into a daemon.
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		os.Exit(hookCommand(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if isServiceEnvironment() {
		runDaemonAsService()
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "compile":
		runCompile(os.Args[2:])
	case "compile-native":
		if err := compileNativeCommand(os.Args[2:], os.Stdout); err != nil {
			if err == flag.ErrHelp {
				return
			}
			log.Fatal(err)
		}
	case "compile-bundle":
		if err := compileBundleCommand(os.Args[2:], os.Stdout); err != nil {
			if err == flag.ErrHelp {
				return
			}
			log.Fatal(err)
		}
	case "install-hook":
		if err := installHookCommand(os.Args[2:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "validate-bundle":
		runValidateBundle(os.Args[2:])
	case "daemon":
		runDaemon(os.Args[2:])
	case "sync-once":
		runSyncOnce(os.Args[2:])
	case "service":
		runService(os.Args[2:])
	case "status", "inspect":
		runStatus(os.Args[2:])
	case "targets":
		writeTargets(os.Stdout, platform.NewProvider())
	case "version", "--version", "-v":
		fmt.Printf("AgentEdict version %s\n", version.Version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AgentEdict - Local Policy Management for AI Coding Agents

Usage:
  edict <command> [arguments]

Commands:
  status        Inspect machine-policy files, declared scope, and filesystem locks
  compile       Compile unified YAML policy profiles into native agent configuration files
  compile-bundle  Compile every profile a version 2 policy map can select into a bundle directory
  compile-native  Compile product-specific Gemini, Cursor, Antigravity, Copilot, Kiro, Windsurf and Cline controls
  hook          Evaluate a local application hook request (used by generated hooks)
  install-hook  Register the Antigravity or Cline hook for the current non-admin user
  validate-bundle  Validate bundle scope and required files before signing
  daemon        Run the background enforcement service (GitLab sync, signed machine policy, anti-tamper)
  sync-once     Run a single policy sync and enforcement pass, then exit
  service       Manage Windows Service registration (install, uninstall, start, stop)
  targets       List managed file paths for this OS (used by the uninstallers)
  version       Display AgentEdict version

Run 'edict <command> -h' for more information on a specific command.`)
}

func runCompile(args []string) {
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	profilePath := fs.String("profile", "", "Path to single unified policy YAML file")
	profilesDir := fs.String("profiles-dir", "", "Directory containing policy YAML profiles")
	targetOS := fs.String("target-os", "all", "Target operating system (windows, linux, darwin, all)")
	targetAgent := fs.String("agent", "all", "Target agent (all supported, codex); unsupported boundaries require codex")
	outputDir := fs.String("output-dir", "dist/profiles", "Directory where compiled files will be saved")
	_ = fs.Parse(args)
	if *targetAgent != "all" && *targetAgent != "codex" {
		log.Fatalf("Unsupported target agent %q", *targetAgent)
	}

	if *profilePath == "" && *profilesDir == "" {
		fmt.Fprintln(os.Stderr, "Error: Must provide either -profile or -profiles-dir")
		fs.Usage()
		os.Exit(1)
	}

	targets := []string{*targetOS}
	if *targetOS == "all" {
		targets = []string{"windows", "linux", "darwin"}
	}

	var files []string
	if *profilePath != "" {
		files = append(files, *profilePath)
	}
	if *profilesDir != "" {
		entries, err := os.ReadDir(*profilesDir)
		if err != nil {
			log.Fatalf("Failed to read profiles directory: %v", err)
		}
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				files = append(files, filepath.Join(*profilesDir, e.Name()))
			}
		}
	}

	for _, f := range files {
		p, err := compiler.LoadPolicy(f)
		if err != nil {
			log.Fatalf("Failed to load policy %s: %v", f, err)
		}

		profileName := p.Name
		if profileName == "" {
			profileName = strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		}

		for _, osName := range targets {
			if *targetAgent == "codex" {
				requirements, telemetry, err := compiler.CompileCodexOnly(p, osName)
				if err != nil {
					log.Fatalf("Failed compiling %s for Codex on %s: %v", f, osName, err)
				}
				destDir := filepath.Join(*outputDir, osName)
				if err := os.MkdirAll(destDir, 0755); err != nil {
					log.Fatalf("Failed to create output dir: %v", err)
				}
				writeFile(filepath.Join(destDir, fmt.Sprintf("%s.codex.toml", profileName)), requirements)
				if telemetry != "" {
					writeFile(filepath.Join(destDir, fmt.Sprintf("%s.codex.config.toml", profileName)), telemetry)
				}
				fmt.Printf("Compiled [%s] -> %s/ (Codex)\n", profileName, destDir)
				continue
			}

			out, err := compiler.Compile(p, osName)
			if err != nil {
				log.Fatalf("Failed compiling %s for %s: %v", f, osName, err)
			}

			destDir := filepath.Join(*outputDir, osName)
			if err := os.MkdirAll(destDir, 0755); err != nil {
				log.Fatalf("Failed to create output dir: %v", err)
			}

			// Write supported agent formats and the managed OpenCode instruction sidecar.
			writeFile(filepath.Join(destDir, fmt.Sprintf("%s.codex.toml", profileName)), out.CodexRequirementsTOML)
			writeFile(filepath.Join(destDir, fmt.Sprintf("%s.claude.json", profileName)), out.ClaudeManagedSettings)
			writeFile(filepath.Join(destDir, fmt.Sprintf("%s.opencode.json", profileName)), out.OpenCodeJSON)
			writeFile(filepath.Join(destDir, fmt.Sprintf("%s.opencode.instructions.md", profileName)), out.OpenCodeInstructions)

			fmt.Printf("Compiled [%s] -> %s/ (Codex, Claude, OpenCode; other products use compile-native)\n", profileName, destDir)
		}
	}
}

// writeTargets prints "purpose<TAB>path" for every managed file on this OS, so
// uninstallers never drift from the targets the daemon actually locks.
func writeTargets(w io.Writer, provider platform.PlatformProvider) {
	for _, target := range provider.GetTargets() {
		purpose := target.Purpose
		if purpose == "" {
			purpose = "policy"
		}
		fmt.Fprintf(w, "%s\t%s\n", purpose, target.FilePath(provider.OSName()))
	}
}

func writeFile(path string, content string) {
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		log.Fatalf("Failed writing %s: %v", path, err)
	}
}

func runValidateBundle(args []string) {
	fs := flag.NewFlagSet("validate-bundle", flag.ExitOnError)
	dir := fs.String("dir", "dist", "Bundle directory containing policy-map.yaml and profiles/")
	targetOS := fs.String("target-os", "all", "Target operating system (windows, linux, darwin, all)")
	_ = fs.Parse(args)
	targets := []string{*targetOS}
	if *targetOS == "all" {
		targets = []string{"windows", "linux", "darwin"}
	}
	for _, osName := range targets {
		if err := agent.ValidateBundleDirectory(*dir, osName); err != nil {
			log.Fatalf("Invalid bundle for %s: %v", osName, err)
		}
		fmt.Printf("Bundle files validated for %s; native consumer behavior not verified.\n", osName)
	}
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	bundleURL := fs.String("bundle-url", os.Getenv("EDICT_BUNDLE_URL"), "HTTPS URL to policy-bundle.tar.gz (GitLab package registry, GitHub contents API, or any HTTPS host)")
	tokenFile := fs.String("deploy-token-file", os.Getenv("EDICT_DEPLOY_TOKEN_FILE"), "Restricted service-account-owned file containing a GitLab deploy token or GitHub fine-grained token")
	interval := fs.Duration("interval", 15*time.Minute, "Polling interval for policy updates")
	sessionInterval := fs.Duration("session-interval", 30*time.Second, "How often to check who is logged in (version 2 maps)")
	pubKeyPath := fs.String("pubkey", "", "Optional path to Ed25519 public key PEM file")
	_ = fs.Parse(args)

	token, err := platform.ReadDeployTokenFile(*tokenFile)
	if err != nil {
		log.Fatalf("Failed loading credential: %v", err)
	}
	pemKey, err := trustedPublicKey(*pubKeyPath, defaultPublicKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	provider := platform.NewProvider()
	ag, err := agent.New(agent.Config{
		GitLabBundleURL: *bundleURL,
		DeployToken:     token,
		PublicKeyPEM:    pemKey,
		SyncInterval:    *interval,
		SessionInterval: *sessionInterval,
	}, provider)
	if err != nil {
		log.Fatalf("Failed to initialize agent: %v", err)
	}

	if err := runPlatformService(ag); err != nil {
		log.Fatalf("Service stopped with error: %v", err)
	}
}

func runSyncOnce(args []string) {
	fs := flag.NewFlagSet("sync-once", flag.ExitOnError)
	bundleURL := fs.String("bundle-url", os.Getenv("EDICT_BUNDLE_URL"), "HTTPS URL to policy-bundle.tar.gz (GitLab package registry, GitHub contents API, or any HTTPS host)")
	tokenFile := fs.String("deploy-token-file", os.Getenv("EDICT_DEPLOY_TOKEN_FILE"), "Restricted service-account-owned file containing a GitLab deploy token or GitHub fine-grained token")
	pubKeyPath := fs.String("pubkey", "", "Optional path to Ed25519 public key PEM file")
	_ = fs.Parse(args)

	token, err := platform.ReadDeployTokenFile(*tokenFile)
	if err != nil {
		log.Fatalf("Failed loading credential: %v", err)
	}
	pemKey, err := trustedPublicKey(*pubKeyPath, defaultPublicKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	provider := platform.NewProvider()
	ag, err := agent.New(agent.Config{
		GitLabBundleURL: *bundleURL,
		DeployToken:     token,
		PublicKeyPEM:    pemKey,
		SyncInterval:    15 * time.Minute,
	}, provider)
	if err != nil {
		log.Fatalf("Failed to initialize agent: %v", err)
	}

	if err := provider.EnsureSecureDirectories(); err != nil {
		log.Fatalf("EnsureSecureDirectories failed: %v", err)
	}

	result, err := ag.SyncAndEnforce()
	if result.MapVersion == 2 {
		writeV2Result(os.Stdout, result)
	}
	if enforcementFailed(err) {
		log.Fatalf("Policy enforcement failed: %v", err)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Some agents were not installed; the service retries them: %v\n", err)
	}
	if result.SyncError != "" {
		fmt.Fprintf(os.Stderr, "Policy update unavailable; installed previous verified snapshot: %s\n", result.SyncError)
	}
	if result.SubsystemError != "" {
		fmt.Fprintf(os.Stderr, "WSL provisioning %s: %s\n", result.SubsystemStatus, result.SubsystemError)
	}
	if result.MapVersion == 2 {
		fmt.Printf("Installed %d files; consumer runtime enforcement has not been verified.\n", len(result.Installed))
		return
	}
	fmt.Printf("Installed machine policy %q (%d files); consumer runtime enforcement has not been verified.\n", result.Profile, len(result.Installed))
}

// enforcementFailed reports errors that must fail sync-once. Skipped or
// incomplete version 2 agents are retried by the service, so they only warn;
// `edict status` exits 1 while any of them remain.
func enforcementFailed(err error) bool {
	return err != nil && !errors.Is(err, agent.ErrPartialEnforcement)
}

// writeV2Result prints one line per version 2 agent assignment.
func writeV2Result(w io.Writer, result agent.EnforcementResult) {
	fmt.Fprintf(w, "Role assignments (%s):\n", result.Proof)
	for _, a := range result.Assignments {
		line := fmt.Sprintf("%s: %s (%s %d) %s", a.Agent, a.Profile, a.Source, a.Priority, a.State)
		if a.Reason != "" {
			line += ": " + a.Reason
		}
		fmt.Fprintln(w, line)
		for _, setting := range a.ToolLevelOnly {
			fmt.Fprintf(w, "%s: %s is enforced in Claude's own tools only\n", a.Agent, setting)
		}
	}
	if len(result.Released) > 0 {
		fmt.Fprintf(w, "released: %s\n", strings.Join(result.Released, ", "))
	}
	if len(result.Originals) > 0 {
		fmt.Fprintf(w, "saved originals: %s\n", strings.Join(result.Originals, ", "))
	}
}

func runService(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: edict service <install|uninstall|start|stop> [options]")
		os.Exit(1)
	}

	action := args[0]
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	bundleURL := fs.String("bundle-url", "", "HTTPS URL to policy-bundle.tar.gz (GitLab package registry, GitHub contents API, or any HTTPS host)")
	tokenFile := fs.String("deploy-token-file", "", "Restricted file containing a GitLab deploy token or GitHub fine-grained token; only the path is registered")
	interval := fs.Duration("interval", 15*time.Minute, "Polling interval for policy updates")
	sessionInterval := fs.Duration("session-interval", 0, "How often to check who is logged in (version 2 maps); 0 keeps the 30s default")
	_ = fs.Parse(args[1:])

	if err := handleServiceCommand(action, *bundleURL, *tokenFile, *interval, *sessionInterval); err != nil {
		log.Fatalf("Service command %q failed: %v", action, err)
	}
}
