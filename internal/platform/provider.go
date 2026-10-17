package platform

import "errors"

// ErrSubsystemUnavailable describes a deferred provisioning step, not native installation success.
var ErrSubsystemUnavailable = errors.New("subsystem session unavailable")

// UserIdentity holds the active user's identity and resolved group memberships.
type UserIdentity struct {
	Username string   // e.g. "CORP\jdoe"
	SID      string   // e.g. "S-1-5-21-..." (or UID on Unix)
	Groups   []string // List of both raw SIDs and translated DOMAIN\Group names
}

// PolicyTarget defines the destination and metadata for an agent policy file.
type PolicyTarget struct {
	AgentName   string // Product identifier from the explicit signed scope.
	WindowsDir  string // e.g. `C:\ProgramData\OpenAI\Codex`
	WindowsFile string // e.g. `C:\ProgramData\OpenAI\Codex\requirements.toml`
	UnixDir     string // e.g. `/etc/codex`
	UnixFile    string // e.g. `/etc/codex/requirements.toml`
	DarwinDir   string // e.g. `/Library/Application Support/ClaudeCode`
	DarwinFile  string // e.g. `/Library/Application Support/ClaudeCode/managed-settings.json`
	BundleExt   string // e.g. "codex.toml", "claude.json", "opencode.json"
	Purpose     string // Empty for consumer files; "registration-template" requires user enrollment; "hook-registration" makes a client run edict and is removed on uninstall.
}

// FilePath returns the appropriate OS-specific file path.
func (pt PolicyTarget) FilePath(osName string) string {
	switch osName {
	case "windows":
		return pt.WindowsFile
	case "darwin":
		if pt.DarwinFile != "" {
			return pt.DarwinFile
		}
		return pt.UnixFile
	default:
		return pt.UnixFile
	}
}

// DirPath returns the appropriate OS-specific directory path.
func (pt PolicyTarget) DirPath(osName string) string {
	switch osName {
	case "windows":
		return pt.WindowsDir
	case "darwin":
		if pt.DarwinDir != "" {
			return pt.DarwinDir
		}
		return pt.UnixDir
	default:
		return pt.UnixDir
	}
}

// PlatformProvider abstracts OS-specific identity lookups, ACL locks, and subsystem synchronization.
type PlatformProvider interface {
	// OSName returns "windows", "linux", or "darwin".
	OSName() string

	// BaseDir returns the root management directory.
	BaseDir() string

	// VaultPath returns the secured local cache directory.
	VaultPath() string

	// GetTargets returns the list of AI agent policy targets to enforce.
	GetTargets() []PolicyTarget

	// EnsureSecureDirectories provisions the base and vault directories with
	// strict OS access permissions.
	EnsureSecureDirectories() error

	// PrepareTargetDirectories secures the directories of the given targets,
	// creating missing ones, and returns the directories it created. Only
	// managed agents' targets are passed, so other products' folders are
	// never created or re-permissioned.
	PrepareTargetDirectories(targets []PolicyTarget) ([]string, error)

	// GetActiveConsoleUser inspects the active interactive user session and groups.
	GetActiveConsoleUser() (*UserIdentity, error)

	// AtomicSwapAndLock securely unlocks, updates, and re-locks a policy target.
	AtomicSwapAndLock(target PolicyTarget, sourcePath string) error

	// SyncSubsystems syncs policies to subsystem environments (such as WSL2 on Windows).
	SyncSubsystems(linuxProfilesDir string, profileName string, targets []PolicyTarget) error
}

// TargetRemover unlocks and deletes a managed file when its agent leaves
// AgentEdict's scope. It refuses symlinks and non-regular files; a missing
// file is not an error.
type TargetRemover interface {
	RemoveManagedFile(target PolicyTarget) error
}

// HookRuntimeValidator is required by hook-based integrations before installing
// any files. Copying hook JSON without a trusted evaluator is incomplete.
type HookRuntimeValidator interface {
	ValidateHookRuntime() error
}

// DefaultPolicyTargets returns fixed local destinations. A bundle cannot choose
// arbitrary privileged paths. Native control scope is reported separately.
func DefaultPolicyTargets() []PolicyTarget {
	return []PolicyTarget{
		{
			AgentName:  "gemini",
			WindowsDir: `C:\ProgramData\gemini-cli\policies`, WindowsFile: `C:\ProgramData\gemini-cli\policies\agentedict.toml`,
			UnixDir: `/etc/gemini-cli/policies`, UnixFile: `/etc/gemini-cli/policies/agentedict.toml`,
			DarwinDir: `/Library/Application Support/GeminiCli/policies`, DarwinFile: `/Library/Application Support/GeminiCli/policies/agentedict.toml`,
			BundleExt: "gemini.policy.toml",
		},
		{
			AgentName:  "gemini",
			WindowsDir: `C:\ProgramData\gemini-cli`, WindowsFile: `C:\ProgramData\gemini-cli\settings.json`,
			UnixDir: `/etc/gemini-cli`, UnixFile: `/etc/gemini-cli/settings.json`,
			DarwinDir: `/Library/Application Support/GeminiCli`, DarwinFile: `/Library/Application Support/GeminiCli/settings.json`,
			BundleExt: "gemini.json",
		},
		{
			AgentName:  "cursor",
			WindowsDir: `C:\ProgramData\Cursor`, WindowsFile: `C:\ProgramData\Cursor\agentedict-policy.json`,
			UnixDir: `/etc/cursor`, UnixFile: `/etc/cursor/agentedict-policy.json`,
			DarwinDir: `/Library/Application Support/Cursor`, DarwinFile: `/Library/Application Support/Cursor/agentedict-policy.json`,
			BundleExt: "cursor.policy.json",
		},
		{
			AgentName:  "cursor",
			WindowsDir: `C:\ProgramData\Cursor`, WindowsFile: `C:\ProgramData\Cursor\hooks.json`,
			UnixDir: `/etc/cursor`, UnixFile: `/etc/cursor/hooks.json`,
			DarwinDir: `/Library/Application Support/Cursor`, DarwinFile: `/Library/Application Support/Cursor/hooks.json`,
			BundleExt: "cursor.hooks.json", Purpose: "hook-registration",
		},
		{
			AgentName:  "antigravity",
			WindowsDir: `C:\ProgramData\AgentEdict`, WindowsFile: `C:\ProgramData\AgentEdict\antigravity-policy.json`,
			UnixDir: `/etc/agent-edict`, UnixFile: `/etc/agent-edict/antigravity-policy.json`,
			BundleExt: "antigravity.policy.json",
		},
		{
			AgentName: "antigravity", Purpose: "registration-template",
			WindowsDir: `C:\ProgramData\AgentEdict`, WindowsFile: `C:\ProgramData\AgentEdict\antigravity-hooks.json`,
			UnixDir: `/etc/agent-edict`, UnixFile: `/etc/agent-edict/antigravity-hooks.json`,
			BundleExt: "antigravity.hooks.json",
		},
		{
			AgentName:  "copilot",
			WindowsDir: `C:\Program Files\GitHubCopilot`, WindowsFile: `C:\Program Files\GitHubCopilot\managed-settings.json`,
			UnixDir: `/etc/github-copilot`, UnixFile: `/etc/github-copilot/managed-settings.json`,
			DarwinDir: `/Library/Application Support/GitHubCopilot`, DarwinFile: `/Library/Application Support/GitHubCopilot/managed-settings.json`,
			BundleExt: "copilot.json",
		},
		{
			AgentName:  "kiro",
			WindowsDir: `C:\ProgramData\Kiro`, WindowsFile: `C:\ProgramData\Kiro\managed-settings.json`,
			UnixDir: `/etc/kiro`, UnixFile: `/etc/kiro/managed-settings.json`,
			DarwinDir: `/Library/Application Support/Kiro`, DarwinFile: `/Library/Application Support/Kiro/managed-settings.json`,
			BundleExt: "kiro.json",
		},
		{
			AgentName:  "windsurf",
			WindowsDir: `C:\ProgramData\AgentEdict`, WindowsFile: `C:\ProgramData\AgentEdict\windsurf-policy.json`,
			UnixDir: `/etc/agent-edict`, UnixFile: `/etc/agent-edict/windsurf-policy.json`,
			BundleExt: "windsurf.policy.json",
		},
		{
			// Devin Desktop reads its own system hooks first.
			AgentName:  "windsurf",
			WindowsDir: `C:\ProgramData\Devin`, WindowsFile: `C:\ProgramData\Devin\hooks.json`,
			UnixDir: `/etc/devin`, UnixFile: `/etc/devin/hooks.json`,
			DarwinDir: `/Library/Application Support/Devin`, DarwinFile: `/Library/Application Support/Devin/hooks.json`,
			BundleExt: "windsurf.hooks.json", Purpose: "hook-registration",
		},
		{
			// Legacy Windsurf location, read when the Devin file is absent.
			AgentName:  "windsurf",
			WindowsDir: `C:\ProgramData\Windsurf`, WindowsFile: `C:\ProgramData\Windsurf\hooks.json`,
			UnixDir: `/etc/windsurf`, UnixFile: `/etc/windsurf/hooks.json`,
			DarwinDir: `/Library/Application Support/Windsurf`, DarwinFile: `/Library/Application Support/Windsurf/hooks.json`,
			BundleExt: "windsurf.hooks.json", Purpose: "hook-registration",
		},
		{
			AgentName:  "cline",
			WindowsDir: `C:\ProgramData\AgentEdict`, WindowsFile: `C:\ProgramData\AgentEdict\cline-policy.json`,
			UnixDir: `/etc/agent-edict`, UnixFile: `/etc/agent-edict/cline-policy.json`,
			BundleExt: "cline.policy.json",
		},
		{
			AgentName:   "codex",
			WindowsDir:  `C:\ProgramData\OpenAI\Codex`,
			WindowsFile: `C:\ProgramData\OpenAI\Codex\requirements.toml`,
			UnixDir:     `/etc/codex`,
			UnixFile:    `/etc/codex/requirements.toml`,
			DarwinDir:   `/etc/codex`,
			DarwinFile:  `/etc/codex/requirements.toml`,
			BundleExt:   "codex.toml",
		},
		{
			AgentName:   "claude",
			WindowsDir:  `C:\Program Files\ClaudeCode`,
			WindowsFile: `C:\Program Files\ClaudeCode\managed-settings.json`,
			UnixDir:     `/etc/claude-code`,
			UnixFile:    `/etc/claude-code/managed-settings.json`,
			DarwinDir:   `/Library/Application Support/ClaudeCode`,
			DarwinFile:  `/Library/Application Support/ClaudeCode/managed-settings.json`,
			BundleExt:   "claude.json",
		},
		{
			AgentName:   "opencode",
			WindowsDir:  `C:\ProgramData\opencode`,
			WindowsFile: `C:\ProgramData\opencode\opencode.json`,
			UnixDir:     `/etc/opencode`,
			UnixFile:    `/etc/opencode/opencode.json`,
			DarwinDir:   `/Library/Application Support/opencode`,
			DarwinFile:  `/Library/Application Support/opencode/opencode.json`,
			BundleExt:   "opencode.json",
		},
		{
			AgentName:   "opencode",
			WindowsDir:  `C:\ProgramData\opencode`,
			WindowsFile: `C:\ProgramData\opencode\managed-instructions.md`,
			UnixDir:     `/etc/opencode`,
			UnixFile:    `/etc/opencode/managed-instructions.md`,
			DarwinDir:   `/Library/Application Support/opencode`,
			DarwinFile:  `/Library/Application Support/opencode/managed-instructions.md`,
			BundleExt:   "opencode.instructions.md",
		},
	}
}
