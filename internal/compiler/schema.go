package compiler

// UnifiedPolicy represents the single-source-of-truth policy schema in YAML.
type UnifiedPolicy struct {
	Version                         int                        `yaml:"version"`
	Name                            string                     `yaml:"name"`
	Description                     string                     `yaml:"description"`
	DefaultPermissions              string                     `yaml:"default_permissions,omitempty"`
	AllowedPermissionProfiles       map[string]bool            `yaml:"allowed_permission_profiles,omitempty"`
	PermissionDefs                  map[string]PermissionDef   `yaml:"permissions,omitempty"`
	Sandbox                         SandboxConfig              `yaml:"sandbox"`
	Approval                        ApprovalConfig             `yaml:"approval"`
	WebSearch                       WebSearchConfig            `yaml:"web_search"`
	BrowserUse                      *BrowserUseConfig          `yaml:"browser_use,omitempty"`
	ComputerUse                     *ComputerUseConfig         `yaml:"computer_use,omitempty"`
	Features                        *FeaturesConfig            `yaml:"features,omitempty"`
	Feedback                        *FeedbackConfig            `yaml:"feedback,omitempty"`
	WindowsPlatform                 *WindowsPlatformConfig     `yaml:"windows_platform,omitempty"`
	Filesystem                      FSConfig                   `yaml:"filesystem"`
	Commands                        CommandsConfig             `yaml:"commands"`
	MCPServers                      map[string]MCPServerConfig `yaml:"mcp_servers"`
	Otel                            OtelConfig                 `yaml:"otel"`
	Flags                           FlagsConfig                `yaml:"flags"`
	AdditionalDeveloperInstructions string                     `yaml:"additional_developer_instructions,omitempty"`
	GuardianExtraPolicy             string                     `yaml:"guardian_extra_policy,omitempty"`
	Claude                          *ClaudeConfig              `yaml:"claude,omitempty"`
	Login                           *LoginConfig               `yaml:"login,omitempty"`
	ModelProvider                   string                     `yaml:"model_provider,omitempty"`
	CodexModel                      *string                    `yaml:"codex_model,omitempty"`
	ModelProviders                  map[string]ModelProvider   `yaml:"model_providers,omitempty"`
	ApplicationNetwork              *ApplicationNetworkConfig  `yaml:"application_network,omitempty"`
	// Plugins approves the MCP servers Codex plugins bundle; an empty map
	// approves none, and nil leaves plugin servers unrestricted.
	Plugins map[string]PluginPolicy `yaml:"plugins"`
}

type SandboxConfig struct {
	Modes []string `yaml:"modes"` // e.g. ["read-only", "workspace-write"]
}

type ApprovalConfig struct {
	Policies   []string `yaml:"policies"`            // e.g. ["untrusted", "on-request"]
	Reviewers  []string `yaml:"reviewers,omitempty"` // e.g. ["auto_review", "user"]
	BypassMode string   `yaml:"bypass_mode"`         // "forbidden" or "allowed"
}

type WebSearchConfig struct {
	Modes []string `yaml:"modes"` // e.g. ["cached", "disabled", "live", "indexed"]
}

type PermissionDef struct {
	Description string                `yaml:"description"`
	Extends     string                `yaml:"extends"`
	Filesystem  *PermissionFilesystem `yaml:"filesystem,omitempty"`
	Network     *PermissionNetwork    `yaml:"network,omitempty"`
}

type PermissionFilesystem struct {
	Root             string            `yaml:":root"`
	Minimal          string            `yaml:":minimal"`
	Tmpdir           string            `yaml:":tmpdir"`
	SlashTmp         string            `yaml:":slash_tmp"`
	GlobScanMaxDepth int               `yaml:"glob_scan_max_depth"`
	WorkspaceRoots   map[string]string `yaml:":workspace_roots"`
}

type PermissionNetwork struct {
	Enabled bool `yaml:"enabled"`
}

type ComputerUseConfig struct {
	AllowLockedComputerUse bool `yaml:"allow_locked_computer_use"`
}

type BrowserUseConfig struct {
	AllowHistoryAccess            bool                `yaml:"allow_history_access"`
	AllowGlobalPersistentApproval bool                `yaml:"allow_global_persistent_approval"`
	DefaultOriginPolicy           DefaultOriginPolicy `yaml:"default_origin_policy"`
}

type DefaultOriginPolicy struct {
	Access                 string `yaml:"access"`
	Uploads                string `yaml:"uploads"`
	Downloads              string `yaml:"downloads"`
	FullCDPAccess          string `yaml:"full_cdp_access"`
	PersistentApproval     bool   `yaml:"persistent_approval"`
	AccessApprovalLifetime string `yaml:"access_approval_lifetime"`
}

type FeaturesConfig struct {
	Apps                    *bool `yaml:"apps,omitempty"`
	BrowserUse              *bool `yaml:"browser_use,omitempty"`
	BrowserUseExternal      *bool `yaml:"browser_use_external,omitempty"`
	BrowserUseFullCDPAccess *bool `yaml:"browser_use_full_cdp_access,omitempty"`
	ComputerUse             *bool `yaml:"computer_use,omitempty"`
	InAppBrowser            *bool `yaml:"in_app_browser,omitempty"`
	Memories                *bool `yaml:"memories,omitempty"`
	MultiAgent              *bool `yaml:"multi_agent,omitempty"`
	PluginSharing           *bool `yaml:"plugin_sharing,omitempty"`
	Plugins                 *bool `yaml:"plugins,omitempty"`
	RemotePlugin            *bool `yaml:"remote_plugin,omitempty"`
	GuardianApproval        *bool `yaml:"guardian_approval,omitempty"`
	PreferMXC               *bool `yaml:"prefer_mxc,omitempty"`
}

type FeedbackConfig struct {
	Enabled bool `yaml:"enabled"`
}

type WindowsPlatformConfig struct {
	AllowedSandboxImplementations []string `yaml:"allowed_sandbox_implementations"`
	AllowMXC                      *bool    `yaml:"allow_mxc,omitempty"`
}

// LoginConfig limits how users sign in to Codex: "chatgpt", "api" or both.
type LoginConfig struct {
	Methods []string `yaml:"methods"`
}

// ModelProvider is a Codex model provider that replaces any provider of the
// same name users configure.
type ModelProvider struct {
	Name               string `yaml:"name,omitempty" toml:"name"`
	BaseURL            string `yaml:"base_url,omitempty" toml:"base_url"`
	WireAPI            string `yaml:"wire_api,omitempty" toml:"wire_api"`
	EnvKey             string `yaml:"env_key,omitempty" toml:"env_key"`
	RequiresOpenAIAuth *bool  `yaml:"requires_openai_auth,omitempty" toml:"requires_openai_auth"`
}

// ApplicationNetworkConfig limits the Codex desktop app's own outbound
// destinations to exact host names. Unlisted hosts are blocked.
type ApplicationNetworkConfig struct {
	Enabled bool              `yaml:"enabled"`
	Domains map[string]string `yaml:"domains"`
}

// PluginPolicy lists the MCP servers one Codex plugin may run.
type PluginPolicy struct {
	MCPServers map[string]PluginMCPServer `yaml:"mcp_servers"`
}

// PluginMCPServer identifies a plugin's MCP server by URL or by launch command.
type PluginMCPServer struct {
	URL     string `yaml:"url,omitempty"`
	Command string `yaml:"command,omitempty"`
}

type PathGroup struct {
	Common  []string `yaml:"common"`
	Windows []string `yaml:"windows"`
	Unix    []string `yaml:"unix"`
}

type FSConfig struct {
	DenyRead  PathGroup `yaml:"deny_read"`
	DenyWrite PathGroup `yaml:"deny_write"`
}

type CommandGroup struct {
	Common  []string `yaml:"common"`
	Windows []string `yaml:"windows"`
	Unix    []string `yaml:"unix"`
}

type CommandsConfig struct {
	Allow  CommandGroup `yaml:"allow"`
	Prompt CommandGroup `yaml:"prompt"`
	Deny   CommandGroup `yaml:"deny"`
}

type MCPServerOS struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

type MCPServerConfig struct {
	Windows *MCPServerOS `yaml:"windows,omitempty"`
	Unix    *MCPServerOS `yaml:"unix,omitempty"`
	URL     string       `yaml:"url,omitempty"`
	Trust   bool         `yaml:"trust"`
}

type OtelConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Endpoint      string `yaml:"endpoint"`
	LogUserPrompt bool   `yaml:"log_user_prompt"`
}

type FlagsConfig struct {
	AllowAppshots              *bool `yaml:"allow_appshots,omitempty"`
	AllowBrowserAndComputerUse *bool `yaml:"allow_browser_and_computer_use,omitempty"`
	AllowManagedHooksOnly      *bool `yaml:"allow_managed_hooks_only,omitempty"`
	AllowLoginShell            *bool `yaml:"allow_login_shell,omitempty"`
	AllowRemoteControl         *bool `yaml:"allow_remote_control,omitempty"`
	DisableAutoUpdate          bool  `yaml:"disable_auto_update"`
}

// CompileOutput holds the compiled strings for all supported agent formats.
type CompileOutput struct {
	CodexRequirementsTOML string
	ClaudeManagedSettings string
	// Deprecated: use CompileNative for Gemini tool rules; this field is always empty.
	GeminiSettingsJSON string
	OpenCodeJSON       string
	// Install as managed-instructions.md beside opencode.json, even when empty.
	OpenCodeInstructions string
	// Deprecated: use CompileNative for Cursor hooks; this field is always empty.
	CursorJSON string
}
