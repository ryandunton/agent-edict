package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// LoadPolicy parses a YAML unified policy file.
func LoadPolicy(path string) (*UnifiedPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return ParsePolicy(data)
}

// ParsePolicy decodes and validates a unified profile from YAML bytes, with
// the same checks as LoadPolicy.
func ParsePolicy(data []byte) (*UnifiedPolicy, error) {
	var p UnifiedPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("policy YAML must contain exactly one document")
	}
	if err := validatePolicy(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

var policyNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var envKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// dnsName matches the exact host names Codex accepts in [application.network.domains].
var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validatePolicy(p *UnifiedPolicy) error {
	if p == nil {
		return fmt.Errorf("policy is required")
	}
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d: expected version 1", p.Version)
	}
	if !policyNamePattern.MatchString(p.Name) {
		return fmt.Errorf("policy name must contain only letters, numbers, underscores, and hyphens")
	}
	if len(p.Filesystem.DenyWrite.Common)+len(p.Filesystem.DenyWrite.Windows)+len(p.Filesystem.DenyWrite.Unix) > 0 {
		return fmt.Errorf("filesystem.deny_write is unsupported by the current adapters; use an explicit Codex permission profile instead")
	}
	if err := validateCodexRequirements(p); err != nil {
		return err
	}
	return validateClientGateways(p)
}

// validateCodexRequirements checks the Codex-only enterprise controls.
func validateCodexRequirements(p *UnifiedPolicy) error {
	if p.Login != nil {
		seen := map[string]bool{}
		for _, method := range p.Login.Methods {
			if (method != "chatgpt" && method != "api") || seen[method] {
				return fmt.Errorf("login.methods must list chatgpt, api or both, each once; %q is not allowed", method)
			}
			seen[method] = true
		}
		if len(seen) == 0 {
			return fmt.Errorf("login.methods must list chatgpt, api or both")
		}
	}
	if n := p.ApplicationNetwork; n != nil {
		seen := map[string]string{}
		for host, decision := range n.Domains {
			if decision != "allow" && decision != "deny" {
				return fmt.Errorf("application_network.domains.%s must be allow or deny", host)
			}
			// Codex compares hosts this way and refuses the whole file over one bad name.
			normalized := strings.ToLower(strings.TrimSuffix(host, "."))
			if len(normalized) > 253 || !dnsName.MatchString(normalized) {
				return fmt.Errorf("application_network.domains: %q must be an exact host name, without a scheme, port, path or wildcard", host)
			}
			if other, dup := seen[normalized]; dup {
				return fmt.Errorf("application_network.domains: %q and %q are the same host", other, host)
			}
			seen[normalized] = host
		}
	}
	policy := p.BrowserUse
	if policy == nil {
		policy = &BrowserUseConfig{}
	}
	for key, value := range map[string]string{"access": policy.DefaultOriginPolicy.Access, "uploads": policy.DefaultOriginPolicy.Uploads,
		"downloads": policy.DefaultOriginPolicy.Downloads, "full_cdp_access": policy.DefaultOriginPolicy.FullCDPAccess} {
		if value != "" && value != "allow" && value != "deny" {
			return fmt.Errorf("browser_use.default_origin_policy.%s must be allow or deny, not %q", key, value)
		}
	}
	if l := policy.DefaultOriginPolicy.AccessApprovalLifetime; l != "" && l != "turn" && l != "thread" {
		return fmt.Errorf("browser_use.default_origin_policy.access_approval_lifetime must be turn or thread, not %q", l)
	}
	if err := validateCodexGateway(p.ModelProvider, p.CodexModel, p.ModelProviders); err != nil {
		return err
	}
	for plugin, policy := range p.Plugins {
		for server, srv := range policy.MCPServers {
			if (srv.URL == "") == (srv.Command == "") {
				return fmt.Errorf("plugins.%s.mcp_servers.%s needs exactly one of url or command", plugin, server)
			}
		}
	}
	return nil
}

func validateCodexGateway(selected string, model *string, providers map[string]ModelProvider) error {
	if model != nil && strings.TrimSpace(*model) == "" {
		return fmt.Errorf("codex_model must be nonempty")
	}
	if model != nil && selected == "" {
		return fmt.Errorf("codex_model requires model_provider")
	}
	if selected != "" && selected != "openai" && selected != "ollama" && selected != "lmstudio" && selected != "amazon-bedrock" {
		if _, ok := providers[selected]; !ok {
			return fmt.Errorf("model_provider must name a configured model_providers entry")
		}
	}
	for name, provider := range providers {
		if !policyNamePattern.MatchString(name) || name == "openai" || name == "ollama" || name == "lmstudio" || name == "amazon-bedrock" {
			return fmt.Errorf("model_providers contains an invalid or reserved provider ID")
		}
		if provider.WireAPI != "" && provider.WireAPI != "responses" {
			return fmt.Errorf("model_providers.%s.wire_api must be responses, the only API Codex speaks", name)
		}
		if err := validateGatewayURL("model_providers."+name+".base_url", provider.BaseURL); err != nil {
			return err
		}
		if provider.RequiresOpenAIAuth != nil && *provider.RequiresOpenAIAuth && provider.EnvKey != "" {
			return fmt.Errorf("model_providers.%s.requires_openai_auth cannot be true when env_key is used", name)
		}
		if (provider.RequiresOpenAIAuth == nil || !*provider.RequiresOpenAIAuth) && !envKeyPattern.MatchString(provider.EnvKey) {
			return fmt.Errorf("model_providers.%s.env_key must name an uppercase environment variable", name)
		}
	}
	return nil
}

// ValidateCodexGatewayTOML checks compiled provider settings again when a
// signed bundle is validated, including bundles edited after compilation.
func ValidateCodexGatewayTOML(data []byte) error {
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return err
	}
	if providers, ok := raw["model_providers"].(map[string]any); ok {
		for name, definition := range providers {
			fields, ok := definition.(map[string]any)
			if !ok {
				return fmt.Errorf("model_providers.%s must be a table", name)
			}
			for field := range fields {
				switch field {
				case "name", "base_url", "wire_api", "env_key", "requires_openai_auth":
				default:
					return fmt.Errorf("model_providers.%s.%s is unsupported", name, field)
				}
			}
		}
	}
	var parsed struct {
		ModelProvider  string                   `toml:"model_provider"`
		ModelProviders map[string]ModelProvider `toml:"model_providers"`
		Models         struct {
			NewThread struct {
				Model *string `toml:"model"`
			} `toml:"new_thread"`
		} `toml:"models"`
	}
	if err := toml.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("invalid Codex gateway setting type")
	}
	return validateCodexGateway(parsed.ModelProvider, parsed.Models.NewThread.Model, parsed.ModelProviders)
}

func validateTargetOS(targetOS string) error {
	if targetOS != "windows" && targetOS != "linux" && targetOS != "darwin" {
		return fmt.Errorf("unsupported target OS %q", targetOS)
	}
	return nil
}

func isStrictReadOnly(p *UnifiedPolicy) bool {
	return len(p.Sandbox.Modes) == 1 && p.Sandbox.Modes[0] == "read-only"
}

// CompileCodexOnly produces the two Codex files for a restrictive read-only
// policy. Other adapters currently cannot guarantee this policy's boundaries.
func CompileCodexOnly(p *UnifiedPolicy, targetOS string) (string, string, error) {
	if err := validatePolicy(p); err != nil {
		return "", "", err
	}
	if err := validateTargetOS(targetOS); err != nil {
		return "", "", err
	}
	if isStrictReadOnly(p) {
		if err := validateStrictReadOnly(p); err != nil {
			return "", "", err
		}
	}
	requirements, err := compileCodex(p, targetOS == "windows")
	if err != nil {
		return "", "", err
	}
	return requirements, compileCodexTelemetry(p), nil
}

func validateStrictReadOnly(p *UnifiedPolicy) error {
	if len(p.Approval.Policies) != 1 || p.Approval.Policies[0] != "never" || p.Approval.BypassMode != "forbidden" {
		return fmt.Errorf("read-only policy requires approval=never and bypass_mode=forbidden")
	}
	if len(p.WebSearch.Modes) != 1 || p.WebSearch.Modes[0] != "disabled" {
		return fmt.Errorf("read-only policy requires disabled web search")
	}
	if p.MCPServers == nil || len(p.MCPServers) != 0 {
		return fmt.Errorf("read-only policy requires an explicit empty MCP server allowlist")
	}
	def, ok := p.PermissionDefs[p.DefaultPermissions]
	if !ok || !p.AllowedPermissionProfiles[p.DefaultPermissions] || def.Filesystem == nil || def.Network == nil {
		return fmt.Errorf("read-only policy requires an allowed custom permission profile with filesystem and network rules")
	}
	for name, allowed := range p.AllowedPermissionProfiles {
		if allowed && name != p.DefaultPermissions {
			return fmt.Errorf("read-only policy cannot allow alternate permission profile %q", name)
		}
	}
	if def.Extends != "" && def.Extends != ":read-only" {
		return fmt.Errorf("read-only policy cannot extend write-capable permission profile %q", def.Extends)
	}
	fs := def.Filesystem
	if fs.Root != "deny" || fs.Minimal != "read" || fs.Tmpdir != "deny" || fs.SlashTmp != "deny" || fs.WorkspaceRoots["."] != "read" || def.Network.Enabled {
		return fmt.Errorf("read-only policy must limit reads to the workspace and minimal runtime, deny temp access, and disable command networking")
	}
	for path, access := range fs.WorkspaceRoots {
		if access != "read" && access != "deny" {
			return fmt.Errorf("read-only policy has invalid access %q for workspace path %q", access, path)
		}
	}
	if p.Features == nil || p.Features.Apps == nil || *p.Features.Apps || p.Features.BrowserUse == nil || *p.Features.BrowserUse || p.Features.ComputerUse == nil || *p.Features.ComputerUse || p.Features.InAppBrowser == nil || *p.Features.InAppBrowser || p.Features.Plugins == nil || *p.Features.Plugins {
		return fmt.Errorf("read-only policy must disable apps, browser use, computer use, in-app browser, and plugins")
	}
	if p.Flags.AllowAppshots == nil || *p.Flags.AllowAppshots || p.Flags.AllowBrowserAndComputerUse == nil || *p.Flags.AllowBrowserAndComputerUse {
		return fmt.Errorf("read-only policy must disable Appshots and browser/computer use")
	}
	if p.Flags.AllowLoginShell == nil || *p.Flags.AllowLoginShell || p.Flags.AllowManagedHooksOnly == nil || !*p.Flags.AllowManagedHooksOnly || p.Flags.AllowRemoteControl == nil || *p.Flags.AllowRemoteControl {
		return fmt.Errorf("read-only policy must disable login shells and remote control and permit managed hooks only")
	}
	if len(p.Commands.Prompt.Common)+len(p.Commands.Prompt.Windows)+len(p.Commands.Prompt.Unix) != 0 {
		return fmt.Errorf("read-only policy cannot have prompt-based command rules")
	}
	return nil
}

// Compile emits supported Codex, Claude, and OpenCode files for the target OS.
// Gemini, Cursor and Antigravity use explicit native controls via CompileNative;
// the legacy Gemini/Cursor compatibility output fields remain empty here.
func Compile(p *UnifiedPolicy, targetOS string) (*CompileOutput, error) {
	if err := validatePolicy(p); err != nil {
		return nil, err
	}
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	isWindows := targetOS == "windows"
	if err := openCodeRejection(p, isWindows); err != nil {
		return nil, err
	}
	claudeMode, _, err := claudeSandboxMode(p, targetOS)
	if err != nil {
		return nil, err
	}

	codexTOML, err := compileCodex(p, isWindows)
	if err != nil {
		return nil, fmt.Errorf("compile codex: %w", err)
	}

	claudeJSON, err := compileClaude(p, isWindows, claudeMode)
	if err != nil {
		return nil, fmt.Errorf("compile claude: %w", err)
	}

	openCodeJSON, err := compileOpenCode(p, targetOS)
	if err != nil {
		return nil, fmt.Errorf("compile opencode: %w", err)
	}

	return &CompileOutput{
		CodexRequirementsTOML: codexTOML,
		ClaudeManagedSettings: claudeJSON,
		OpenCodeJSON:          openCodeJSON,
		OpenCodeInstructions:  compileInstructions(p),
	}, nil
}

func getPathList(pg PathGroup, isWindows bool) []string {
	var paths []string
	paths = append(paths, pg.Common...)
	if isWindows {
		paths = append(paths, pg.Windows...)
	} else {
		paths = append(paths, pg.Unix...)
	}
	return cleanList(paths)
}

func getCmdList(cg CommandGroup, isWindows bool) []string {
	var cmds []string
	cmds = append(cmds, cg.Common...)
	if isWindows {
		cmds = append(cmds, cg.Windows...)
	} else {
		cmds = append(cmds, cg.Unix...)
	}
	return cleanList(cmds)
}

func cleanList(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func formatTOMLStringSlice(slice []string) string {
	quoted := make([]string, len(slice))
	for i, s := range slice {
		quoted[i] = tomlString(s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

var tomlBareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// tomlKey quotes names that are not TOML bare keys, so "a.b" stays one key.
func tomlKey(name string) string {
	if tomlBareKey.MatchString(name) {
		return name
	}
	return tomlString(name)
}

// tomlString returns a TOML basic string. Go's %q is not a substitute: it
// emits escapes such as \x7f and \v that TOML rejects.
func tomlString(s string) string {
	return `"` + tomlEscape(s, false) + `"`
}

// tomlMultiline returns a multi-line basic string with literal newlines.
// Escaping every backslash and quote keeps Windows paths and """ verbatim.
func tomlMultiline(s string) string {
	return "\"\"\"\n" + tomlEscape(s, true) + "\n\"\"\""
}

func tomlEscape(s string, multiline bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n' && multiline:
			b.WriteByte('\n')
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// compileCodex generates requirements.toml
func compileCodex(p *UnifiedPolicy, isWindows bool) (string, error) {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Generated policy for profile %q\n", p.Name))

	if p.DefaultPermissions != "" {
		b.WriteString(fmt.Sprintf("default_permissions = %s\n", tomlString(p.DefaultPermissions)))
	}

	if len(p.Sandbox.Modes) > 0 {
		b.WriteString(fmt.Sprintf("allowed_sandbox_modes = %s\n", formatTOMLStringSlice(p.Sandbox.Modes)))
	}
	if len(p.Approval.Policies) > 0 {
		b.WriteString(fmt.Sprintf("allowed_approval_policies = %s\n", formatTOMLStringSlice(p.Approval.Policies)))
	}
	if len(p.Approval.Reviewers) > 0 {
		b.WriteString(fmt.Sprintf("allowed_approvals_reviewers = %s\n", formatTOMLStringSlice(p.Approval.Reviewers)))
	}
	if len(p.WebSearch.Modes) == 1 && p.WebSearch.Modes[0] == "disabled" {
		b.WriteString("allowed_web_search_modes = []\n")
	} else if len(p.WebSearch.Modes) > 0 {
		b.WriteString(fmt.Sprintf("allowed_web_search_modes = %s\n", formatTOMLStringSlice(p.WebSearch.Modes)))
	}
	if p.Login != nil {
		b.WriteString(fmt.Sprintf("allowed_login_methods = %s\n", formatTOMLStringSlice(p.Login.Methods)))
	}
	if p.ModelProvider != "" {
		b.WriteString(fmt.Sprintf("model_provider = %s\n", tomlString(p.ModelProvider)))
	}

	if p.Flags.AllowAppshots != nil {
		b.WriteString(fmt.Sprintf("allow_appshots = %t\n", *p.Flags.AllowAppshots))
	}
	if p.Flags.AllowBrowserAndComputerUse != nil {
		b.WriteString(fmt.Sprintf("allow_browser_and_computer_use = %t\n", *p.Flags.AllowBrowserAndComputerUse))
	}
	if p.Flags.AllowLoginShell != nil {
		b.WriteString(fmt.Sprintf("allow_login_shell = %t\n", *p.Flags.AllowLoginShell))
	}
	if p.Flags.AllowManagedHooksOnly != nil {
		b.WriteString(fmt.Sprintf("allow_managed_hooks_only = %t\n", *p.Flags.AllowManagedHooksOnly))
	} else {
		b.WriteString("allow_managed_hooks_only = true\n")
	}
	if p.Flags.AllowRemoteControl != nil {
		b.WriteString(fmt.Sprintf("allow_remote_control = %t\n", *p.Flags.AllowRemoteControl))
	}
	if p.MCPServers != nil && len(p.MCPServers) == 0 {
		b.WriteString("mcp_servers = {}\n")
	}
	if p.Plugins != nil && len(p.Plugins) == 0 {
		b.WriteString("plugins = {}\n")
	}

	if strings.TrimSpace(p.AdditionalDeveloperInstructions) != "" {
		b.WriteString("\nadditional_developer_instructions = " + tomlMultiline(strings.TrimSpace(p.AdditionalDeveloperInstructions)) + "\n")
	}

	if strings.TrimSpace(p.GuardianExtraPolicy) != "" {
		b.WriteString("\nguardian_extra_policy = " + tomlMultiline(strings.TrimSpace(p.GuardianExtraPolicy)) + "\n")
	}

	if len(p.PermissionDefs) > 0 {
		var pNames []string
		for k := range p.PermissionDefs {
			pNames = append(pNames, k)
		}
		sort.Strings(pNames)
		for _, k := range pNames {
			pDef := p.PermissionDefs[k]
			b.WriteString(fmt.Sprintf("\n[permissions.%s]\n", tomlKey(k)))
			b.WriteString(fmt.Sprintf("description = %s\n", tomlString(pDef.Description)))
			if pDef.Extends != "" {
				b.WriteString(fmt.Sprintf("extends = %s\n", tomlString(pDef.Extends)))
			}
			if fs := pDef.Filesystem; fs != nil {
				b.WriteString(fmt.Sprintf("\n[permissions.%s.filesystem]\n", tomlKey(k)))
				for _, entry := range []struct{ path, access string }{
					{":root", fs.Root}, {":minimal", fs.Minimal}, {":tmpdir", fs.Tmpdir}, {":slash_tmp", fs.SlashTmp},
				} {
					if entry.access != "" {
						b.WriteString(fmt.Sprintf("%s = %s\n", tomlString(entry.path), tomlString(entry.access)))
					}
				}
				if fs.GlobScanMaxDepth > 0 {
					b.WriteString(fmt.Sprintf("glob_scan_max_depth = %d\n", fs.GlobScanMaxDepth))
				}
				if len(fs.WorkspaceRoots) > 0 {
					b.WriteString(fmt.Sprintf("\n[permissions.%s.filesystem.\":workspace_roots\"]\n", tomlKey(k)))
					var paths []string
					for path := range fs.WorkspaceRoots {
						paths = append(paths, path)
					}
					sort.Strings(paths)
					for _, path := range paths {
						b.WriteString(fmt.Sprintf("%s = %s\n", tomlString(path), tomlString(fs.WorkspaceRoots[path])))
					}
				}
			}
			if pDef.Network != nil {
				b.WriteString(fmt.Sprintf("\n[permissions.%s.network]\n", tomlKey(k)))
				b.WriteString(fmt.Sprintf("enabled = %t\n", pDef.Network.Enabled))
			}
		}
	}

	if len(p.AllowedPermissionProfiles) > 0 {
		var profNames []string
		for k := range p.AllowedPermissionProfiles {
			profNames = append(profNames, k)
		}
		sort.Strings(profNames)
		b.WriteString("\n[allowed_permission_profiles]\n")
		for _, k := range profNames {
			val := p.AllowedPermissionProfiles[k]
			if strings.HasPrefix(k, ":") || strings.Contains(k, "-") || !tomlBareKey.MatchString(k) {
				b.WriteString(fmt.Sprintf("%s = %t\n", tomlString(k), val))
			} else {
				b.WriteString(fmt.Sprintf("%s = %t\n", k, val))
			}
		}
	}

	if p.BrowserUse != nil {
		b.WriteString("\n[browser_use]\n")
		b.WriteString(fmt.Sprintf("allow_history_access = %t\n", p.BrowserUse.AllowHistoryAccess))
		b.WriteString(fmt.Sprintf("allow_global_persistent_approval = %t\n", p.BrowserUse.AllowGlobalPersistentApproval))

		// Unset origin fields are left out so Codex applies its own defaults.
		policy := p.BrowserUse.DefaultOriginPolicy
		b.WriteString("\n[browser_use.default_origin_policy]\n")
		for _, field := range []struct{ key, value string }{
			{"access", policy.Access}, {"uploads", policy.Uploads}, {"downloads", policy.Downloads}, {"full_cdp_access", policy.FullCDPAccess},
		} {
			if field.value != "" {
				b.WriteString(fmt.Sprintf("%s = %s\n", field.key, tomlString(field.value)))
			}
		}
		b.WriteString(fmt.Sprintf("persistent_approval = %t\n", policy.PersistentApproval))
		if policy.AccessApprovalLifetime != "" {
			b.WriteString(fmt.Sprintf("access_approval_lifetime = %s\n", tomlString(policy.AccessApprovalLifetime)))
		}
	}

	if p.ComputerUse != nil {
		b.WriteString("\n[computer_use]\n")
		b.WriteString(fmt.Sprintf("allow_locked_computer_use = %t\n", p.ComputerUse.AllowLockedComputerUse))
	}

	if p.Features != nil {
		b.WriteString("\n[features]\n")
		if p.Features.Apps != nil {
			b.WriteString(fmt.Sprintf("apps = %t\n", *p.Features.Apps))
		}
		if p.Features.BrowserUse != nil {
			b.WriteString(fmt.Sprintf("browser_use = %t\n", *p.Features.BrowserUse))
		}
		if p.Features.BrowserUseExternal != nil {
			b.WriteString(fmt.Sprintf("browser_use_external = %t\n", *p.Features.BrowserUseExternal))
		}
		if p.Features.BrowserUseFullCDPAccess != nil {
			b.WriteString(fmt.Sprintf("browser_use_full_cdp_access = %t\n", *p.Features.BrowserUseFullCDPAccess))
		}
		if p.Features.ComputerUse != nil {
			b.WriteString(fmt.Sprintf("computer_use = %t\n", *p.Features.ComputerUse))
		}
		if p.Features.InAppBrowser != nil {
			b.WriteString(fmt.Sprintf("in_app_browser = %t\n", *p.Features.InAppBrowser))
		}
		if p.Features.Memories != nil {
			b.WriteString(fmt.Sprintf("memories = %t\n", *p.Features.Memories))
		}
		if p.Features.MultiAgent != nil {
			b.WriteString(fmt.Sprintf("multi_agent = %t\n", *p.Features.MultiAgent))
		}
		if p.Features.PluginSharing != nil {
			b.WriteString(fmt.Sprintf("plugin_sharing = %t\n", *p.Features.PluginSharing))
		}
		if p.Features.Plugins != nil {
			b.WriteString(fmt.Sprintf("plugins = %t\n", *p.Features.Plugins))
		}
		if p.Features.RemotePlugin != nil {
			b.WriteString(fmt.Sprintf("remote_plugin = %t\n", *p.Features.RemotePlugin))
		}
		if p.Features.GuardianApproval != nil {
			b.WriteString(fmt.Sprintf("guardian_approval = %t\n", *p.Features.GuardianApproval))
		}
		if p.Features.PreferMXC != nil {
			b.WriteString(fmt.Sprintf("prefer_mxc = %t\n", *p.Features.PreferMXC))
		}
	}

	if p.Feedback != nil {
		b.WriteString("\n[feedback]\n")
		b.WriteString(fmt.Sprintf("enabled = %t\n", p.Feedback.Enabled))
	}

	if w := p.WindowsPlatform; isWindows && w != nil && (len(w.AllowedSandboxImplementations) > 0 || w.AllowMXC != nil) {
		b.WriteString("\n[windows]\n")
		if len(w.AllowedSandboxImplementations) > 0 {
			b.WriteString(fmt.Sprintf("allowed_sandbox_implementations = %s\n", formatTOMLStringSlice(w.AllowedSandboxImplementations)))
		}
		if w.AllowMXC != nil {
			b.WriteString(fmt.Sprintf("allow_mxc = %t\n", *w.AllowMXC))
		}
	}

	if n := p.ApplicationNetwork; n != nil {
		b.WriteString("\n[application.network]\n")
		b.WriteString(fmt.Sprintf("enabled = %t\n", n.Enabled))
		if n.Domains != nil && len(n.Domains) == 0 {
			b.WriteString("domains = {}\n")
		} else if len(n.Domains) > 0 {
			hosts := make([]string, 0, len(n.Domains))
			for host := range n.Domains {
				hosts = append(hosts, host)
			}
			sort.Strings(hosts)
			b.WriteString("\n[application.network.domains]\n")
			for _, host := range hosts {
				b.WriteString(fmt.Sprintf("%s = %s\n", tomlString(host), tomlString(n.Domains[host])))
			}
		}
	}

	denyReadPaths := getPathList(p.Filesystem.DenyRead, isWindows)
	if len(denyReadPaths) > 0 {
		b.WriteString("\n[permissions.filesystem]\n")
		b.WriteString("deny_read = [\n")
		for _, path := range denyReadPaths {
			b.WriteString(fmt.Sprintf("  %s,\n", tomlString(path)))
		}
		b.WriteString("]\n")
	}

	promptCmds := getCmdList(p.Commands.Prompt, isWindows)
	for _, cmd := range promptCmds {
		tokens := strings.Fields(cmd)
		if len(tokens) == 0 {
			continue
		}
		var tokenParts []string
		for _, tok := range tokens {
			tokenParts = append(tokenParts, fmt.Sprintf("{ token = %s }", tomlString(tok)))
		}
		b.WriteString("\n[[rules.prefix_rules]]\n")
		b.WriteString(fmt.Sprintf("pattern = [%s]\n", strings.Join(tokenParts, ", ")))
		b.WriteString("decision = \"prompt\"\n")
	}

	denyCmds := getCmdList(p.Commands.Deny, isWindows)
	for _, cmd := range denyCmds {
		tokens := strings.Fields(cmd)
		if len(tokens) == 0 {
			continue
		}
		var tokenParts []string
		for _, tok := range tokens {
			tokenParts = append(tokenParts, fmt.Sprintf("{ token = %s }", tomlString(tok)))
		}
		b.WriteString("\n[[rules.prefix_rules]]\n")
		b.WriteString(fmt.Sprintf("pattern = [%s]\n", strings.Join(tokenParts, ", ")))
		b.WriteString("decision = \"forbidden\"\n")
	}

	// MCP Servers
	var mcpNames []string
	for k := range p.MCPServers {
		mcpNames = append(mcpNames, k)
	}
	sort.Strings(mcpNames)

	for _, name := range mcpNames {
		srv := p.MCPServers[name]
		b.WriteString(fmt.Sprintf("\n[mcp_servers.%s]\n", tomlKey(name)))
		if srv.URL != "" {
			b.WriteString(fmt.Sprintf("identity = { url = %s }\n", tomlString(srv.URL)))
		} else if isWindows && srv.Windows != nil && srv.Windows.Command != "" {
			b.WriteString(fmt.Sprintf("identity = { command = %s }\n", tomlString(srv.Windows.Command)))
		} else if !isWindows && srv.Unix != nil && srv.Unix.Command != "" {
			b.WriteString(fmt.Sprintf("identity = { command = %s }\n", tomlString(srv.Unix.Command)))
		}
	}

	plugins := make([]string, 0, len(p.Plugins))
	for name := range p.Plugins {
		plugins = append(plugins, name)
	}
	sort.Strings(plugins)
	for _, plugin := range plugins {
		servers := p.Plugins[plugin].MCPServers
		if len(servers) == 0 {
			b.WriteString(fmt.Sprintf("\n[plugins.%s]\nmcp_servers = {}\n", tomlKey(plugin)))
			continue
		}
		names := make([]string, 0, len(servers))
		for name := range servers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			srv := servers[name]
			b.WriteString(fmt.Sprintf("\n[plugins.%s.mcp_servers.%s]\n", tomlKey(plugin), tomlKey(name)))
			if srv.URL != "" {
				b.WriteString(fmt.Sprintf("identity = { url = %s }\n", tomlString(srv.URL)))
			} else {
				b.WriteString(fmt.Sprintf("identity = { command = %s }\n", tomlString(srv.Command)))
			}
		}
	}

	providers := make([]string, 0, len(p.ModelProviders))
	for name := range p.ModelProviders {
		providers = append(providers, name)
	}
	sort.Strings(providers)
	for _, name := range providers {
		provider := p.ModelProviders[name]
		b.WriteString(fmt.Sprintf("\n[model_providers.%s]\n", tomlKey(name)))
		for _, field := range []struct{ key, value string }{
			{"name", provider.Name}, {"base_url", provider.BaseURL}, {"wire_api", provider.WireAPI}, {"env_key", provider.EnvKey},
		} {
			if field.value != "" {
				b.WriteString(fmt.Sprintf("%s = %s\n", field.key, tomlString(field.value)))
			}
		}
		if provider.RequiresOpenAIAuth != nil {
			b.WriteString(fmt.Sprintf("requires_openai_auth = %t\n", *provider.RequiresOpenAIAuth))
		}
	}
	if p.CodexModel != nil {
		b.WriteString(fmt.Sprintf("\n[models.new_thread]\nmodel = %s\n", tomlString(*p.CodexModel)))
	}

	return b.String(), nil
}

func compileCodexTelemetry(p *UnifiedPolicy) string {
	if !p.Otel.Enabled {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Replace the example endpoint in a private deployment.\n")
	b.WriteString("[otel]\n")
	b.WriteString(fmt.Sprintf("environment = %s\n", tomlString(p.Name)))
	b.WriteString(fmt.Sprintf("log_user_prompt = %t\n", p.Otel.LogUserPrompt))
	b.WriteString(fmt.Sprintf("exporter = { otlp-http = { endpoint = %s, protocol = \"binary\" } }\n", tomlString(p.Otel.Endpoint)))
	return b.String()
}

// compileClaude generates managed-settings.json for Claude Code
// claudePathPattern writes a path in Claude's rule syntax. Claude anchors a
// single leading slash at the settings file, so absolute paths need "//", and
// it matches Windows paths in POSIX form: C:\Users becomes /c/Users.
func claudePathPattern(path string) string {
	slashed := strings.ReplaceAll(path, `\`, "/")
	if len(slashed) >= 3 && slashed[1] == ':' && slashed[2] == '/' {
		drive := strings.ToLower(slashed[:1])
		if drive >= "a" && drive <= "z" {
			return "//" + drive + slashed[2:]
		}
	}
	if strings.HasPrefix(slashed, "/") && !strings.HasPrefix(slashed, "//") {
		return "/" + slashed
	}
	return path
}

func compileClaude(p *UnifiedPolicy, isWindows bool, sandboxMode string) (string, error) {
	allowCmds := getCmdList(p.Commands.Allow, isWindows)
	promptCmds := getCmdList(p.Commands.Prompt, isWindows)
	denyCmds := getCmdList(p.Commands.Deny, isWindows)
	denyPaths := getPathList(p.Filesystem.DenyRead, isWindows)

	var allows []string
	allows = append(allows, "Read(*)", "Edit(*)")
	for _, cmd := range allowCmds {
		allows = append(allows, fmt.Sprintf("Bash(%s:*)", cmd))
	}

	asks := make([]string, 0)
	for _, cmd := range promptCmds {
		asks = append(asks, fmt.Sprintf("Bash(%s:*)", cmd))
	}

	denies := make([]string, 0)
	for _, pth := range denyPaths {
		denies = append(denies, fmt.Sprintf("Read(%s/**)", claudePathPattern(pth)))
	}
	for _, cmd := range denyCmds {
		denies = append(denies, fmt.Sprintf("Bash(%s:*)", cmd))
	}

	type mcpServerRef struct {
		ServerName string `json:"serverName"`
	}
	allowedMcp := make([]mcpServerRef, 0)
	var mcpNames []string
	for k := range p.MCPServers {
		mcpNames = append(mcpNames, k)
	}
	sort.Strings(mcpNames)
	for _, name := range mcpNames {
		allowedMcp = append(allowedMcp, mcpServerRef{ServerName: name})
	}

	isNetworkDisabled := claudeNetworkDisabled(p)
	if isNetworkDisabled {
		denies = append(denies, "Bash(curl:*)", "Bash(wget:*)", "Bash(ssh:*)", "Bash(scp:*)")
	}

	data := map[string]interface{}{
		"permissions": map[string]interface{}{
			"disableBypassPermissionsMode": "disable",
			"allow":                        allows,
			"ask":                          asks,
			"deny":                         denies,
		},
		"allowManagedPermissionRulesOnly": true,
		"allowedMcpServers":               allowedMcp,
	}
	if p.Claude != nil && p.Claude.Gateway != nil {
		data["env"] = map[string]string{"ANTHROPIC_BASE_URL": p.Claude.Gateway.BaseURL}
		data["allowedProviders"] = []string{"customEndpoint"}
		if p.Claude.Gateway.Model != nil {
			data["model"] = *p.Claude.Gateway.Model
		}
	}
	if sandboxMode == ClaudeSandboxRequired && !isWindows {
		// The sandbox covers shell commands; the Read rules above cover Claude's
		// own file tools. Together they block reads of the denied paths.
		sandbox := map[string]interface{}{
			"enabled":                  true,
			"failIfUnavailable":        true,
			"allowUnsandboxedCommands": false,
			"filesystem": map[string]interface{}{
				"denyRead":                  append([]string{}, denyPaths...),
				"allowManagedReadPathsOnly": true,
			},
		}
		if isNetworkDisabled {
			sandbox["network"] = map[string]interface{}{
				"allowedDomains":          []string{},
				"strictAllowlist":         true,
				"allowManagedDomainsOnly": true,
			}
		}
		data["sandbox"] = sandbox
	}

	var instructions []string
	if strings.TrimSpace(p.AdditionalDeveloperInstructions) != "" {
		instructions = append(instructions, strings.TrimSpace(p.AdditionalDeveloperInstructions))
	}
	if strings.TrimSpace(p.GuardianExtraPolicy) != "" {
		instructions = append(instructions, strings.TrimSpace(p.GuardianExtraPolicy))
	}
	if len(instructions) > 0 {
		data["instructions"] = strings.Join(instructions, "\n\n")
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// compileGemini intentionally refuses managed output. Current Gemini source
// treats an empty mcp.allowed as unrestricted, permits CLI name-list overrides,
// and discards file-based admin controls in favor of remote administration.
// A system settings file therefore cannot establish the declared MCP boundary.
func compileGemini(p *UnifiedPolicy, isWindows bool) (string, error) {
	return "", fmt.Errorf("Gemini unified compilation is unsupported: use compile-native for explicit local tool rules; these do not enforce MCP process startup or an OS sandbox")
}

// compileOpenCode generates opencode.json for OpenCode
func compileOpenCode(p *UnifiedPolicy, targetOS string) (string, error) {
	isWindows := targetOS == "windows"
	allowCmds := getCmdList(p.Commands.Allow, isWindows)
	promptCmds := getCmdList(p.Commands.Prompt, isWindows)
	denyCmds := getCmdList(p.Commands.Deny, isWindows)

	// OpenCode applies the last matching pattern, so a command listed in
	// several groups keeps its strictest decision and stricter groups go last.
	strictness := map[string]int{"allow": 0, "ask": 1, "deny": 2}
	decisions := make(map[string]string)
	for decision, cmds := range map[string][]string{"allow": allowCmds, "ask": promptCmds, "deny": denyCmds} {
		for _, cmd := range cmds {
			if current, ok := decisions[cmd+"*"]; !ok || strictness[decision] > strictness[current] {
				decisions[cmd+"*"] = decision
			}
		}
	}
	var bashRules orderedRules
	for pattern, decision := range decisions {
		bashRules = append(bashRules, [2]string{pattern, decision})
	}
	sort.Slice(bashRules, func(i, j int) bool {
		a, b := strictness[bashRules[i][1]], strictness[bashRules[j][1]]
		return a < b || (a == b && bashRules[i][0] < bashRules[j][0])
	})

	type openCodeMCP struct {
		Type    string   `json:"type"`
		Command []string `json:"command,omitempty"`
		URL     string   `json:"url,omitempty"`
		Enabled bool     `json:"enabled"`
	}
	mcpMap := make(map[string]openCodeMCP)
	for name, srv := range p.MCPServers {
		if srv.URL != "" {
			mcpMap[name] = openCodeMCP{
				Type:    "remote",
				URL:     srv.URL,
				Enabled: true,
			}
		} else {
			var cmdList []string
			if isWindows && srv.Windows != nil {
				cmdList = append([]string{srv.Windows.Command}, srv.Windows.Args...)
			} else if !isWindows && srv.Unix != nil {
				cmdList = append([]string{srv.Unix.Command}, srv.Unix.Args...)
			}
			mcpMap[name] = openCodeMCP{
				Type:    "local",
				Command: cmdList,
				Enabled: true,
			}
		}
	}

	webfetchDecision := "ask"
	if len(p.WebSearch.Modes) > 0 {
		if p.WebSearch.Modes[0] == "disabled" {
			webfetchDecision = "deny"
		} else if p.WebSearch.Modes[0] == "live" {
			webfetchDecision = "allow"
		}
	}

	data := map[string]interface{}{
		"$schema": "https://opencode.ai/config.json",
		"permission": map[string]interface{}{
			"edit":     "allow",
			"webfetch": webfetchDecision,
			"bash":     bashRules,
		},
		"mcp": mcpMap,
	}
	if p.OpenCode != nil && p.OpenCode.Gateway != nil {
		g := p.OpenCode.Gateway
		pack := "@ai-sdk/openai-compatible"
		if g.WireAPI == "responses" {
			pack = "@ai-sdk/openai"
		}
		name := g.Name
		if name == "" {
			name = g.Provider
		}
		data["provider"] = map[string]interface{}{g.Provider: map[string]interface{}{
			"npm":  pack,
			"name": name,
			"options": map[string]string{
				"baseURL": g.BaseURL,
				"apiKey":  "{env:" + g.EnvKey + "}",
			},
			"models": map[string]interface{}{g.Model: map[string]string{"name": g.Model}},
		}}
		data["enabled_providers"] = []string{g.Provider}
		data["model"] = g.Provider + "/" + g.Model
		data["small_model"] = data["model"]
	}
	var instructionsPath string
	switch targetOS {
	case "windows":
		instructionsPath = "C:/ProgramData/opencode/managed-instructions.md"
	case "darwin":
		instructionsPath = "/Library/Application Support/opencode/managed-instructions.md"
	case "linux":
		instructionsPath = "/etc/opencode/managed-instructions.md"
	default:
		return "", fmt.Errorf("unsupported target OS %q", targetOS)
	}
	// Always reference the sidecar, including an empty one, so changing profiles
	// replaces any instructions installed for the previous profile.
	data["instructions"] = []string{instructionsPath}

	if p.PermissionDefs != nil && p.DefaultPermissions != "" {
		if def, ok := p.PermissionDefs[p.DefaultPermissions]; ok && def.Network != nil && !def.Network.Enabled {
			data["permission"].(map[string]interface{})["webfetch"] = "deny"
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// orderedRules encodes a JSON object whose key order is significant.
type orderedRules [][2]string

func (r orderedRules) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	b.WriteByte('{')
	for i, rule := range r {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := enc.Encode(rule[0]); err != nil {
			return nil, err
		}
		b.WriteByte(':')
		if err := enc.Encode(rule[1]); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func compileInstructions(p *UnifiedPolicy) string {
	var sections []string
	for _, text := range []string{p.AdditionalDeveloperInstructions, p.GuardianExtraPolicy} {
		if text = strings.TrimSpace(text); text != "" {
			sections = append(sections, text)
		}
	}
	if len(sections) == 0 {
		return ""
	}
	return strings.Join(sections, "\n\n") + "\n"
}

// compileCursor is intentionally unsupported: Cursor does not consume the
// invented cross-platform file format previously produced by this adapter.
func compileCursor(p *UnifiedPolicy, isWindows bool) (string, error) {
	return "", fmt.Errorf("Cursor unified compilation is unsupported: use compile-native for explicit local hook controls; these do not enforce an OS sandbox")
}
