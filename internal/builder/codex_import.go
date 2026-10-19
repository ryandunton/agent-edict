package builder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Pasted is text pasted into the builder, read as a JSON tree for the page.
type Pasted struct {
	Format string          `json:"format"` // "yaml" or "codex-requirements"
	Tree   json.RawMessage `json:"tree"`
	Notes  []string        `json:"notes"`
}

var (
	tomlLine          = regexp.MustCompile(`(?m)^\s*(\[[^\]]+\]|[A-Za-z0-9_."-]+\s*=)`)
	generatedName     = regexp.MustCompile(`(?m)^# Generated policy for profile "([A-Za-z0-9_-]+)"`)
	tomlComment       = regexp.MustCompile(`(?m)^\s*#`)
	windowsPathPrefix = regexp.MustCompile(`^[A-Za-z]:\\|\\`)
)

// ParsePasted reads AgentEdict YAML, or a Codex requirements.toml, which it
// converts into a unified profile. Notes say what the builder won't keep.
func ParsePasted(data []byte) (Pasted, error) {
	if len(data) > MaxInput {
		return Pasted{}, errors.New("file exceeds the 1 MiB limit")
	}
	tree, yamlErr := YAMLToJSON(data)
	if yamlErr == nil && bytes.HasPrefix(bytes.TrimSpace(tree), []byte("{")) {
		return Pasted{Format: "yaml", Tree: tree, Notes: PasteNotes(data)}, nil
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		if tomlLine.Match(data) {
			return Pasted{}, fmt.Errorf("this looks like TOML but doesn't parse: %v", err)
		}
		if yamlErr != nil {
			return Pasted{}, yamlErr
		}
		return Pasted{}, errors.New("paste a profile, native profile or policy map in YAML, or a Codex requirements.toml")
	}
	if len(doc) == 0 {
		return Pasted{}, errors.New("there are no settings in this file")
	}
	profile, notes := importCodexRequirements(doc, data)
	out, err := json.Marshal(profile)
	if err != nil {
		return Pasted{}, err
	}
	return Pasted{Format: "codex-requirements", Tree: out, Notes: notes}, nil
}

// object is a JSON object that keeps insertion order, so the imported
// profile's cards appear in a sensible order.
type object struct {
	keys   []string
	values map[string]any
}

func newObject() *object { return &object{values: map[string]any{}} }

func (o *object) set(key string, value any) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *object) child(key string) *object {
	if c, ok := o.values[key].(*object); ok {
		return c
	}
	c := newObject()
	o.set(key, c)
	return c
}

func (o *object) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, _ := json.Marshal(key)
		v, err := json.Marshal(o.values[key])
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// importer moves recognized keys out of a parsed requirements file and
// notes everything it leaves behind.
type importer struct {
	notes []string
}

func (im *importer) skip(path string) {
	im.notes = append(im.notes, fmt.Sprintf("Not loaded: %s isn't something AgentEdict writes yet.", path))
}

func (im *importer) wrongType(path string) {
	im.notes = append(im.notes, fmt.Sprintf("Not loaded: %s has a value AgentEdict doesn't expect.", path))
}

// take removes key from table and returns its value.
func take(table map[string]any, key string) (any, bool) {
	v, ok := table[key]
	delete(table, key)
	return v, ok
}

// leftovers notes every key still in table, which nothing imported.
func (im *importer) leftovers(prefix string, table map[string]any) {
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		im.skip(prefix + k)
	}
}

func (im *importer) bools(dst *object, src map[string]any, prefix string, keys ...string) {
	for _, k := range keys {
		if v, ok := take(src, k); ok {
			if b, isBool := v.(bool); isBool {
				dst.set(k, b)
			} else {
				im.wrongType(prefix + k)
			}
		}
	}
}

func (im *importer) strings(dst *object, src map[string]any, prefix string, keys ...string) {
	for _, k := range keys {
		if v, ok := take(src, k); ok {
			if s, isString := v.(string); isString {
				dst.set(k, s)
			} else {
				im.wrongType(prefix + k)
			}
		}
	}
}

func stringList(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// list moves a string list from src[key] to dst[name].
func (im *importer) list(dst *object, name string, src map[string]any, key string) {
	if v, ok := take(src, key); ok {
		if items, isList := stringList(v); isList {
			dst.set(name, items)
		} else {
			im.wrongType(key)
		}
	}
}

func table(v any) (map[string]any, bool) {
	t, ok := v.(map[string]any)
	return t, ok
}

func importCodexRequirements(doc map[string]any, raw []byte) (*object, []string) {
	im := &importer{}
	p := newObject()
	p.set("version", 1)
	name := "codex-requirements"
	if m := generatedName.FindSubmatch(raw); m != nil {
		name = string(m[1])
	}
	p.set("name", name)
	p.set("description", "Imported from a Codex requirements.toml")

	if v, ok := take(doc, "allowed_login_methods"); ok {
		if methods, isList := stringList(v); isList {
			p.child("login").set("methods", methods)
		} else {
			im.wrongType("allowed_login_methods")
		}
	}
	im.strings(p, doc, "", "model_provider")
	if v, ok := take(doc, "model_providers"); ok {
		im.modelProviders(p, v)
	}
	im.strings(p, doc, "", "default_permissions")
	if v, ok := take(doc, "allowed_permission_profiles"); ok {
		p.set("allowed_permission_profiles", v)
	}
	if v, ok := take(doc, "permissions"); ok {
		im.permissions(p, v)
	}
	im.list(p.child("sandbox"), "modes", doc, "allowed_sandbox_modes")
	approval := newObject()
	im.list(approval, "policies", doc, "allowed_approval_policies")
	im.list(approval, "reviewers", doc, "allowed_approvals_reviewers")
	if len(approval.keys) > 0 {
		p.set("approval", approval)
	}
	if v, ok := take(doc, "allowed_web_search_modes"); ok {
		modes, isList := stringList(v)
		switch {
		case !isList:
			im.wrongType("allowed_web_search_modes")
		case len(modes) == 0:
			p.child("web_search").set("modes", []string{"disabled"})
		default:
			p.child("web_search").set("modes", modes)
		}
	}
	flags := newObject()
	im.bools(flags, doc, "", "allow_appshots", "allow_browser_and_computer_use", "allow_login_shell", "allow_managed_hooks_only", "allow_remote_control")
	if len(flags.keys) > 0 {
		p.set("flags", flags)
	}
	im.section(p, doc, "windows", "windows_platform", func(dst *object, src map[string]any) {
		im.list(dst, "allowed_sandbox_implementations", src, "allowed_sandbox_implementations")
		im.bools(dst, src, "windows.", "allow_mxc")
		if _, ok := take(src, "sandbox_private_desktop"); ok {
			im.notes = append(im.notes, "Not loaded: Codex removed windows.sandbox_private_desktop and warns when it's set. Its older Windows sandboxes always use a private desktop.")
		}
	})
	im.section(p, doc, "features", "features", func(dst *object, src map[string]any) {
		im.bools(dst, src, "features.", "apps", "browser_use", "browser_use_external", "browser_use_full_cdp_access", "computer_use",
			"in_app_browser", "memories", "multi_agent", "plugin_sharing", "plugins", "remote_plugin", "guardian_approval", "prefer_mxc")
	})
	im.section(p, doc, "browser_use", "browser_use", func(dst *object, src map[string]any) {
		im.bools(dst, src, "browser_use.", "allow_history_access", "allow_global_persistent_approval")
		im.section(dst, src, "default_origin_policy", "default_origin_policy", func(policy *object, origin map[string]any) {
			im.strings(policy, origin, "browser_use.default_origin_policy.", "access", "uploads", "downloads", "full_cdp_access", "access_approval_lifetime")
			im.bools(policy, origin, "browser_use.default_origin_policy.", "persistent_approval")
		})
	})
	im.section(p, doc, "computer_use", "computer_use", func(dst *object, src map[string]any) {
		im.bools(dst, src, "computer_use.", "allow_locked_computer_use")
	})
	if v, ok := take(doc, "mcp_servers"); ok {
		im.mcpServers(p, v)
	}
	if v, ok := take(doc, "plugins"); ok {
		im.plugins(p, v)
	}
	if v, ok := take(doc, "application"); ok {
		if app, isTable := table(v); isTable {
			im.section(p, app, "network", "application_network", func(dst *object, src map[string]any) {
				im.bools(dst, src, "application.network.", "enabled")
				if domains, ok := take(src, "domains"); ok {
					dst.set("domains", domains)
				}
			})
			im.leftovers("application.", app)
		} else {
			im.wrongType("application")
		}
	}
	im.section(p, doc, "feedback", "feedback", func(dst *object, src map[string]any) {
		im.bools(dst, src, "feedback.", "enabled")
	})
	if v, ok := take(doc, "rules"); ok {
		im.rules(p, v)
	}
	im.strings(p, doc, "", "additional_developer_instructions", "guardian_extra_policy")
	im.leftovers("", doc)

	notes := []string{"Converted from a Codex requirements.toml into a profile. If you also use it for Claude Code or OpenCode, Check shows what each of them can and can't enforce."}
	if tomlComment.Match(raw) {
		notes = append(notes, "Comments won't be kept, including commented-out settings.")
	}
	return p, append(notes, im.notes...)
}

// section imports the table src[key] into dst[name] with fill, then notes
// anything fill left in it.
func (im *importer) section(dst *object, src map[string]any, key, name string, fill func(*object, map[string]any)) {
	v, ok := take(src, key)
	if !ok {
		return
	}
	t, isTable := table(v)
	if !isTable {
		im.wrongType(key)
		return
	}
	out := dst.child(name)
	fill(out, t)
	im.leftovers(key+".", t)
}

var permissionFilesystemKeys = []string{":root", ":minimal", ":tmpdir", ":slash_tmp", "glob_scan_max_depth", ":workspace_roots"}

func (im *importer) permissions(p *object, v any) {
	all, ok := table(v)
	if !ok {
		im.wrongType("permissions")
		return
	}
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		def, isTable := table(all[name])
		if !isTable {
			im.wrongType("permissions." + name)
			continue
		}
		prefix := "permissions." + name + "."
		// AgentEdict writes filesystem.deny_read as [permissions.filesystem].
		if deny, hasDeny := def["deny_read"]; name == "filesystem" && hasDeny {
			delete(def, "deny_read")
			if paths, isList := stringList(deny); isList {
				p.child("filesystem").child("deny_read").set("common", paths)
			} else {
				im.wrongType(prefix + "deny_read")
			}
			im.leftovers(prefix, def)
			continue
		}
		out := p.child("permissions").child(name)
		im.strings(out, def, prefix, "description", "extends")
		im.section(out, def, "filesystem", "filesystem", func(fs *object, src map[string]any) {
			for _, k := range permissionFilesystemKeys {
				if v, ok := take(src, k); ok {
					fs.set(k, v)
				}
			}
		})
		im.section(out, def, "network", "network", func(n *object, src map[string]any) {
			im.bools(n, src, prefix+"network.", "enabled")
		})
		im.leftovers(prefix, def)
	}
}

// identity reads an MCP server's { url } or { command } identity.
func identity(v any) (url, command string, ok bool) {
	server, isTable := table(v)
	if !isTable {
		return "", "", false
	}
	id, isTable := table(server["identity"])
	if !isTable || len(server) != 1 {
		return "", "", false
	}
	url, _ = id["url"].(string)
	command, _ = id["command"].(string)
	return url, command, len(id) == 1 && (url != "") != (command != "")
}

func (im *importer) mcpServers(p *object, v any) {
	servers, ok := table(v)
	if !ok {
		im.wrongType("mcp_servers")
		return
	}
	out := p.child("mcp_servers")
	for _, name := range sortedKeys(servers) {
		url, command, ok := identity(servers[name])
		switch {
		case !ok:
			im.wrongType("mcp_servers." + name)
		case url != "":
			out.set(name, map[string]any{"url": url})
		case windowsPathPrefix.MatchString(command):
			out.set(name, map[string]any{"windows": map[string]any{"command": command, "args": []string{}}})
			im.notes = append(im.notes, fmt.Sprintf("mcp_servers.%s runs a Windows command; add its macOS and Linux command too if Codex runs there.", name))
		default:
			out.set(name, map[string]any{"unix": map[string]any{"command": command, "args": []string{}}})
			im.notes = append(im.notes, fmt.Sprintf("mcp_servers.%s runs a macOS or Linux command; add its Windows command too if Codex runs there.", name))
		}
	}
}

func (im *importer) modelProviders(p *object, v any) {
	providers, ok := table(v)
	if !ok {
		im.wrongType("model_providers")
		return
	}
	out := p.child("model_providers")
	for _, name := range sortedKeys(providers) {
		def, isTable := table(providers[name])
		if !isTable {
			im.wrongType("model_providers." + name)
			continue
		}
		prefix := "model_providers." + name + "."
		provider := out.child(name)
		im.strings(provider, def, prefix, "name", "base_url", "wire_api", "env_key")
		im.bools(provider, def, prefix, "requires_openai_auth")
		im.leftovers(prefix, def)
	}
}

func (im *importer) plugins(p *object, v any) {
	plugins, ok := table(v)
	if !ok {
		im.wrongType("plugins")
		return
	}
	out := p.child("plugins")
	for _, plugin := range sortedKeys(plugins) {
		policy, isTable := table(plugins[plugin])
		if !isTable {
			im.wrongType("plugins." + plugin)
			continue
		}
		servers := map[string]any{}
		if v, ok := take(policy, "mcp_servers"); ok {
			listed, isTable := table(v)
			if !isTable {
				im.wrongType("plugins." + plugin + ".mcp_servers")
			}
			for _, name := range sortedKeys(listed) {
				url, command, ok := identity(listed[name])
				switch {
				case !ok:
					im.wrongType("plugins." + plugin + ".mcp_servers." + name)
				case url != "":
					servers[name] = map[string]any{"url": url}
				default:
					servers[name] = map[string]any{"command": command}
				}
			}
		}
		out.set(plugin, map[string]any{"mcp_servers": servers})
		im.leftovers("plugins."+plugin+".", policy)
	}
}

func (im *importer) rules(p *object, v any) {
	rules, ok := table(v)
	if !ok {
		im.wrongType("rules")
		return
	}
	prefixRules, _ := take(rules, "prefix_rules")
	im.leftovers("rules.", rules)
	items, isList := prefixRules.([]any)
	if prefixRules != nil && !isList {
		im.wrongType("rules.prefix_rules")
		return
	}
	lists := map[string][]string{}
	for i, item := range items {
		rule, isTable := table(item)
		command, decision := "", ""
		if isTable {
			command, decision = prefixCommand(rule["pattern"]), fmt.Sprint(rule["decision"])
		}
		target := map[string]string{"prompt": "prompt", "forbidden": "deny", "allow": "allow"}[decision]
		if command == "" || target == "" || len(rule) != 2 {
			im.notes = append(im.notes, fmt.Sprintf("Not loaded: rules.prefix_rules[%d] isn't a plain command prefix AgentEdict can hold.", i))
			continue
		}
		if target == "allow" {
			im.notes = append(im.notes, fmt.Sprintf("rules.prefix_rules[%d] allows %q; AgentEdict passes allow rules to Claude Code and OpenCode, not to Codex.", i, command))
		}
		lists[target] = append(lists[target], command)
	}
	for _, target := range []string{"allow", "prompt", "deny"} {
		if len(lists[target]) > 0 {
			p.child("commands").child(target).set("common", lists[target])
		}
	}
}

// prefixCommand joins a pattern of plain { token = "..." } parts.
func prefixCommand(v any) string {
	parts, ok := v.([]any)
	if !ok || len(parts) == 0 {
		return ""
	}
	tokens := make([]string, 0, len(parts))
	for _, part := range parts {
		t, isTable := table(part)
		token, isString := t["token"].(string)
		if !isTable || !isString || len(t) != 1 || token == "" || strings.ContainsAny(token, " \t") {
			return ""
		}
		tokens = append(tokens, token)
	}
	return strings.Join(tokens, " ")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
