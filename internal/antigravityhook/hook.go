package antigravityhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const maxPayloadBytes = 1 << 20

type CommandRule struct {
	Command   string `json:"command" yaml:"command"`
	Directory string `json:"directory" yaml:"directory"`
	Decision  string `json:"decision" yaml:"decision"`
}

type Policy struct {
	Version      int               `json:"version" yaml:"version"`
	ReadRoots    []string          `json:"read_roots,omitempty" yaml:"read_roots,omitempty"`
	WriteRoots   []string          `json:"write_roots,omitempty" yaml:"write_roots,omitempty"`
	HTTPSOrigins []string          `json:"https_origins,omitempty" yaml:"https_origins,omitempty"`
	Commands     []CommandRule     `json:"commands,omitempty" yaml:"commands,omitempty"`
	Tools        map[string]string `json:"tools,omitempty" yaml:"tools,omitempty"`
}

// Policy governs only tool calls delivered to the registered App PreToolUse
// hook. It does not make hook registration mandatory or sandbox processes.
// Paths are administrator-selected absolute roots, never payload workspacePaths.

var fileTools = map[string]struct {
	pathKey string
	write   bool
	keys    string
}{
	"view_file":                  {"AbsolutePath", false, "AbsolutePath StartLine EndLine IsSkillFile"},
	"list_dir":                   {"DirectoryPath", false, "DirectoryPath"},
	"find_by_name":               {"SearchDirectory", false, "SearchDirectory Pattern Type Excludes Extensions FullPath MaxDepth"},
	"grep_search":                {"SearchPath", false, "SearchPath Query IsRegex CaseInsensitive Includes MatchPerLine"},
	"write_to_file":              {"TargetFile", true, "TargetFile Overwrite CodeContent Description IsArtifact ArtifactMetadata"},
	"replace_file_content":       {"TargetFile", true, "TargetFile Instruction Description AllowMultiple TargetContent ReplacementContent StartLine EndLine TargetLintErrorIds"},
	"multi_replace_file_content": {"TargetFile", true, "TargetFile Instruction Description ReplacementChunks TargetLintErrorIds ArtifactMetadata"},
}

var simpleTools = map[string]string{
	"ask_question":     "questions",
	"list_permissions": "",
	"search_web":       "query domain",
}

// Validate checks the policy without accessing endpoint filesystem paths. This
// allows a publisher to compile policies for a different operating system.
func Validate(p Policy, targetOS string) error {
	if targetOS != "linux" && targetOS != "darwin" && targetOS != "windows" {
		return fmt.Errorf("unsupported Antigravity target OS %q", targetOS)
	}
	if p.Version != 1 {
		return errors.New("Antigravity hook policy version must be 1")
	}
	if len(p.Commands) > 1024 || len(p.Tools) > 32 || len(p.ReadRoots) > 256 || len(p.WriteRoots) > 256 || len(p.HTTPSOrigins) > 256 {
		return errors.New("Antigravity hook policy exceeds rule limits")
	}
	for _, roots := range [][]string{p.ReadRoots, p.WriteRoots} {
		seen := map[string]bool{}
		for _, root := range roots {
			if !absoluteClean(root, targetOS) || seen[root] {
				return errors.New("file roots must be unique clean absolute paths")
			}
			seen[root] = true
		}
	}
	seenCommands := map[string]bool{}
	for _, rule := range p.Commands {
		key := rule.Command + "\x00" + rule.Directory
		if !safeString(rule.Command, 4096) || strings.TrimSpace(rule.Command) != rule.Command || !absoluteClean(rule.Directory, targetOS) || !validDecision(rule.Decision) || seenCommands[key] {
			return errors.New("commands require a unique exact command, clean absolute directory, and allow/ask/deny decision")
		}
		seenCommands[key] = true
	}
	seenOrigins := map[string]bool{}
	for _, origin := range p.HTTPSOrigins {
		u, err := url.Parse(origin)
		if err != nil || !safeURL(u) || u.Path != "" || u.RawQuery != "" || u.ForceQuery || seenOrigins[origin] {
			return errors.New("https_origins must contain unique HTTPS origins without paths, credentials, queries, or fragments")
		}
		seenOrigins[origin] = true
	}
	for tool, decision := range p.Tools {
		_, file := fileTools[tool]
		_, simple := simpleTools[tool]
		if (!file && !simple && tool != "read_url_content") || !validDecision(decision) {
			return fmt.Errorf("unsupported Antigravity tool or decision: %q", tool)
		}
	}
	return nil
}

func validDecision(s string) bool { return s == "allow" || s == "ask" || s == "deny" }

func safeString(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func absoluteClean(s, osName string) bool {
	if !safeString(s, 4096) {
		return false
	}
	if osName == "windows" {
		if len(s) < 3 || !((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) || s[1] != ':' || (s[2] != '\\' && s[2] != '/') {
			return false
		}
		s = strings.ReplaceAll(s, "\\", "/")
		if strings.Contains(s[2:], ":") {
			return false
		}
		s = s[2:]
	} else if strings.Contains(s, "\\") {
		return false
	}
	return strings.HasPrefix(s, "/") && path.Clean(s) == s
}

func safeURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == "" && safeString(u.String(), 8192)
}

type invocation struct {
	ToolCall *struct {
		Name string                     `json:"name"`
		Args map[string]json.RawMessage `json:"args"`
	} `json:"toolCall"`
}

// Run emits a native deny response before returning any parse, policy, or I/O
// error. A caller must not print diagnostics onto the JSON response stream.
// Whether the application calls the hook, or honors failures to execute it,
// remains an application property; this evaluator cannot impose that behavior.
func Run(policyReader, inputReader io.Reader, output io.Writer) error {
	var p Policy
	if err := decode(policyReader, &p, true); err != nil {
		return errors.Join(fmt.Errorf("read Antigravity policy: %w", err), Deny(output))
	}
	if err := Validate(p, runtime.GOOS); err != nil {
		return errors.Join(err, Deny(output))
	}
	var request invocation
	if err := decode(inputReader, &request, false); err != nil {
		return errors.Join(fmt.Errorf("read Antigravity hook input: %w", err), Deny(output))
	}
	if request.ToolCall == nil || request.ToolCall.Args == nil {
		return errors.Join(errors.New("missing toolCall object or args object"), Deny(output))
	}
	decision := evaluate(p, request.ToolCall.Name, request.ToolCall.Args)
	if decision == "ask" {
		decision = "force_ask"
	}
	return respond(output, decision)
}

func Deny(output io.Writer) error { return respond(output, "deny") }

// Allow answers allow; it is used only when AgentEdict has released the agent.
func Allow(output io.Writer) error { return respond(output, "allow") }

func respond(output io.Writer, decision string) error {
	return json.NewEncoder(output).Encode(struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}{decision, "AgentEdict local tool policy"})
}

func evaluate(p Policy, tool string, args map[string]json.RawMessage) string {
	if tool == "run_command" {
		if !onlyKeys(args, "CommandLine Cwd WaitMsBeforeAsync RunPersistent RequestedTerminalID") {
			return "deny"
		}
		// An existing interactive terminal can carry a different directory,
		// environment, or shell state. Persistent commands outlive this decision.
		// Neither mode is covered by an exact command/directory rule.
		if _, exists := args["RequestedTerminalID"]; exists {
			return "deny"
		}
		if raw, exists := args["RunPersistent"]; exists {
			var persistent bool
			if string(raw) == "null" || json.Unmarshal(raw, &persistent) != nil || persistent {
				return "deny"
			}
		}
		if raw, exists := args["WaitMsBeforeAsync"]; exists {
			var wait int64
			if string(raw) == "null" || json.Unmarshal(raw, &wait) != nil || wait < 0 {
				return "deny"
			}
		}
		command, cwd := stringArg(args, "CommandLine"), stringArg(args, "Cwd")
		if !safeString(command, 4096) || !absoluteClean(cwd, runtime.GOOS) {
			return "deny"
		}
		actual, err := filepath.EvalSymlinks(cwd)
		if err != nil {
			return "deny"
		}
		info, err := os.Stat(actual)
		if err != nil || !info.IsDir() {
			return "deny"
		}
		for _, rule := range p.Commands {
			if command != rule.Command {
				continue
			}
			expected, err := filepath.EvalSymlinks(rule.Directory)
			if err == nil && actual == expected {
				return rule.Decision
			}
		}
		return "deny"
	}
	decision, ok := p.Tools[tool]
	if !ok || decision == "deny" {
		return "deny"
	}
	if spec, ok := fileTools[tool]; ok {
		if !onlyKeys(args, spec.keys) {
			return "deny"
		}
		roots := p.ReadRoots
		if spec.write {
			roots = p.WriteRoots
		}
		if !withinRoots(stringArg(args, spec.pathKey), roots, spec.write) {
			return "deny"
		}
		return decision
	}
	if tool == "read_url_content" {
		if !onlyKeys(args, "Url") {
			return "deny"
		}
		u, err := url.Parse(stringArg(args, "Url"))
		if err != nil || !safeURL(u) {
			return "deny"
		}
		for _, origin := range p.HTTPSOrigins {
			if u.Scheme+"://"+u.Host == origin {
				return decision
			}
		}
		return "deny"
	}
	if keys, ok := simpleTools[tool]; ok && onlyKeys(args, keys) {
		return decision
	}
	return "deny"
}

func onlyKeys(args map[string]json.RawMessage, allowed string) bool {
	keys := map[string]bool{}
	for _, k := range strings.Fields(allowed) {
		keys[k] = true
	}
	for key := range args {
		if !keys[key] {
			return false
		}
	}
	return true
}

func stringArg(args map[string]json.RawMessage, key string) string {
	var result string
	if err := json.Unmarshal(args[key], &result); err != nil {
		return ""
	}
	return result
}

func withinRoots(filename string, roots []string, allowMissing bool) bool {
	if !absoluteClean(filename, runtime.GOOS) {
		return false
	}
	canonical, err := resolvePath(filename, allowMissing)
	if err != nil {
		return false
	}
	for _, root := range roots {
		base, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		info, err := os.Stat(base)
		if err != nil || !info.IsDir() {
			continue
		}
		rel, err := filepath.Rel(base, canonical)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}

// Resolve existing ancestors for creation, so a symlinked parent cannot move a
// proposed write outside a root. This is a preflight check, not a filesystem
// reference held across the application's later write (see integration limits).
func resolvePath(filename string, allowMissing bool) (string, error) {
	resolved, err := filepath.EvalSymlinks(filename)
	if err == nil {
		return resolved, nil
	}
	if !allowMissing || !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if _, statErr := os.Lstat(filename); statErr == nil {
		return "", err
	} // dangling symlink
	parent := filepath.Dir(filename)
	if parent == filename {
		return "", err
	}
	base, parentErr := resolvePath(parent, true)
	if parentErr != nil {
		return "", parentErr
	}
	return filepath.Join(base, filepath.Base(filename)), nil
}

func decode(reader io.Reader, target any, strict bool) error {
	if reader == nil {
		return errors.New("missing JSON reader")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxPayloadBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxPayloadBytes {
		return errors.New("JSON exceeds size limit")
	}
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	if err := uniqueValue(check, 0); err != nil {
		return err
	}
	if _, err := check.Token(); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return errors.New("expected JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	return decoder.Decode(target)
}

// Reject duplicate keys rather than relying on encoding/json's last-key wins.
func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON object key")
			}
			seen[key] = true
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for decoder.More() {
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	} else {
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
