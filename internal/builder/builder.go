// Package builder checks, converts and previews AgentEdict YAML for the
// browser-based configuration builder. It wraps the same compiler and map
// code CI uses, so the builder never reports a different answer.
package builder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/platform"
	"gopkg.in/yaml.v3"
)

// MaxInput matches the CLI's limit for policy files.
const MaxInput = 1 << 20

// Fix ids the browser knows how to apply.
const (
	FixClaudeSandboxSplit      = "claude-sandbox-split"
	FixWindowsFallbackElevated = "windows-fallback-elevated"
	FixMapConvertV1            = "map-convert-v1"
)

var (
	osNames       = []string{"windows", "linux", "darwin"}
	unifiedAgents = []string{"codex", "claude", "opencode"}
	yamlLine      = regexp.MustCompile(`line (\d+)`)
)

// Problem is one error or warning about a pasted file.
type Problem struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
	Agent    string `json:"agent,omitempty"`
	OS       string `json:"os,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// AgentResult says whether a file compiles for one agent on one OS.
type AgentResult struct {
	Agent         string   `json:"agent"`
	OS            string   `json:"os"`
	OK            bool     `json:"ok"`
	Error         string   `json:"error,omitempty"`
	ToolLevelOnly []string `json:"tool_level_only,omitempty"`
}

// Report is the check result for one file. Valid means the file itself
// parses and validates; Agents shows which agents it compiles for.
type Report struct {
	Valid    bool          `json:"valid"`
	Problems []Problem     `json:"problems"`
	Agents   []AgentResult `json:"agents,omitempty"`
}

// PreviewFile is one file an agent receives, at its installed path.
type PreviewFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// PreviewResult is what one agent receives on one OS.
type PreviewResult struct {
	Files         []PreviewFile `json:"files"`
	ToolLevelOnly []string      `json:"tool_level_only,omitempty"`
	Error         string        `json:"error,omitempty"`
}

func errorProblem(err error) Problem {
	p := Problem{Severity: "error", Message: err.Error()}
	if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
		p.Line, _ = strconv.Atoi(m[1])
	}
	return p
}

func sizeProblem(data []byte) *Report {
	if len(data) > MaxInput {
		return &Report{Problems: []Problem{{Severity: "error", Message: "file exceeds the 1 MiB limit"}}}
	}
	return nil
}

// YAMLToJSON converts one YAML document to JSON for the browser's editor.
func YAMLToJSON(data []byte) ([]byte, error) {
	if len(data) > MaxInput {
		return nil, errors.New("file exceeds the 1 MiB limit")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var value any
	if err := dec.Decode(&value); err != nil && err != io.EOF {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("YAML must contain exactly one document")
	}
	if _, err := json.Marshal(value); err != nil {
		return nil, fmt.Errorf("YAML keys must be strings: %w", err)
	}
	// The decode above validated the document; walk it again as nodes so
	// the JSON keeps the file's key order.
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeOrderedJSON(&buf, &doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeOrderedJSON(buf *bytes.Buffer, n *yaml.Node) error {
	switch n.Kind {
	case 0:
		buf.WriteString("null")
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			buf.WriteString("null")
			return nil
		}
		return writeOrderedJSON(buf, n.Content[0])
	case yaml.AliasNode:
		return writeOrderedJSON(buf, n.Alias)
	case yaml.SequenceNode:
		buf.WriteByte('[')
		for i, item := range n.Content {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeOrderedJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Tag == "!!merge" {
				// shortcut: merge keys lose key order; they are rare in policy files.
				var v any
				if err := n.Decode(&v); err != nil {
					return err
				}
				out, err := json.Marshal(v)
				buf.Write(out)
				return err
			}
		}
		buf.WriteByte('{')
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind == yaml.AliasNode {
				key = key.Alias
			}
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return errors.New("YAML keys must be strings")
			}
			if i > 0 {
				buf.WriteByte(',')
			}
			name, _ := json.Marshal(key.Value)
			buf.Write(name)
			buf.WriteByte(':')
			if err := writeOrderedJSON(buf, n.Content[i+1]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		if n.ShortTag() == "!!timestamp" {
			// AgentEdict's string fields read an unquoted date as written.
			out, _ := json.Marshal(n.Value)
			buf.Write(out)
			return nil
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return err
		}
		out, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(out)
	}
	return nil
}

// LintProfile checks a unified profile and compiles it for every unified
// agent on every OS.
func LintProfile(data []byte) Report {
	if r := sizeProblem(data); r != nil {
		return *r
	}
	p, err := compiler.ParsePolicy(data)
	if err != nil {
		return Report{Problems: []Problem{errorProblem(err)}}
	}
	r := Report{Valid: true, Problems: []Problem{}}
	sandboxFlagged := false
	for _, agentName := range unifiedAgents {
		for _, osName := range osNames {
			out, err := compiler.CompileAgent(p, osName, agentName)
			row := AgentResult{Agent: agentName, OS: osName, OK: err == nil}
			if err != nil {
				row.Error = err.Error()
				if errors.Is(err, compiler.ErrClaudeSandboxChoice) && !sandboxFlagged {
					sandboxFlagged = true
					r.Problems = append(r.Problems, Problem{Severity: "error", Message: err.Error(), Agent: agentName, OS: osName, Fix: FixClaudeSandboxSplit})
				}
			} else {
				row.ToolLevelOnly = out.ToolLevelOnly
			}
			r.Agents = append(r.Agents, row)
		}
	}
	if w := p.WindowsPlatform; w != nil && slices.Contains(w.AllowedSandboxImplementations, "unelevated") && !slices.Contains(w.AllowedSandboxImplementations, "elevated") {
		r.Problems = append(r.Problems, Problem{Severity: "warning", Message: `"unelevated" has weaker network isolation than "elevated"`, Agent: "codex", OS: "windows", Fix: FixWindowsFallbackElevated})
	}
	return r
}

// LintNative checks a native profile and compiles each declared product on
// every OS.
func LintNative(data []byte) Report {
	if r := sizeProblem(data); r != nil {
		return *r
	}
	p, err := compiler.DecodeNativePolicy(data)
	if err != nil {
		return Report{Problems: []Problem{errorProblem(err)}}
	}
	r := Report{Valid: true, Problems: []Problem{}}
	for _, product := range compiler.NativeProducts() {
		if _, err := compiler.SelectNativePolicy(p, product); err != nil {
			continue // section not declared
		}
		for _, osName := range osNames {
			_, err := compiler.CompileNative(p, osName, product)
			row := AgentResult{Agent: product, OS: osName, OK: err == nil}
			if err != nil {
				row.Error = err.Error()
			}
			r.Agents = append(r.Agents, row)
		}
	}
	return r
}

func mapVersion(data []byte) int {
	var header struct {
		Version int `yaml:"version"`
	}
	_ = yaml.Unmarshal(data, &header)
	return header.Version
}

// LintMap checks a version 2 policy map. A version 1 map is reported with
// an offer to convert it.
func LintMap(data []byte) Report {
	if r := sizeProblem(data); r != nil {
		return *r
	}
	if mapVersion(data) == 1 {
		return Report{Problems: []Problem{{Severity: "error", Message: "this is a version 1 map; the builder edits version 2 maps", Fix: FixMapConvertV1}}}
	}
	if _, err := agent.ParsePolicyMapV2(data); err != nil {
		return Report{Problems: []Problem{errorProblem(err)}}
	}
	return Report{Valid: true, Problems: []Problem{}}
}

// ConvertV1Map turns a version 1 map into a version 2 map whose standard is
// the old machine_profile. Version 1's diagnostic rules are dropped.
func ConvertV1Map(data []byte) ([]byte, error) {
	if len(data) > MaxInput {
		return nil, errors.New("file exceeds the 1 MiB limit")
	}
	var v1 struct {
		Version        int      `yaml:"version"`
		MachineProfile string   `yaml:"machine_profile"`
		ManagedAgents  []string `yaml:"managed_agents"`
		SyncWSL        bool     `yaml:"sync_wsl"`
	}
	if err := yaml.Unmarshal(data, &v1); err != nil {
		return nil, err
	}
	if v1.Version != 1 || v1.MachineProfile == "" {
		return nil, errors.New("not a version 1 map with a machine_profile")
	}
	if v1.SyncWSL {
		return nil, errors.New("sync_wsl is not supported with version 2 maps; turn it off before converting")
	}
	type standard struct {
		Profile  string `yaml:"profile"`
		Priority int    `yaml:"priority"`
	}
	out, err := yaml.Marshal(struct {
		Version       int      `yaml:"version"`
		ManagedAgents []string `yaml:"managed_agents,flow"`
		SyncWSL       bool     `yaml:"sync_wsl"`
		Standard      standard `yaml:"standard"`
	}{2, v1.ManagedAgents, false, standard{v1.MachineProfile, 100}})
	if err != nil {
		return nil, err
	}
	if _, err := agent.ParsePolicyMapV2(out); err != nil {
		return nil, err
	}
	return out, nil
}

// Preview returns the files one agent receives on one OS. kind is
// "profile" or "native".
func Preview(kind string, data []byte, osName, agentName string) PreviewResult {
	if len(data) > MaxInput {
		return PreviewResult{Error: "file exceeds the 1 MiB limit"}
	}
	var files []compiler.AgentFile
	var toolLevel []string
	switch kind {
	case "profile":
		p, err := compiler.ParsePolicy(data)
		if err != nil {
			return PreviewResult{Error: err.Error()}
		}
		out, err := compiler.CompileAgent(p, osName, agentName)
		if err != nil {
			return PreviewResult{Error: err.Error()}
		}
		files, toolLevel = out.Files, out.ToolLevelOnly
	case "native":
		p, err := compiler.DecodeNativePolicy(data)
		if err != nil {
			return PreviewResult{Error: err.Error()}
		}
		out, err := compiler.CompileNative(p, osName, agentName)
		if err != nil {
			return PreviewResult{Error: err.Error()}
		}
		for _, artifact := range out.Artifacts {
			files = append(files, compiler.AgentFile{Extension: artifact.Extension, Content: artifact.Content})
		}
	default:
		return PreviewResult{Error: fmt.Sprintf("unknown preview kind %q", kind)}
	}
	result := PreviewResult{Files: []PreviewFile{}, ToolLevelOnly: toolLevel}
	for _, file := range files {
		for _, target := range platform.DefaultPolicyTargets() {
			if target.AgentName == agentName && target.BundleExt == file.Extension {
				result.Files = append(result.Files, PreviewFile{Path: target.FilePath(osName), Content: file.Content})
			}
		}
	}
	return result
}

// PasteNotes lists what the builder drops when it loads pasted YAML:
// comments, and anchors or aliases, which it expands. Unparseable input
// gets no notes; the lint reports the error.
func PasteNotes(data []byte) []string {
	notes := []string{}
	if len(data) > MaxInput {
		return notes
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return notes
	}
	var comments, anchors bool
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.HeadComment != "" || n.LineComment != "" || n.FootComment != "" {
			comments = true
		}
		if n.Anchor != "" || n.Kind == yaml.AliasNode {
			anchors = true
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(&doc)
	if comments {
		notes = append(notes, "Comments won't be kept: the builder writes the file fresh.")
	}
	if anchors {
		notes = append(notes, "Anchors and aliases (& and *) are expanded; they won't be kept.")
	}
	return notes
}
