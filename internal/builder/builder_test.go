package builder

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/compiler"
	"gopkg.in/yaml.v3"
)

var root = filepath.Join("..", "..")

func read(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func hasProblem(r Report, fix, contains string) bool {
	for _, p := range r.Problems {
		if (fix == "" || p.Fix == fix) && strings.Contains(p.Message, contains) {
			return true
		}
	}
	return false
}

func TestYAMLToJSON(t *testing.T) {
	out, err := YAMLToJSON([]byte("a:\n  b: [1, x]\nnote: |\n  line one\n  line two\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal(out, &got)
	want := map[string]any{"a": map[string]any{"b": []any{float64(1), "x"}}, "note": "line one\nline two\n"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("YAMLToJSON = %s", out)
	}
}

func TestLintRejectsMultipleDocuments(t *testing.T) {
	doc := []byte("version: 1\nname: x\n---\nversion: 1\n")
	for name, r := range map[string]Report{"profile": LintProfile(doc), "native": LintNative(doc), "map": LintMap([]byte("version: 2\n---\nversion: 2\n"))} {
		if r.Valid || !hasProblem(r, "", "exactly one") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if _, err := YAMLToJSON(doc); err == nil {
		t.Error("YAMLToJSON accepted two documents")
	}
}

func TestLintRejectsOversizedInput(t *testing.T) {
	big := bytes.Repeat([]byte("#"), 1<<20+1)
	for name, r := range map[string]Report{"profile": LintProfile(big), "native": LintNative(big), "map": LintMap(big)} {
		if r.Valid || !hasProblem(r, "", "1 MiB") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if _, err := YAMLToJSON(big); err == nil {
		t.Error("YAMLToJSON accepted an oversized input")
	}
}

func agentRow(r Report, agent, osName string) AgentResult {
	for _, row := range r.Agents {
		if row.Agent == agent && row.OS == osName {
			return row
		}
	}
	return AgentResult{}
}

func TestLintProfileRepositoryFiles(t *testing.T) {
	var files []string
	for _, pattern := range []string{"profiles/*.yaml", "examples/role-policy/profiles/*.yaml"} {
		matches, _ := filepath.Glob(filepath.Join(root, pattern))
		for _, m := range matches {
			if !strings.HasSuffix(m, ".native.yaml") {
				files = append(files, m)
			}
		}
	}
	for _, file := range files {
		data, _ := os.ReadFile(file)
		if r := LintProfile(data); !r.Valid || len(r.Agents) != 9 {
			t.Errorf("%s: %+v", file, r)
		}
	}
	eng := LintProfile(read(t, "examples", "role-policy", "profiles", "engineering.yaml"))
	for _, osName := range []string{"windows", "linux", "darwin"} {
		for _, agent := range []string{"codex", "claude"} {
			if row := agentRow(eng, agent, osName); !row.OK {
				t.Errorf("engineering %s/%s: %+v", agent, osName, row)
			}
		}
	}
	contractor := LintProfile(read(t, "profiles", "contractor-readonly.yaml"))
	if row := agentRow(contractor, "claude", "linux"); row.OK || !strings.Contains(row.Error, "read-only") {
		t.Errorf("contractor claude: %+v", row)
	}
}

func TestLintProfileClaudeSandboxFix(t *testing.T) {
	r := LintProfile([]byte("version: 1\nname: x\nfilesystem:\n  deny_read:\n    common: [\"~/.ssh\"]\n"))
	count := 0
	for _, p := range r.Problems {
		if p.Fix == "claude-sandbox-split" {
			count++
		}
	}
	if !r.Valid || count != 1 {
		t.Fatalf("want exactly one claude-sandbox-split problem: %+v", r)
	}
}

func TestLintProfileUnelevatedWarning(t *testing.T) {
	r := LintProfile([]byte("version: 1\nname: x\nwindows_platform:\n  allowed_sandbox_implementations: [unelevated]\n"))
	if !hasProblem(r, "windows-fallback-elevated", `"unelevated" has weaker network isolation than "elevated"`) {
		t.Fatalf("%+v", r)
	}
	for _, p := range r.Problems {
		if p.Fix == "windows-fallback-elevated" && p.Severity != "warning" {
			t.Fatalf("severity = %q", p.Severity)
		}
	}
}

func TestLintProfileUnknownField(t *testing.T) {
	r := LintProfile([]byte("bogus: 1\nversion: 1\nname: x\n"))
	if r.Valid || len(r.Problems) == 0 || !strings.Contains(r.Problems[0].Message, "bogus") || r.Problems[0].Line != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestLintNativeExamples(t *testing.T) {
	files := []string{filepath.Join(root, "examples", "native", "local-guardrails.yaml")}
	more, _ := filepath.Glob(filepath.Join(root, "examples", "role-policy", "profiles", "*.native.yaml"))
	for _, file := range append(files, more...) {
		data, _ := os.ReadFile(file)
		r := LintNative(data)
		if !r.Valid || len(r.Agents) == 0 {
			t.Errorf("%s: %+v", file, r)
		}
		for _, row := range r.Agents {
			if !row.OK {
				t.Errorf("%s %s/%s: %s", file, row.Agent, row.OS, row.Error)
			}
		}
	}
}

func TestLintMap(t *testing.T) {
	if r := LintMap(read(t, "examples", "role-policy", "policy-map.yaml")); !r.Valid {
		t.Errorf("example map: %+v", r)
	}
	bad := strings.Replace(string(read(t, "examples", "role-policy", "policy-map.yaml")), "priority: 20", "priority: 0", 1)
	if r := LintMap([]byte(bad)); r.Valid || !hasProblem(r, "", "priority must be 1 or higher") {
		t.Errorf("priority 0: %+v", r)
	}
	if r := LintMap(read(t, "examples", "native", "policy-map.yaml")); r.Valid || !hasProblem(r, "map-convert-v1", "version 1") {
		t.Errorf("v1 map: %+v", r)
	}
}

func TestConvertV1Map(t *testing.T) {
	out, err := ConvertV1Map(read(t, "examples", "native", "policy-map.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if r := LintMap(out); !r.Valid {
		t.Fatalf("converted map invalid: %+v\n%s", r, out)
	}
	var m struct {
		Standard struct{ Profile string } `yaml:"standard"`
	}
	yaml.Unmarshal(out, &m)
	if m.Standard.Profile != "local-guardrails" {
		t.Fatalf("standard = %q\n%s", m.Standard.Profile, out)
	}
}

func TestPreview(t *testing.T) {
	data := read(t, "examples", "role-policy", "profiles", "standard.yaml")
	got := Preview("profile", data, "windows", "codex")
	p, _ := compiler.ParsePolicy(data)
	want, _ := compiler.CompileAgent(p, "windows", "codex")
	if got.Error != "" || len(got.Files) != 1 || got.Files[0].Path != `C:\ProgramData\OpenAI\Codex\requirements.toml` || got.Files[0].Content != want.Files[0].Content {
		t.Fatalf("codex windows preview: %+v", got)
	}
	native := Preview("native", read(t, "examples", "native", "local-guardrails.yaml"), "linux", "windsurf")
	var paths []string
	for _, f := range native.Files {
		paths = append(paths, f.Path)
	}
	for _, want := range []string{"/etc/devin/hooks.json", "/etc/windsurf/hooks.json", "/etc/agent-edict/windsurf-policy.json"} {
		if !slices.Contains(paths, want) {
			t.Errorf("windsurf preview missing %s: %v (%s)", want, paths, native.Error)
		}
	}
	if bad := Preview("profile", []byte("bogus: 1\n"), "linux", "codex"); bad.Error == "" {
		t.Error("preview of an invalid profile reported no error")
	}
}

func TestPasteNotes(t *testing.T) {
	cases := map[string]int{
		"a: 1 # note\n":                       1,
		"url: \"x#y\"\n":                      0,
		"text: |\n  ## heading\n  body\n":     0,
		"# top\na: 1\n":                       1,
		"base: &b {x: 1}\nother: *b\n":        1,
		"a: 1 # one\nb: &x 2\nc: *x # two\n":  2,
		"name: plain\n":                       0,
		"bad: [\n":                            0,
		"groups: ['CORP\\SG-Engineers']\n":    0,
		"s: \"it's # not a comment\" # yes\n": 1,
	}
	for in, want := range cases {
		if got := PasteNotes([]byte(in)); len(got) != want {
			t.Errorf("%q: got %v, want %d notes", in, got, want)
		}
	}
}

func TestYAMLToJSONKeepsKeyOrder(t *testing.T) {
	out, err := YAMLToJSON([]byte("name: x\nfilesystem:\n  z: 1\n  a: [b, {y: 1, c: 2}]\nbase: &b {k: v}\ncopy: *b\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"x","filesystem":{"z":1,"a":["b",{"y":1,"c":2}]},"base":{"k":"v"},"copy":{"k":"v"}}`
	if string(out) != want {
		t.Fatalf("YAMLToJSON = %s\nwant        %s", out, want)
	}
	for _, bad := range []string{"a: 1\na: 2\n", "true: 1\n"} {
		if _, err := YAMLToJSON([]byte(bad)); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// AgentEdict reads an unquoted date into its string fields as written, so
// the builder must not turn it into a timestamp.
func TestYAMLToJSONKeepsDatesAsWritten(t *testing.T) {
	out, err := YAMLToJSON([]byte("name: 2026-10-17\ndescription: 2026-10-17T09:30:00Z\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"name":"2026-10-17","description":"2026-10-17T09:30:00Z"}`; string(out) != want {
		t.Fatalf("YAMLToJSON = %s, want %s", out, want)
	}
	if r := LintProfile([]byte("version: 1\nname: 2026-10-17\n")); !r.Valid {
		t.Fatalf("a date-like profile name is valid for AgentEdict: %+v", r)
	}
}
