package builder

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"gopkg.in/yaml.v3"
)

func TestImportCodexRequirementsRoundTrip(t *testing.T) {
	original := read(t, "internal", "builder", "testdata", "codex-requirements.toml")
	pasted, err := ParsePasted(original)
	if err != nil {
		t.Fatal(err)
	}
	if pasted.Format != "codex-requirements" {
		t.Fatalf("format = %q", pasted.Format)
	}
	notes := strings.Join(pasted.Notes, "\n")
	for _, want := range []string{"remote_sandbox_config", "Comments", "sandbox_private_desktop"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes don't mention %s:\n%s", want, notes)
		}
	}

	var tree any
	json.Unmarshal(pasted.Tree, &tree)
	profile, _ := yaml.Marshal(tree)
	p, err := compiler.ParsePolicy(profile)
	if err != nil {
		t.Fatalf("imported profile doesn't parse: %v\n%s", err, profile)
	}
	out, err := compiler.CompileAgent(p, "windows", "codex")
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	if err := toml.Unmarshal([]byte(out.Files[0].Content), &got); err != nil {
		t.Fatal(err)
	}
	toml.Unmarshal(original, &want)
	// Not written, so reported instead: one isn't supported yet, and Codex removed the other.
	delete(want, "remote_sandbox_config")
	delete(want["windows"].(map[string]any), "sandbox_private_desktop")
	// Codex reads [] and ["disabled"] alike: only disabled search is allowed.
	if reflect.DeepEqual(got["allowed_web_search_modes"], []any{}) {
		got["allowed_web_search_modes"] = []any{"disabled"}
	}
	if !reflect.DeepEqual(got, want) {
		for key := range want {
			if !reflect.DeepEqual(got[key], want[key]) {
				t.Errorf("%s: got %#v, want %#v", key, got[key], want[key])
			}
		}
		for key := range got {
			if _, ok := want[key]; !ok {
				t.Errorf("unexpected %s = %#v", key, got[key])
			}
		}
		t.Logf("profile:\n%s", profile)
	}
}

func TestParsePastedKeepsYAMLAndReportsBadInput(t *testing.T) {
	pasted, err := ParsePasted([]byte("version: 1\nname: x # note\n"))
	if err != nil || pasted.Format != "yaml" || len(pasted.Notes) != 1 {
		t.Fatalf("yaml paste: %+v %v", pasted, err)
	}
	if _, err := ParsePasted([]byte("[features]\nbrowser_use = \n")); err == nil || !strings.Contains(err.Error(), "TOML") {
		t.Fatalf("broken TOML: %v", err)
	}
	if _, err := ParsePasted([]byte("just: [unclosed\n")); err == nil {
		t.Fatal("broken YAML accepted")
	}
	if p, err := ParsePasted([]byte("# only a comment\n")); err == nil {
		t.Fatalf("empty paste accepted: %+v", p)
	}
}

func TestImportNamesProfileFromAgentEdictHeader(t *testing.T) {
	pasted, err := ParsePasted([]byte("# Generated policy for profile \"engineering\"\nallowed_sandbox_modes = [\"read-only\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	json.Unmarshal(pasted.Tree, &tree)
	if tree["name"] != "engineering" {
		t.Fatalf("name = %v", tree["name"])
	}
	if !strings.HasPrefix(string(pasted.Tree), `{"version":1,"name":"engineering"`) {
		t.Fatalf("tree should start with version and name: %s", pasted.Tree[:60])
	}
}
