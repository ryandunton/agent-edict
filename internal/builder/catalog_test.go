package builder

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/compiler"
)

func loadRepoCatalog(t *testing.T) *Catalog {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "public", "builder", "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogCoversEverySupportedField(t *testing.T) {
	c := loadRepoCatalog(t)
	for file, typ := range map[string]reflect.Type{
		"profile": reflect.TypeOf(compiler.UnifiedPolicy{}),
		"native":  reflect.TypeOf(compiler.NativePolicy{}),
		"map":     reflect.TypeOf(agent.PolicyMapV2{}),
	} {
		want := map[string]bool{}
		for _, p := range structPaths(typ, "") {
			// deny_write parses but every non-empty list is rejected, so the
			// catalog lists it as not yet supported instead of offering it.
			if p != "version" && !(file == "profile" && strings.HasPrefix(p, "filesystem.deny_write.")) {
				want[p] = true
			}
		}
		got := map[string]bool{}
		for _, s := range c.Settings {
			if s.File == file && s.Status == "supported" {
				for _, p := range s.YAMLPaths {
					got[p] = true
				}
			}
		}
		var missing, extra []string
		for p := range want {
			if !got[p] {
				missing = append(missing, p)
			}
		}
		for p := range got {
			if !want[p] {
				extra = append(extra, p)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 || len(extra) > 0 {
			t.Errorf("%s catalog out of step with AgentEdict:\n  missing: %s\n  extra:   %s", file, strings.Join(missing, ", "), strings.Join(extra, ", "))
		}
	}
}

var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func TestCatalogEntriesAreComplete(t *testing.T) {
	c := loadRepoCatalog(t)
	levels := []string{"enforced", "partial", "configuration-only", "not-applicable", "not-available", "not-documented"}
	statuses := []string{"supported", "not-yet-supported", "vendor-console", "user-setting"}
	topics := map[string]bool{}
	for _, topic := range c.Topics {
		topics[topic.ID] = true
	}
	seen := map[string]bool{}
	for _, s := range c.Settings {
		where := s.ID
		if s.ID == "" || seen[s.ID] {
			t.Errorf("missing or duplicate id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Title == "" || strings.TrimSpace(s.Description) == "" || !topics[s.Topic] {
			t.Errorf("%s: needs a title, a description and a known topic", where)
		}
		if !slices.Contains([]string{"profile", "native", "map"}, s.File) || !slices.Contains(statuses, s.Status) {
			t.Errorf("%s: bad file %q or status %q", where, s.File, s.Status)
		}
		if len(s.Sources) == 0 {
			t.Errorf("%s: needs at least one source", where)
		}
		for _, src := range s.Sources {
			if !strings.HasPrefix(src.URL, "https://") || src.Title == "" {
				t.Errorf("%s: source %+v needs a title and an https URL", where, src)
			}
		}
		if !datePattern.MatchString(s.Researched) {
			t.Errorf("%s: researched %q is not YYYY-MM-DD", where, s.Researched)
		}
		if len(s.Reach) == 0 {
			t.Errorf("%s: needs reach", where)
		}
		for tool, perOS := range s.Reach {
			if !slices.Contains(c.Tools, tool) {
				t.Errorf("%s: unknown tool %q", where, tool)
			}
			for osName, r := range perOS {
				if !slices.Contains(c.OSes, osName) || !slices.Contains(levels, r.Level) {
					t.Errorf("%s: %s/%s has bad os or level %q", where, tool, osName, r.Level)
				}
			}
		}
		if s.Status == "supported" {
			if len(s.YAMLPaths) == 0 || len(s.Value) == 0 {
				t.Errorf("%s: supported settings need yaml_paths and a value spec", where)
			}
		} else if s.VendorKey == "" || len(s.YAMLPaths) > 0 {
			t.Errorf("%s: %s settings need a vendor_key and no yaml_paths", where, s.Status)
		}
	}
}

func TestCatalogLabelsMatchSpec(t *testing.T) {
	c := loadRepoCatalog(t)
	want := map[string]string{
		"not-yet-supported": "not yet supported by AgentEdict",
		"vendor-console":    "vendor console only",
		"user-setting":      "user setting: users can change it",
	}
	if !reflect.DeepEqual(c.Labels, want) {
		t.Fatalf("labels = %v", c.Labels)
	}
	for _, tool := range c.Tools {
		if c.ToolNames[tool] == "" {
			t.Errorf("tool %s has no display name", tool)
		}
	}
	for _, osName := range c.OSes {
		if c.OSNames[osName] == "" {
			t.Errorf("OS %s has no display name", osName)
		}
	}
	if !slices.Equal(c.Tools, []string{"codex", "claude", "opencode", "gemini", "cursor", "antigravity", "copilot", "kiro", "windsurf", "cline"}) || !slices.Equal(c.OSes, []string{"macos", "linux", "windows"}) {
		t.Fatalf("tools %v oses %v", c.Tools, c.OSes)
	}
}
