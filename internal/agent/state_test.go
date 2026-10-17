package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ryandunton/agent-edict/internal/platform"
)

func TestRoleStateRoundTrip(t *testing.T) {
	vault := t.TempDir()
	want := &RoleState{
		Version:     1,
		BundleHash:  "abc123",
		ProvenAt:    time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC),
		Users:       []platform.SessionUser{{Key: "1001", Name: "eve", Groups: []string{"engineers"}}},
		Assignments: []Assignment{{Agent: "codex", Profile: "engineering", Priority: 20, Source: "rule", Users: []string{"eve"}}},
		Installed:   map[string]string{"/etc/codex/requirements.toml": "deadbeef"},
		CreatedDirs: []string{"/etc/kiro"},
		Originals:   []OriginalCopy{{Path: "/etc/claude-code/managed-settings.json", Copy: "originals/x.orig", SHA256: "x", SavedAt: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}},
		Released:    []string{"cline"},
	}
	if err := SaveRoleState(vault, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRoleState(vault)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadRoleState = %+v, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(vault, "role-state.json"))
		if info.Mode().Perm() != 0600 {
			t.Errorf("role state mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

func TestLoadRoleStateMissingIsNil(t *testing.T) {
	got, err := LoadRoleState(t.TempDir())
	if got != nil || err != nil {
		t.Fatalf("missing state = %+v, %v", got, err)
	}
}

func TestLoadRoleStateRejectsUnknownVersionAndFields(t *testing.T) {
	for _, body := range []string{`{"version":9,"assignments":[]}`, `{"version":1,"surprise":true}`, `{"version":1}{}`, `not json`} {
		vault := t.TempDir()
		os.WriteFile(filepath.Join(vault, "role-state.json"), []byte(body), 0600)
		if _, err := LoadRoleState(vault); err == nil {
			t.Errorf("accepted role state %s", body)
		}
	}
}

func TestSaveOriginalStoresExactBytes(t *testing.T) {
	vault := t.TempDir()
	data := []byte("{\"from\":\"another admin\"}\n")
	copy, err := SaveOriginal(vault, "/etc/claude-code/managed-settings.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if copy.Path != "/etc/claude-code/managed-settings.json" || copy.SHA256 == "" || copy.SavedAt.IsZero() || !strings.HasPrefix(copy.Copy, "originals"+string(filepath.Separator)) {
		t.Errorf("copy record = %+v", copy)
	}
	stored, err := os.ReadFile(filepath.Join(vault, copy.Copy))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("stored original = %q, %v", stored, err)
	}
	if _, err := SaveOriginal(vault, "/x", make([]byte, 5*1024*1024+1)); err == nil {
		t.Error("an oversized original was copied")
	}
}

func TestSaveRoleStateLeavesNoTempFiles(t *testing.T) {
	vault := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := SaveRoleState(vault, &RoleState{Version: 1, Assignments: []Assignment{}}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(vault)
	if len(entries) != 1 || entries[0].Name() != "role-state.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("vault holds %v", names)
	}
}
