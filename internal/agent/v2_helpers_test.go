package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryandunton/agent-edict/internal/compiler"
	"gopkg.in/yaml.v3"
)

var exampleProfiles = filepath.Join("..", "..", "examples", "role-policy", "profiles")

func exampleMapText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "role-policy", "policy-map.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// compileV2Files compiles every pair the map selects, the way compile-bundle
// does, and returns bundle-relative file names with their contents.
func compileV2Files(t *testing.T, mapText string, osNames ...string) map[string][]byte {
	t.Helper()
	return compileV2FilesFrom(t, exampleProfiles, mapText, osNames...)
}

func compileV2FilesFrom(t *testing.T, profilesDir, mapText string, osNames ...string) map[string][]byte {
	t.Helper()
	m, err := ParsePolicyMapV2([]byte(mapText))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"policy-map.yaml": []byte(mapText)}
	native := map[string][]string{}
	for _, pair := range m.Pairs() {
		if !compiler.IsUnifiedAgent(pair.Agent) {
			native[pair.Profile] = append(native[pair.Profile], pair.Agent)
			continue
		}
		p, err := compiler.LoadPolicy(filepath.Join(profilesDir, pair.Profile+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, osName := range osNames {
			out, err := compiler.CompileAgent(p, osName, pair.Agent)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range out.Files {
				files[filepath.Join("profiles", osName, pair.Profile+"."+f.Extension)] = []byte(f.Content)
			}
			if len(out.ToolLevelOnly) > 0 {
				notes, _ := json.Marshal(map[string][]string{"tool_level_only": out.ToolLevelOnly})
				files[filepath.Join("profiles", osName, pair.Profile+"."+pair.Agent+".notes.json")] = append(notes, '\n')
			}
		}
	}
	for profile, products := range native {
		declared, err := compiler.LoadNativePolicy(filepath.Join(profilesDir, profile+".native.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		selected, err := compiler.SelectNativeProducts(declared, products)
		if err != nil {
			t.Fatal(err)
		}
		declaration, err := yaml.Marshal(selected)
		if err != nil {
			t.Fatal(err)
		}
		for _, osName := range osNames {
			out, err := compiler.CompileNative(selected, osName, "all")
			if err != nil {
				t.Fatal(err)
			}
			files[filepath.Join("profiles", osName, profile+".native.yaml")] = declaration
			for _, artifact := range out.Artifacts {
				files[filepath.Join("profiles", osName, profile+"."+artifact.Extension)] = []byte(artifact.Content)
			}
		}
	}
	return files
}

func writeFiles(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for name, content := range files {
		target := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func writeV2Snapshot(t *testing.T, mapText string, osNames ...string) string {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, compileV2Files(t, mapText, osNames...))
	return dir
}
