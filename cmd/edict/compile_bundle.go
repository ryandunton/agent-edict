package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"gopkg.in/yaml.v3"
)

// compileBundleCommand compiles every profile-agent pair a version 2 map can
// select, for every requested OS, and writes nothing unless all succeed.
func compileBundleCommand(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("compile-bundle", flag.ContinueOnError)
	fs.SetOutput(output)
	mapPath := fs.String("map", "", "Version 2 policy map")
	profilesDir := fs.String("profiles-dir", "", "Directory with <profile>.yaml and <profile>.native.yaml sources")
	targetOS := fs.String("target-os", "all", "windows, linux, darwin, or all")
	outDir := fs.String("output-dir", "dist", "Bundle root to write policy-map.yaml and profiles/ into")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mapPath == "" || *profilesDir == "" || fs.NArg() != 0 {
		return fmt.Errorf("provide -map and -profiles-dir and no positional arguments")
	}
	// Writing over an earlier bundle would sign its stale files, such as an
	// old notes file, along with the new ones.
	for _, existing := range []string{"policy-map.yaml", "profiles"} {
		if _, err := os.Lstat(filepath.Join(*outDir, existing)); err == nil {
			return fmt.Errorf("output directory %s already contains a bundle; use a new or empty directory", *outDir)
		}
	}
	mapData, err := os.ReadFile(*mapPath)
	if err != nil {
		return fmt.Errorf("read policy map: %w", err)
	}
	var header struct {
		Version int `yaml:"version"`
	}
	if yaml.Unmarshal(mapData, &header) != nil || header.Version != 2 {
		return fmt.Errorf("compile-bundle requires a version 2 map; use compile or compile-native for version 1")
	}
	m, err := agent.ParsePolicyMapV2(mapData)
	if err != nil {
		return err
	}
	osNames := []string{*targetOS}
	if *targetOS == "all" {
		osNames = []string{"windows", "linux", "darwin"}
	}

	files := map[string][]byte{"policy-map.yaml": mapData}
	add := func(name string, content []byte) error {
		if _, taken := files[name]; taken {
			return fmt.Errorf("two outputs would write %s", name)
		}
		files[name] = content
		return nil
	}
	agentsByProfile := map[string][]string{}
	for _, pair := range m.Pairs() {
		agentsByProfile[pair.Profile] = append(agentsByProfile[pair.Profile], pair.Agent)
	}
	profiles := make([]string, 0, len(agentsByProfile))
	for profile := range agentsByProfile {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	var notes []string
	for _, profile := range profiles {
		var unified, native []string
		for _, name := range agentsByProfile[profile] {
			if compiler.IsUnifiedAgent(name) {
				unified = append(unified, name)
			} else {
				native = append(native, name)
			}
		}
		if len(unified) > 0 {
			source := filepath.Join(*profilesDir, profile+".yaml")
			p, err := compiler.LoadPolicy(source)
			if err != nil {
				return fmt.Errorf("%s: %w", source, err)
			}
			if p.Name != profile {
				return fmt.Errorf("%s declares name %q; the map references profile %q", source, p.Name, profile)
			}
			for _, osName := range osNames {
				for _, name := range unified {
					out, err := compiler.CompileAgent(p, osName, name)
					if err != nil {
						return fmt.Errorf("profile %s for %s on %s: %w", profile, name, osName, err)
					}
					for _, file := range out.Files {
						if err := add(filepath.Join("profiles", osName, profile+"."+file.Extension), []byte(file.Content)); err != nil {
							return err
						}
					}
					if len(out.ToolLevelOnly) > 0 {
						report, err := json.Marshal(struct {
							ToolLevelOnly []string `json:"tool_level_only"`
						}{out.ToolLevelOnly})
						if err != nil {
							return err
						}
						if err := add(filepath.Join("profiles", osName, profile+"."+name+".notes.json"), append(report, '\n')); err != nil {
							return err
						}
						for _, setting := range out.ToolLevelOnly {
							notes = append(notes, fmt.Sprintf("%s %s %s: %s is enforced in Claude's own tools only", osName, profile, name, setting))
						}
					}
				}
			}
		}
		if len(native) > 0 {
			source := filepath.Join(*profilesDir, profile+".native.yaml")
			declared, err := compiler.LoadNativePolicy(source)
			if err != nil {
				return fmt.Errorf("%s: %w", source, err)
			}
			if declared.Name != profile {
				return fmt.Errorf("%s declares name %q; the map references profile %q", source, declared.Name, profile)
			}
			selected, err := compiler.SelectNativeProducts(declared, native)
			if err != nil {
				return err
			}
			policyYAML, err := yaml.Marshal(selected)
			if err != nil {
				return err
			}
			if len(policyYAML) > 1024*1024 {
				return fmt.Errorf("native declaration for %s exceeds size limit", profile)
			}
			for _, osName := range osNames {
				out, err := compiler.CompileNative(selected, osName, "all")
				if err != nil {
					return fmt.Errorf("native profile %s on %s: %w", profile, osName, err)
				}
				named, err := nativeOutputFiles(profile, policyYAML, out)
				if err != nil {
					return err
				}
				for name, content := range named {
					if err := add(filepath.Join("profiles", osName, name), content); err != nil {
						return err
					}
				}
			}
		}
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		target := filepath.Join(*outDir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(target, files[name], 0644); err != nil {
			return err
		}
	}
	fmt.Fprintf(output, "Compiled bundle -> %s (%d files)\n", *outDir, len(files))
	for _, note := range notes {
		fmt.Fprintln(output, note)
	}
	return nil
}
