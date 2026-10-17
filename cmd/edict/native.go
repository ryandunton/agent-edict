package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ryandunton/agent-edict/internal/antigravityhook"
	"github.com/ryandunton/agent-edict/internal/clinehook"
	"github.com/ryandunton/agent-edict/internal/compiler"
	"github.com/ryandunton/agent-edict/internal/cursorhook"
	"github.com/ryandunton/agent-edict/internal/hookjson"
	"github.com/ryandunton/agent-edict/internal/windsurfhook"
	"gopkg.in/yaml.v3"
)

func compileNativeCommand(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("compile-native", flag.ContinueOnError)
	fs.SetOutput(output)
	profile := fs.String("profile", "", "Native policy YAML with explicit product controls")
	targetOS := fs.String("target-os", "all", "windows, linux, darwin, or all")
	product := fs.String("agent", "all", "gemini, cursor, antigravity, copilot, kiro, windsurf, cline, or all declared products")
	dir := fs.String("output-dir", "dist/profiles", "Output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *profile == "" || fs.NArg() != 0 {
		return fmt.Errorf("provide -profile and no positional arguments")
	}
	p, err := compiler.LoadNativePolicy(*profile)
	if err != nil {
		return err
	}
	p, err = compiler.SelectNativePolicy(p, *product)
	if err != nil {
		return err
	}
	osNames := []string{*targetOS}
	if *targetOS == "all" {
		osNames = []string{"windows", "linux", "darwin"}
	}
	// Validate every requested platform before writing anything.
	compiled := make(map[string]*compiler.NativeOutput)
	for _, osName := range osNames {
		out, err := compiler.CompileNative(p, osName, "all")
		if err != nil {
			return fmt.Errorf("compile %s: %w", osName, err)
		}
		compiled[osName] = out
	}
	policyYAML, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	if len(policyYAML) > 1024*1024 {
		return fmt.Errorf("expanded native declaration exceeds size limit")
	}
	for _, osName := range osNames {
		out := compiled[osName]
		dest := filepath.Join(*dir, osName)
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
		files, err := nativeOutputFiles(p.Name, policyYAML, out)
		if err != nil {
			return err
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dest, name), content, 0644); err != nil {
				return err
			}
		}
		fmt.Fprintf(output, "Compiled [%s] -> %s/ (%d native files)\n", p.Name, dest, len(out.Artifacts))
		for _, capability := range out.Capabilities {
			fmt.Fprintf(output, "  %s.%s: %s — %s\n", capability.Product, capability.Control, capability.Level, capability.Details)
		}
	}
	return nil
}

// nativeOutputFiles names every file written for one native profile on one
// OS. The endpoint recompiles the typed declaration and checks the complete
// artifact bytes, rather than trusting claimed destinations or capabilities.
func nativeOutputFiles(name string, policyYAML []byte, out *compiler.NativeOutput) (map[string][]byte, error) {
	files := map[string][]byte{name + ".native.yaml": policyYAML}
	for _, artifact := range out.Artifacts {
		files[name+"."+artifact.Extension] = []byte(artifact.Content)
	}
	report, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	files[name+".native-capabilities.json"] = append(report, '\n')
	return files, nil
}

func hookCommand(args []string, input io.Reader, output, diagnostics io.Writer) int {
	// Unknown adapters do not have a safe protocol to answer with.
	if len(args) == 0 || (args[0] != "cursor" && args[0] != "antigravity" && args[0] != "windsurf" && args[0] != "cline") {
		fmt.Fprintln(diagnostics, "Unsupported hook adapter")
		return 2
	}
	adapter := args[0]
	// deny refuses in each client's own protocol. Windsurf blocks only on exit
	// 2; Cline treats any non-zero exit as permission, so it gets JSON and 0.
	deny := func() int {
		switch adapter {
		case "antigravity":
			_ = antigravityhook.Deny(output)
		case "cursor":
			_ = cursorhook.Deny(output)
		case "windsurf":
			fmt.Fprintln(diagnostics, "AgentEdict policy blocked this action.")
		case "cline":
			_ = clinehook.Respond(output, false)
			return 0
		}
		return 2
	}
	fs := flag.NewFlagSet("hook "+adapter, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Invalid arguments must not echo paths or policy data.
	event := fs.String("event", "", "Native hook event")
	policy := fs.String("policy", "", "Protected AgentEdict hook policy")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *policy == "" {
		return deny()
	}
	limit := int64(256 * 1024)
	switch adapter {
	case "antigravity":
		limit = 1024 * 1024
	case "windsurf":
		limit = windsurfhook.PolicyLimit
	case "cline":
		limit = clinehook.PolicyLimit
	}
	info, err := os.Lstat(*policy)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return deny()
	}
	f, err := os.Open(*policy)
	if err != nil {
		return deny()
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return deny()
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return deny()
	}
	// A released per-user hook product is outside AgentEdict's scope; its
	// still-registered hooks must not block the application.
	if hookjson.IsReleased(data) && *event == "" {
		switch adapter {
		case "antigravity":
			_ = antigravityhook.Allow(output)
			return 0
		case "cline":
			_ = clinehook.Respond(output, true)
			return 0
		}
	}
	policyReader := bytes.NewReader(data)
	switch adapter {
	case "antigravity":
		if *event != "" {
			return deny()
		}
		err = antigravityhook.Run(policyReader, input, output)
	case "cursor":
		err = cursorhook.Run(*event, policyReader, input, output)
	case "windsurf":
		if err := windsurfhook.Evaluate(*event, policyReader, input); err != nil {
			return deny()
		}
		return 0
	case "cline":
		if *event != "" {
			return deny()
		}
		allowed, err := clinehook.Evaluate(policyReader, input)
		if err != nil || !allowed {
			return deny()
		}
		_ = clinehook.Respond(output, true)
		return 0
	}
	if err != nil {
		fmt.Fprintln(diagnostics, "AgentEdict rejected invalid hook input or policy")
		return 2
	}
	return 0
}
