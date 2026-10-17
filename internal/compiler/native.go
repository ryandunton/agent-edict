package compiler

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/ryandunton/agent-edict/internal/clinehook"
	"github.com/ryandunton/agent-edict/internal/windsurfhook"
	"gopkg.in/yaml.v3"
)

// NativePolicy expresses only product-specific controls with a known consumer
// contract. It deliberately has no universal sandbox or filesystem promises.
type NativePolicy struct {
	Version     int                      `yaml:"version"`
	Name        string                   `yaml:"name"`
	Gemini      *GeminiNativePolicy      `yaml:"gemini,omitempty"`
	Cursor      *CursorNativePolicy      `yaml:"cursor,omitempty"`
	Antigravity *AntigravityNativePolicy `yaml:"antigravity,omitempty"`
	Copilot     *CopilotNativePolicy     `yaml:"copilot,omitempty"`
	Kiro        *KiroNativePolicy        `yaml:"kiro,omitempty"`
	Windsurf    *WindsurfNativePolicy    `yaml:"windsurf,omitempty"`
	Cline       *ClineNativePolicy       `yaml:"cline,omitempty"`
}

// nativeProducts lists every native product in compilation order. Each entry
// reports whether its section is present, copies it, and compiles it.
var nativeProducts = []struct {
	name    string
	present func(*NativePolicy) bool
	copy    func(dst, src *NativePolicy)
	compile func(*NativePolicy, string) (*NativeOutput, error)
}{
	{"gemini", func(p *NativePolicy) bool { return p.Gemini != nil }, func(d, s *NativePolicy) { d.Gemini = s.Gemini },
		func(p *NativePolicy, os string) (*NativeOutput, error) { return compileNativeGemini(p.Gemini, os) }},
	{"cursor", func(p *NativePolicy) bool { return p.Cursor != nil }, func(d, s *NativePolicy) { d.Cursor = s.Cursor },
		func(p *NativePolicy, os string) (*NativeOutput, error) { return compileNativeCursor(p.Cursor, os) }},
	{"antigravity", func(p *NativePolicy) bool { return p.Antigravity != nil }, func(d, s *NativePolicy) { d.Antigravity = s.Antigravity },
		func(p *NativePolicy, os string) (*NativeOutput, error) {
			return compileNativeAntigravity(p.Antigravity, os)
		}},
	{"copilot", func(p *NativePolicy) bool { return p.Copilot != nil }, func(d, s *NativePolicy) { d.Copilot = s.Copilot },
		func(p *NativePolicy, os string) (*NativeOutput, error) { return compileNativeCopilot(p.Copilot, os) }},
	{"kiro", func(p *NativePolicy) bool { return p.Kiro != nil }, func(d, s *NativePolicy) { d.Kiro = s.Kiro },
		func(p *NativePolicy, os string) (*NativeOutput, error) { return compileNativeKiro(p.Kiro, os) }},
	{"windsurf", func(p *NativePolicy) bool { return p.Windsurf != nil }, func(d, s *NativePolicy) { d.Windsurf = s.Windsurf },
		func(p *NativePolicy, os string) (*NativeOutput, error) { return compileNativeWindsurf(p.Windsurf, os) }},
	{"cline", func(p *NativePolicy) bool { return p.Cline != nil }, func(d, s *NativePolicy) { d.Cline = s.Cline },
		func(p *NativePolicy, os string) (*NativeOutput, error) { return compileNativeCline(p.Cline, os) }},
}

// NativeProducts lists the products configured through compile-native, in
// compilation order.
func NativeProducts() []string {
	names := make([]string, 0, len(nativeProducts))
	for _, product := range nativeProducts {
		names = append(names, product.name)
	}
	return names
}

// IsNativeProduct reports whether name is configured through compile-native.
func IsNativeProduct(name string) bool {
	for _, product := range nativeProducts {
		if product.name == name {
			return true
		}
	}
	return false
}

// Hook evaluators read their protected policy with these limits.
var nativeArtifactLimits = map[string]int{
	"cursor.policy.json":      256 * 1024,
	"antigravity.policy.json": 1024 * 1024,
	"windsurf.policy.json":    windsurfhook.PolicyLimit,
	"cline.policy.json":       clinehook.PolicyLimit,
}

var nativeProfileName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

func LoadNativePolicy(filename string) (*NativePolicy, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	return DecodeNativePolicy(data)
}

func DecodeNativePolicy(data []byte) (*NativePolicy, error) {
	if len(data) > 1024*1024 {
		return nil, fmt.Errorf("native policy exceeds size limit")
	}
	var p NativePolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode native policy: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("native policy must contain exactly one YAML document")
	}
	if err := validateNativePolicy(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func validateNativePolicy(p *NativePolicy) error {
	if p == nil || p.Version != 1 || !nativeProfileName.MatchString(p.Name) {
		return fmt.Errorf("native policy requires version 1 and a safe explicit name")
	}
	for _, product := range nativeProducts {
		if product.present(p) {
			return nil
		}
	}
	return fmt.Errorf("native policy requires at least one explicit product section")
}

// SelectNativePolicy returns a copy containing exactly the requested products.
func SelectNativePolicy(p *NativePolicy, product string) (*NativePolicy, error) {
	if err := validateNativePolicy(p); err != nil {
		return nil, err
	}
	if product == "all" {
		selected := *p
		return &selected, nil
	}
	for _, candidate := range nativeProducts {
		if candidate.name != product {
			continue
		}
		if !candidate.present(p) {
			return nil, fmt.Errorf("native policy has no %s section", product)
		}
		selected := &NativePolicy{Version: p.Version, Name: p.Name}
		candidate.copy(selected, p)
		return selected, nil
	}
	return nil, fmt.Errorf("unsupported native product %q", product)
}

// SelectNativeProducts returns a copy containing exactly the named products,
// each of which must have a section in p.
func SelectNativeProducts(p *NativePolicy, products []string) (*NativePolicy, error) {
	if err := validateNativePolicy(p); err != nil {
		return nil, err
	}
	selected := &NativePolicy{Version: p.Version, Name: p.Name}
	for _, product := range products {
		found := false
		for _, candidate := range nativeProducts {
			if candidate.name != product {
				continue
			}
			if !candidate.present(p) {
				return nil, fmt.Errorf("native policy %s has no %s section", p.Name, product)
			}
			candidate.copy(selected, p)
			found = true
		}
		if !found {
			return nil, fmt.Errorf("unsupported native product %q", product)
		}
	}
	if err := validateNativePolicy(selected); err != nil {
		return nil, err
	}
	return selected, nil
}

func CompileNative(p *NativePolicy, targetOS, product string) (*NativeOutput, error) {
	if err := validateTargetOS(targetOS); err != nil {
		return nil, err
	}
	selected, err := SelectNativePolicy(p, product)
	if err != nil {
		return nil, err
	}
	out := &NativeOutput{}
	for _, candidate := range nativeProducts {
		if !candidate.present(selected) {
			continue
		}
		next, err := candidate.compile(selected, targetOS)
		if err != nil {
			return nil, err
		}
		for _, artifact := range next.Artifacts {
			limit, ok := nativeArtifactLimits[artifact.Extension]
			if !ok {
				limit = 5 * 1024 * 1024
			}
			if len(artifact.Content) > limit {
				return nil, fmt.Errorf("native artifact %s exceeds consumer size limit", artifact.Extension)
			}
		}
		out.Artifacts = append(out.Artifacts, next.Artifacts...)
		out.Capabilities = append(out.Capabilities, next.Capabilities...)
	}
	return out, nil
}
