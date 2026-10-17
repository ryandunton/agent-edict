package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func TestNativePolicyRequiresExplicitValidScope(t *testing.T) {
	base := "version: 1\nname: workstation\ngemini:\n  default_decision: deny\n"
	for _, input := range []string{
		strings.Replace(base, "version: 1", "version: 2", 1),
		strings.Replace(base, "workstation", "../escape", 1),
		base + "sandbox: read-only\n", base + "---\nname: second\n",
		base + "gemini: {default_decision: allow}\n", "version: 1\nname: empty\n",
		strings.Replace(base, "default_decision", "default_decison", 1),
	} {
		if _, err := DecodeNativePolicy([]byte(input)); err == nil {
			t.Errorf("invalid native policy accepted: %s", input)
		}
	}
	p, err := DecodeNativePolicy([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux", "darwin", "windows"} {
		out, err := CompileNative(p, target, "all")
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Artifacts) != 2 || len(out.Capabilities) == 0 {
			t.Fatalf("incomplete output: %+v", out)
		}
	}
	if _, err := CompileNative(p, "linux", "cursor"); err == nil {
		t.Fatal("missing requested product accepted")
	}
	if _, err := CompileNative(p, "other", "all"); err == nil {
		t.Fatal("unsupported OS accepted")
	}
	if _, err := CompileNative(p, "linux", "other"); err == nil {
		t.Fatal("unknown product accepted")
	}
}

func TestNativeCompilationPreservesAllRequestedProducts(t *testing.T) {
	input := "version: 1\nname: workstation\ngemini:\n  default_decision: deny\ncursor:\n  hooks:\n    version: 1\n"
	p, err := DecodeNativePolicy([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	out, err := CompileNative(p, "linux", "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Artifacts) != 4 {
		t.Fatalf("lost requested artifacts: %+v", out)
	}
	selected, err := SelectNativePolicy(p, "gemini")
	if err != nil {
		t.Fatal(err)
	}
	if selected.Gemini == nil || selected.Cursor != nil || p.Cursor == nil {
		t.Fatal("selection dropped or mutated wrong scope")
	}
}

func TestNativeCompilerRejectsPolicyLargerThanHookReaderLimit(t *testing.T) {
	p := &NativePolicy{Version: 1, Name: "large", Cursor: cursorNativeFixture()}
	p.Cursor.Hooks.Shell.Allow = nil
	for i := 0; i < 32; i++ {
		p.Cursor.Hooks.Shell.Allow = append(p.Cursor.Hooks.Shell.Allow, fmt.Sprintf("%d%s", i, strings.Repeat("x", 10000)))
	}
	if _, err := CompileNative(p, "linux", "cursor"); err == nil {
		t.Fatal("compiled policy that the hook runtime cannot read")
	}
}
