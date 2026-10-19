//go:build js && wasm

// Command edict-wasm exposes AgentEdict's checks to the configuration
// builder in the browser, as globalThis.edictBuilder. Every function takes
// strings and returns a JSON string: {"ok":true,"value":...} or
// {"ok":false,"error":"..."}.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/ryandunton/agent-edict/internal/builder"
	"github.com/ryandunton/agent-edict/internal/version"
)

func reply(value any, err error) string {
	body := map[string]any{"ok": true, "value": value}
	if err != nil {
		body = map[string]any{"ok": false, "error": err.Error()}
	}
	out, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		out, _ = json.Marshal(map[string]any{"ok": false, "error": marshalErr.Error()})
	}
	return string(out)
}

// export wraps fn so that bad arguments and panics come back as errors.
func export(want int, fn func(args []string) (any, error)) js.Func {
	return js.FuncOf(func(_ js.Value, values []js.Value) (result any) {
		defer func() {
			if r := recover(); r != nil {
				result = reply(nil, fmt.Errorf("internal error: %v", r))
			}
		}()
		if len(values) != want {
			return reply(nil, fmt.Errorf("expected %d string arguments, got %d", want, len(values)))
		}
		args := make([]string, want)
		for i, v := range values {
			if v.Type() != js.TypeString {
				return reply(nil, fmt.Errorf("argument %d must be a string", i+1))
			}
			args[i] = v.String()
		}
		return reply(fn(args))
	})
}

func main() {
	js.Global().Set("edictBuilder", js.ValueOf(map[string]any{
		"yamlToJSON": export(1, func(a []string) (any, error) {
			out, err := builder.YAMLToJSON([]byte(a[0]))
			return json.RawMessage(out), err
		}),
		"lintProfile": export(1, func(a []string) (any, error) { return builder.LintProfile([]byte(a[0])), nil }),
		"lintNative":  export(1, func(a []string) (any, error) { return builder.LintNative([]byte(a[0])), nil }),
		"lintMap":     export(1, func(a []string) (any, error) { return builder.LintMap([]byte(a[0])), nil }),
		"convertV1Map": export(1, func(a []string) (any, error) {
			out, err := builder.ConvertV1Map([]byte(a[0]))
			return string(out), err
		}),
		"parsePasted": export(1, func(a []string) (any, error) {
			pasted, err := builder.ParsePasted([]byte(a[0]))
			return pasted, err
		}),
		"preview": export(4, func(a []string) (any, error) {
			return builder.Preview(a[0], []byte(a[1]), a[2], a[3]), nil
		}),
		"version": export(0, func([]string) (any, error) { return version.Version, nil }),
	}))
	select {} // keep the exported functions alive
}
