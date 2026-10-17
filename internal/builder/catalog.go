package builder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// Catalog describes every setting the configuration builder shows.
type Catalog struct {
	Version    int               `json:"version"`
	Researched string            `json:"researched"`
	Tools      []string          `json:"tools"`
	ToolNames  map[string]string `json:"tool_names"`
	OSes       []string          `json:"oses"`
	OSNames    map[string]string `json:"os_names"`
	Labels     map[string]string `json:"labels"`
	Topics     []Topic           `json:"topics"`
	Settings   []Setting         `json:"settings"`
}

// Topic groups settings in the library.
type Topic struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Setting is one entry in the library. Only "supported" settings have YAML
// paths and can be added to a file.
type Setting struct {
	ID          string                      `json:"id"`
	Title       string                      `json:"title"`
	Topic       string                      `json:"topic"`
	File        string                      `json:"file"`
	Status      string                      `json:"status"`
	Required    bool                        `json:"required,omitempty"`
	YAMLPaths   []string                    `json:"yaml_paths,omitempty"`
	Value       json.RawMessage             `json:"value,omitempty"`
	Description string                      `json:"description"`
	Reach       map[string]map[string]Reach `json:"reach"`
	VendorKey   string                      `json:"vendor_key,omitempty"`
	Sources     []Source                    `json:"sources"`
	Researched  string                      `json:"researched"`
}

// Reach says how a setting lands for one tool on one OS.
type Reach struct {
	Level  string `json:"level"`
	Writes string `json:"writes,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Source is where a setting's facts come from.
type Source struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// LoadCatalog decodes a catalog, rejecting unknown fields.
func LoadCatalog(data []byte) (*Catalog, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	return &c, nil
}

var yamlUnmarshaler = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()

// structPaths lists the leaf YAML paths of a Go type: "*" for a map key,
// "[]" for a list element. Maps and lists of scalars are leaves, as are
// types with their own YAML decoding.
func structPaths(t reflect.Type, prefix string) []string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if prefix != "" && reflect.PointerTo(t).Implements(yamlUnmarshaler) {
		return []string{prefix}
	}
	join := func(name string) string {
		if prefix == "" {
			return name
		}
		return prefix + "." + name
	}
	switch t.Kind() {
	case reflect.Struct:
		var paths []string
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if !field.IsExported() || name == "-" || name == "" {
				continue
			}
			paths = append(paths, structPaths(field.Type, join(name))...)
		}
		return paths
	case reflect.Map:
		elem := t.Elem()
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct {
			return structPaths(elem, prefix+".*")
		}
		return []string{prefix}
	case reflect.Slice:
		elem := t.Elem()
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct {
			return structPaths(elem, prefix+"[]")
		}
		return []string{prefix}
	default:
		return []string{prefix}
	}
}
