// Package hookjson reads untrusted hook payloads and protected hook policies.
package hookjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ReadObject bounds memory and rejects duplicate JSON keys at every nesting
// level. encoding/json otherwise accepts duplicate keys with last-value wins,
// so a payload could show one value to a client and another to this evaluator.
func ReadObject(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, errors.New("cannot read JSON")
	}
	if int64(len(data)) > limit {
		return nil, errors.New("JSON exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("expected a JSON object")
	}
	if err := scanContainer(decoder, '{', 1); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return data, nil
}

func scanContainer(decoder *json.Decoder, opening json.Delim, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds limit")
	}
	seen := map[string]bool{}
	for decoder.More() {
		if opening == '{' {
			key, err := decoder.Token()
			if err != nil {
				return errors.New("malformed JSON object")
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate or invalid JSON key")
			}
			seen[name] = true
		}
		token, err := decoder.Token()
		if err != nil {
			return errors.New("malformed JSON value")
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' && delimiter != '[' {
				return errors.New("unexpected JSON delimiter")
			}
			if err := scanContainer(decoder, delimiter, depth+1); err != nil {
				return err
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil || (opening == '{' && closing != json.Delim('}')) || (opening == '[' && closing != json.Delim(']')) {
		return errors.New("incomplete JSON container")
	}
	return nil
}

// StringField returns a JSON string member. A present null, non-string, or
// (when required) empty value is an error rather than a zero value.
func StringField(fields map[string]json.RawMessage, name string, required bool) (string, error) {
	raw, ok := fields[name]
	if !ok && !required {
		return "", nil
	}
	var value string
	if !ok || string(raw) == "null" || json.Unmarshal(raw, &value) != nil || (required && value == "") {
		return "", errors.New("invalid hook field " + name)
	}
	return value, nil
}
