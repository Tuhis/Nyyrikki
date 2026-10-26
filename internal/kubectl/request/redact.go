package request

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// lastApplied is the annotation client-side apply fills with the whole
// object, Secret data included (docs/gotchas.md, Kubernetes).
const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// redactManifests returns stdin with the data and stringData values of
// every Secret replaced (docs/04 D14), and ok=false when it can't be shown
// safely as text.
//
// stdin is decoded with the same YAML-or-JSON stream decoder kubectl uses
// for -f -. Without a Secret in it, the original bytes are shown as sent.
// With one, the decoded documents are shown re-serialised, so only what
// was decoded, redacted, reaches the approver. A stream that doesn't
// decode is shown as sent unless it mentions a Secret at all.
func redactManifests(stdin []byte) (out []byte, ok bool) {
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(stdin), 4096)
	var docs []any
	redacted := false
	for {
		var raw json.RawMessage
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if bytes.Contains(bytes.ToLower(stdin), []byte("secret")) {
				return nil, false
			}
			return stdin, true
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var doc any
		if err := d.Decode(&doc); err != nil {
			return nil, false
		}
		if doc == nil {
			continue
		}
		if redactObject(doc) {
			redacted = true
		}
		docs = append(docs, doc)
	}
	if !redacted {
		return stdin, true
	}
	var b bytes.Buffer
	for i, doc := range docs {
		y, err := yaml.Marshal(doc)
		if err != nil {
			return nil, false
		}
		if i > 0 {
			b.WriteString("---\n")
		}
		b.Write(y)
	}
	return b.Bytes(), true
}

// redactObject redacts v in place if it is a Secret, and recurses into
// the items of a list. Kind and keys are matched case-insensitively, which
// redacts more than Kubernetes would read, never less.
func redactObject(v any) bool {
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	redacted := false
	for k, val := range obj {
		if strings.EqualFold(k, "items") {
			if items, ok := val.([]any); ok {
				for _, it := range items {
					if redactObject(it) {
						redacted = true
					}
				}
			}
		}
	}
	if !isSecret(obj) {
		return redacted
	}
	for k, val := range obj {
		if strings.EqualFold(k, "data") || strings.EqualFold(k, "stringData") {
			if m, ok := val.(map[string]any); ok {
				for dk, dv := range m {
					m[dk] = redactedMarker(valueBytes(dv))
				}
			} else if val != nil {
				obj[k] = redactedMarker(valueBytes(val))
			}
		}
		if strings.EqualFold(k, "metadata") {
			if md, ok := val.(map[string]any); ok {
				for ak, av := range md {
					if !strings.EqualFold(ak, "annotations") {
						continue
					}
					if ann, ok := av.(map[string]any); ok {
						for name, value := range ann {
							if strings.EqualFold(name, lastApplied) {
								ann[name] = redactedMarker(valueBytes(value))
							}
						}
					}
				}
			}
		}
	}
	return true
}

func isSecret(obj map[string]any) bool {
	for k, v := range obj {
		if strings.EqualFold(k, "kind") {
			if s, ok := v.(string); ok && strings.EqualFold(strings.TrimSpace(s), "Secret") {
				return true
			}
		}
	}
	return false
}

func valueBytes(v any) []byte {
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	b, _ := json.Marshal(v)
	return b
}
