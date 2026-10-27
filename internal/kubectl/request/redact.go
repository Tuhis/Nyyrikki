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
// was decoded, redacted, reaches the approver. A stream that fails to
// decode anywhere is not shown at all (ok=false).
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
			// Fail closed: escapes ("\u0053ecret") or a Secret before the
			// broken part defeat any check of the raw bytes, so a stream
			// that doesn't decode in full is never shown as text.
			return nil, false
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
		if redactObject(doc, nil) {
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

// redactObject redacts v in place if it may be a Secret, and recurses
// into the items of a list. inherited are the kinds an item takes from its
// list when it has no "kind" of its own: apimachinery gives such an item
// the list's kind without "List" (decodeToList).
//
// kubectl reads only the exact key "kind", so that key alone decides
// whether an item inherits. Whether to redact is decided more widely: an
// object is treated as a Secret if its exact kind, any key that folds to
// "kind" (in any case, Kelvin sign included), or an inherited kind says
// so. The redactor only ever redacts more than Kubernetes would read, and
// never depends on map order.
func redactObject(v any, inherited []string) bool {
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	kinds := foldedKinds(obj)
	if _, hasKind := exactKind(obj); !hasKind {
		kinds = append(kinds, inherited...)
	}
	var itemKinds []string
	secret := false
	for _, k := range kinds {
		if strings.EqualFold(k, "Secret") {
			secret = true
		}
		if len(k) > 4 && strings.EqualFold(k[len(k)-4:], "List") {
			itemKinds = append(itemKinds, k[:len(k)-4])
		}
	}
	redacted := false
	for k, val := range obj {
		if strings.EqualFold(k, "items") {
			if items, ok := val.([]any); ok {
				for _, it := range items {
					if redactObject(it, itemKinds) {
						redacted = true
					}
				}
			}
		}
	}
	if !secret {
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

// exactKind returns the value of the exact key "kind", the only one
// kubectl and apimachinery read.
func exactKind(obj map[string]any) (string, bool) {
	s, ok := obj["kind"].(string)
	s = strings.TrimSpace(s)
	return s, ok && s != ""
}

// foldedKinds returns the values of every key that folds to "kind",
// the exact key included.
func foldedKinds(obj map[string]any) []string {
	var kinds []string
	for k, v := range obj {
		if strings.EqualFold(k, "kind") {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				kinds = append(kinds, strings.TrimSpace(s))
			}
		}
	}
	return kinds
}

func valueBytes(v any) []byte {
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	b, _ := json.Marshal(v)
	return b
}
