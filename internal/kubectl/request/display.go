package request

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Tuhis/Nyyrikki/internal/textsafe"
)

// redactedMarker is the form a secret-bearing value takes in the
// approver's view and the audit record (docs/04 D14).
func redactedMarker(v []byte) string {
	sum := sha256.Sum256(v)
	return fmt.Sprintf("‹redacted: %d bytes, sha256:%s›", len(v), hex.EncodeToString(sum[:])[:12])
}

// redactedArgv is the canonical argv with the values of D14's flags
// replaced. Only flags are touched: a positional is never redacted, and
// the canonical render puts every flag in --name=value form.
func (c *Canonical) redactedArgv() []string {
	out := make([]string, 0, len(c.argv))
	out = append(out, c.path...)
	secretPatch := c.patchesSecret()
	for _, f := range c.flags {
		for _, v := range f.values {
			if secretPatch && f.name == "patch" {
				v = redactedMarker([]byte(v))
			} else {
				v = redactFlagValue(f.name, v)
			}
			out = append(out, "--"+f.name+"="+v)
		}
	}
	return append(out, c.argv[len(out):]...)
}

// patchesSecret reports whether the command is a patch that may target a
// Secret, whose --patch then carries secret values (docs/04 D14): any
// positional names one, before or after "--", alone or in a
// comma-separated type list (kubectl's ResourceTypeOrNameArgs splits
// types on commas), or the target comes from -f, where it can't be told
// from the argv.
func (c *Canonical) patchesSecret() bool {
	if len(c.path) != 1 || c.path[0] != "patch" {
		return false
	}
	if _, ok := c.flag("filename"); ok {
		return true
	}
	for _, a := range c.positionals {
		types, _, _ := strings.Cut(strings.ToLower(a), "/")
		for _, typ := range strings.Split(types, ",") {
			typ, _, _ = strings.Cut(typ, ".") // secret.v1, secrets.v1.
			if typ == "secret" || typ == "secrets" {
				return true
			}
		}
	}
	return false
}

func redactFlagValue(name, v string) string {
	switch name {
	case "from-literal":
		// key=value: the key stays visible (docs/04 D14).
		if k, val, ok := strings.Cut(v, "="); ok {
			return k + "=" + redactedMarker([]byte(val))
		}
		return redactedMarker([]byte(v))
	case "docker-password":
		return redactedMarker([]byte(v))
	}
	return v
}

// DisplayArgv returns what the approver sees of the command line:
// "kubectl " and the redacted canonical argv, each element shell-quoted
// when needed, with invisible and control characters escaped (docs/04
// §5.2). It is not HTML-escaped.
func (c *Canonical) DisplayArgv() string {
	var b strings.Builder
	b.WriteString("kubectl")
	for _, a := range c.redactedArgv() {
		b.WriteByte(' ')
		b.WriteString(quote(a))
	}
	return b.String()
}

// DisplayStdin returns what the approver sees of stdin (docs/04 §5.2):
// "" without stdin, the text when it is valid UTF-8 without control
// characters (after D14's redaction), and a size and hash otherwise.
func (c *Canonical) DisplayStdin() string {
	if len(c.stdin) == 0 {
		return ""
	}
	shown, ok := c.stdin, true
	if _, raw := c.flag("raw"); raw {
		// With --raw the URL, not the body, decides the kind: a body with
		// no kind can still create a Secret (docs/04 D14).
		ok = false
	} else if c.manifestStdin() {
		shown, ok = redactManifests(c.stdin)
	}
	if !ok || !isPlainText(shown) {
		sum := sha256.Sum256(c.stdin)
		return fmt.Sprintf("‹binary: %d bytes, sha256:%s›", len(c.stdin), hex.EncodeToString(sum[:]))
	}
	return string(shown)
}

// manifestStdin reports whether stdin is read as manifests (-f -), as
// opposed to bytes for a remote process (exec, attach).
func (c *Canonical) manifestStdin() bool {
	v, ok := c.flag("filename")
	return ok && len(v) == 1 && v[0] == "-"
}

// quote shell-quotes s for display, escaping invisible characters
// (docs/04 §5.2).
func quote(s string) string { return textsafe.Quote(s) }

func invisible(r rune) bool { return textsafe.Invisible(r) }

const maxCombiningRun = textsafe.MaxCombiningRun

func isCombining(r rune) bool { return textsafe.IsCombining(r) }

// isPlainText reports whether b can be shown as text: valid UTF-8, no
// invisible characters other than tab, newline and CR before a newline,
// and no run of more than maxCombiningRun combining marks.
func isPlainText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	run := 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if isCombining(r) {
			run++
		} else {
			run = 0
		}
		switch {
		case r == '\n' || r == '\t':
		case r == '\r' && bytes.HasPrefix(b[i+1:], []byte("\n")):
		case invisible(r) || run > maxCombiningRun:
			return false
		}
		i += size
	}
	return true
}
