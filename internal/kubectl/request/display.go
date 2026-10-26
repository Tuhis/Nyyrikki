package request

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
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
// Secret, whose --patch then carries secret values (docs/04 D14): a
// positional names one, or the target comes from -f, where it can't be
// told from the argv.
func (c *Canonical) patchesSecret() bool {
	if len(c.path) != 1 || c.path[0] != "patch" {
		return false
	}
	if _, ok := c.flag("filename"); ok {
		return true
	}
	pos := c.positionals
	if c.dash >= 0 && c.dash <= len(pos) {
		pos = pos[:c.dash]
	}
	for _, a := range pos {
		kind, _, _ := strings.Cut(strings.ToLower(a), "/")
		kind, _, _ = strings.Cut(kind, ".") // secret.v1, secrets.v1.
		if kind == "secret" || kind == "secrets" {
			return true
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
	if c.manifestStdin() {
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

// safeShellChars are the characters that need no quoting (docs/04 §5.2).
func safeShellRune(r rune) bool {
	return r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		strings.ContainsRune("@%+=:,./_-", r))
}

// quote shell-quotes s for display, escaping invisible characters.
func quote(s string) string {
	needs := s == ""
	for _, r := range s {
		if !safeShellRune(r) {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	b.WriteByte('\'')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02x}`, s[i])
		case r == '\'':
			b.WriteString(`'\''`)
		case invisible(r):
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	b.WriteByte('\'')
	return b.String()
}

// invisible reports characters that could hide or reorder what the
// approver reads: control characters, format characters (bidi controls,
// zero-width characters, BOM) and line/paragraph separators.
func invisible(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
		r == 'ᅟ' || r == 'ᅠ' || r == 'ㅤ' || r == 'ﾠ' // Hangul fillers render as blanks
}

// isPlainText reports whether b can be shown as text: valid UTF-8, and no
// invisible characters other than tab, newline and CR before a newline.
func isPlainText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == '\n' || r == '\t':
		case r == '\r' && bytes.HasPrefix(b[i+1:], []byte("\n")):
		case invisible(r):
			return false
		}
		i += size
	}
	return true
}
