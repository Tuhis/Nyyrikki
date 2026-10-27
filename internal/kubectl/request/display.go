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
	run := 0 // consecutive combining marks
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if isCombining(r) {
			run++
		} else {
			run = 0
		}
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02x}`, s[i])
		case r == '\'':
			b.WriteString(`'\''`)
		case invisible(r) || run > maxCombiningRun:
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
// zero-width characters, BOM), line/paragraph separators, every Unicode
// default-ignorable code point (variation selectors, fillers, tags and
// the like) and the blank braille pattern U+2800.
func invisible(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		r == 0x034F || // combining grapheme joiner
		r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0 || // Hangul fillers
		(r >= 0x17B4 && r <= 0x17B5) || // Khmer inherent vowels
		(r >= 0x180B && r <= 0x180F) || // Mongolian free variation selectors, vowel separator
		(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) || // variation selectors
		(r >= 0xE0000 && r <= 0xE0FFF) || // tags and unassigned default-ignorables
		r == 0x2800 // braille pattern blank
}

// maxCombiningRun is how many combining marks in a row are shown as they
// are; the rest of a longer run is escaped, so stacked marks can't paint
// over neighbouring text.
const maxCombiningRun = 4

func isCombining(r rune) bool { return unicode.In(r, unicode.Mn, unicode.Me) }

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
