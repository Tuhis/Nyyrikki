// Package textsafe decides which characters could hide or reorder what
// an approver reads (docs/04 §5.2), so that every request display uses
// the same list.
package textsafe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Invisible reports characters that could hide or reorder what the
// approver reads: control characters, format characters (bidi controls,
// zero-width characters, BOM), line/paragraph separators, every Unicode
// default-ignorable code point (variation selectors, fillers, tags and
// the like), the blank braille pattern U+2800, and every space other than
// U+0020: a shell splits words only on ASCII blanks, so a no-break space
// would read as a word break that isn't one (docs/07 D2).
func Invisible(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		(unicode.Is(unicode.Zs, r) && r != ' ') ||
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

// MaxCombiningRun is how many combining marks in a row are shown as they
// are; the rest of a longer run is escaped, so stacked marks can't paint
// over neighbouring text.
const MaxCombiningRun = 4

// IsCombining reports a combining mark.
func IsCombining(r rune) bool { return unicode.In(r, unicode.Mn, unicode.Me) }

// safeShellRune reports the characters that need no quoting (docs/04
// §5.2).
func safeShellRune(r rune) bool {
	return r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		strings.ContainsRune("@%+=:,./_-", r))
}

// Quote shell-quotes s for display (docs/04 §5.2): as it is when every
// character is safe, otherwise in single quotes, with invisible
// characters, combining marks past MaxCombiningRun and invalid UTF-8
// shown as escapes. Every request display uses it, so that one argv
// element reads the same whatever the target type.
func Quote(s string) string {
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
		if IsCombining(r) {
			run++
		} else {
			run = 0
		}
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02x}`, s[i])
		case r == '\'':
			b.WriteString(`'\''`)
		case Invisible(r) || run > MaxCombiningRun:
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	b.WriteByte('\'')
	return b.String()
}
