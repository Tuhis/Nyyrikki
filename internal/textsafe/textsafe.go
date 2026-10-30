// Package textsafe decides which characters could hide or reorder what
// an approver reads (docs/04 §5.2), so that every request display uses
// the same list.
package textsafe

import "unicode"

// Invisible reports characters that could hide or reorder what the
// approver reads: control characters, format characters (bidi controls,
// zero-width characters, BOM), line/paragraph separators, every Unicode
// default-ignorable code point (variation selectors, fillers, tags and
// the like) and the blank braille pattern U+2800.
func Invisible(r rune) bool {
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

// MaxCombiningRun is how many combining marks in a row are shown as they
// are; the rest of a longer run is escaped, so stacked marks can't paint
// over neighbouring text.
const MaxCombiningRun = 4

// IsCombining reports a combining mark.
func IsCombining(r rune) bool { return unicode.In(r, unicode.Mn, unicode.Me) }
