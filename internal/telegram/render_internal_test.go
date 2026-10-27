package telegram

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

// textLen must agree with what the fake (modelled on Telegram) counts, or
// the D9 check refuses too little or too much.
func TestTextLenMatchesParsedLength(t *testing.T) {
	for _, s := range []string{
		"plain",
		"<b>bold</b> &lt;x&gt; &amp;",
		"emoji 😀 counts two",
		show("<&>\u202e😀\n"+strings.Repeat("é", 50), true),
		renderRun(approval.RunPrompt{Target: "t", Argv: "a & b", Reason: "r <x>", ExpiresAt: time.Now()}),
	} {
		want, err := telegramtest.CheckHTML(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got := textLen(s); got != want {
			t.Errorf("textLen(%q) = %d, parsed length %d", s, got, want)
		}
	}
}

// The boundary of docs/05 D9: the largest prompt that fits is accepted,
// one more character is refused, and the longest status line still fits.
func TestFitsBoundary(t *testing.T) {
	p := approval.RunPrompt{Target: "t", ExpiresAt: time.Now()}
	base := textLen(renderRun(p))
	room := maxMessageLen - 2 - statusReserve - base
	p.Argv = strings.Repeat("&", room)
	if !fits(renderRun(p)) {
		t.Fatalf("a prompt of exactly the limit is refused")
	}
	p.Argv += "x"
	if fits(renderRun(p)) {
		t.Fatalf("a prompt one over the limit fits")
	}
	for _, k := range []approval.OutcomeKind{approval.Approved, approval.Denied, approval.Expired, approval.Withdrawn,
		approval.Failed, approval.ElevationLive, approval.ElevationEnded, approval.ElevationExpired} {
		s, err := statusLine(approval.Outcome{Kind: k, Until: time.Now()}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if textLen(s) > statusReserve {
			t.Errorf("status %q longer than the reserve", s)
		}
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"a\u202eb":     `a\u{202e}b`,
		"a\nb\tc":      `a\u{000a}b\u{0009}c`,
		"x\u00ady":     `x\u{00ad}y`, // soft hyphen (Cf)
		"\U000E0041":   `\u{e0041}`,  // tag character (Cf)
		"\u3164":       `\u{3164}`,   // Hangul filler
		"ok ä 😀":       "ok ä 😀",
		"\x7f\u009b":   `\u{007f}\u{009b}`,
		"\ue000":       `\u{e000}`, // private use
		"\u2029\u2028": `\u{2029}\u{2028}`,
	} {
		if got := sanitize(in, false); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitize("a\nb\tc", true); got != "a\nb\tc" {
		t.Errorf("multi-line sanitize = %q", got)
	}
}

func TestCallbackKeys(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		k := newCallbackKey()
		if !wellFormedKey(k) || len(k) != 25 || len(k) > 64 {
			t.Fatalf("bad key %q", k)
		}
		if seen[k] {
			t.Fatal("duplicate key")
		}
		seen[k] = true
	}
	for _, bad := range []string{"", "v1:", "v2:AAAAAAAAAAAAAAAAAAAAAA", "v1:AAAAAAAAAAAAAAAAAAAAA=", "v1:AAAAAAAAAAAAAAAAAAAAA+", "v1:AAAAAAAAAAAAAAAAAAAAAAA"} {
		if wellFormedKey(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Review L3: every default-ignorable code point, Braille blank and long runs
// of combining marks are shown, not rendered invisibly.
func TestSanitizeInvisibles(t *testing.T) {
	for _, r := range []rune{
		0x034F,         // combining grapheme joiner
		0xFE00, 0xFE0F, // variation selectors
		0xE0100, 0xE01EF, // variation selectors supplement
		0x180B, 0x180D, 0x180F, // Mongolian free variation selectors
		0x180E,         // Mongolian vowel separator
		0x17B4, 0x17B5, // Khmer inherent vowels
		0x2800,                 // Braille pattern blank
		0x115F, 0x3164, 0xFFA0, // Hangul fillers
		0x2065, 0xFFF0, 0xE0000, 0xE0FFF, // Other_Default_Ignorable_Code_Point
	} {
		in := "a" + string(r) + "b"
		want := fmt.Sprintf(`a\u{%04x}b`, r)
		if got := sanitize(in, false); got != want {
			t.Errorf("sanitize(%U) = %q, want %q", r, got, want)
		}
	}
	// Every Other_Default_Ignorable_Code_Point is escaped.
	for _, rt := range unicode.Other_Default_Ignorable_Code_Point.R16 {
		for r := rune(rt.Lo); r <= rune(rt.Hi); r += rune(rt.Stride) {
			if s := sanitize(string(r), false); !strings.HasPrefix(s, `\u{`) {
				t.Errorf("%U not escaped", r)
			}
		}
	}
	for _, rt := range unicode.Other_Default_Ignorable_Code_Point.R32 {
		for r := rune(rt.Lo); r <= rune(rt.Hi); r += rune(rt.Stride) {
			if s := sanitize(string(r), false); !strings.HasPrefix(s, `\u{`) {
				t.Errorf("%U not escaped", r)
			}
		}
	}

	// Combining marks: four in a row are kept, the rest of the run is
	// escaped; the count restarts after any other character.
	acute := "́"
	if got := sanitize("e"+strings.Repeat(acute, 4)+"x", false); got != "e"+strings.Repeat(acute, 4)+"x" {
		t.Errorf("four marks changed: %q", got)
	}
	got := sanitize("e"+strings.Repeat(acute, 6)+"x"+acute, false)
	want := "e" + strings.Repeat(acute, 4) + `\u{0301}\u{0301}` + "x" + acute
	if got != want {
		t.Errorf("long mark run: %q, want %q", got, want)
	}
	// Enclosing marks (Me) count too.
	if got := sanitize("o"+strings.Repeat("⃝", 5), false); got != "o"+strings.Repeat("⃝", 4)+`\u{20dd}` {
		t.Errorf("enclosing marks: %q", got)
	}
}
