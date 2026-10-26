package telegram

import (
	"strings"
	"testing"
	"time"

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
