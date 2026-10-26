package telegram

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Tuhis/Nyyrikki/internal/approval"
)

// Limits from docs/05 D8 and D9 and the Bot API (docs/05 M3).
const (
	maxReasonRunes     = 500
	maxClientNameRunes = 64
	maxMessageLen      = 4096
	cutMarker          = "…(cut)"
	claimHeader        = "Agent's claim (unverified):"
)

// errTooLarge is the agent-facing message of docs/05 D9.
const errTooLargeMsg = "request too large to show the approver; split it"

// statusReserve is room kept for the status line a settled prompt gains
// (docs/05 D6, D7), so that every later edit of a prompt that was sent
// also fits. The longest line is shorter than this.
const statusReserve = 64

// sanitize shows characters that could hide or reorder text as \u{…}:
// controls, bidi controls, zero-width and other format characters, line and
// paragraph separators, private-use and surrogate code points, Hangul
// fillers, and invalid UTF-8 (docs/05 D8). keepNewlines keeps '\n' and '\t'
// as they are, for multi-line blocks (stdin, reason); they can't leave the
// block they are in.
func sanitize(s string, keepNewlines bool) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size <= 1 {
			sb.WriteString(`\u{fffd}`)
			continue
		}
		if keepNewlines && (r == '\n' || r == '\t') {
			sb.WriteRune(r)
			continue
		}
		if hidden(r) {
			fmt.Fprintf(&sb, `\u{%04x}`, r)
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func hidden(r rune) bool {
	switch {
	case unicode.IsControl(r): // Cc: C0, DEL, C1
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C: // bidi
		return true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF: // zero-width
		return true
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0: // Hangul fillers render blank
		return true
	case unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co, unicode.Cs):
		return true
	}
	return false
}

// escapeHTML escapes the three characters HTML parse mode requires
// (docs/05 M3).
func escapeHTML(s string) string {
	return htmlEscaper.Replace(s)
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// cut shortens s to n runes and marks the cut (docs/05 D8).
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + cutMarker
}

// show is the one way text reaches a message: sanitized, then escaped.
func show(s string, keepNewlines bool) string {
	return escapeHTML(sanitize(s, keepNewlines))
}

func code(s string) string { return "<code>" + show(s, false) + "</code>" }

func clock(t time.Time) string { return t.UTC().Format("15:04:05") }

func renderRunAs(sb *strings.Builder, id approval.Identity) {
	sb.WriteString("<b>Runs as:</b> ")
	sb.WriteString(code(id.User))
	if len(id.Groups) > 0 {
		sb.WriteString(", groups ")
		for i, g := range id.Groups {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(code(g))
		}
	}
	sb.WriteString("\n")
}

func renderAgent(sb *strings.Builder, a approval.Agent) {
	sb.WriteString("<b>Agent:</b> ")
	sb.WriteString(code(cut(a.ClientName, maxClientNameRunes)))
	sb.WriteString(" <i>(name claimed by the client)</i>\n")
	sb.WriteString("key ")
	sb.WriteString(code(a.KeyShort))
	sb.WriteString(", signed in ")
	if a.SignedInAt.IsZero() {
		sb.WriteString("at an unknown time")
	} else {
		sb.WriteString(a.SignedInAt.UTC().Format("2006-01-02 15:04:05") + " UTC")
	}
	sb.WriteString("\n")
}

// renderReason puts the reason in its own blockquote under the claim header.
// It is the only place agent prose appears (docs/05 D5, D8).
func renderReason(sb *strings.Builder, reason string) {
	sb.WriteString("<b>" + claimHeader + "</b>\n<blockquote>")
	if strings.TrimSpace(reason) == "" {
		sb.WriteString("<i>(no reason given)</i>")
	} else {
		sb.WriteString(show(cut(reason, maxReasonRunes), true))
	}
	sb.WriteString("</blockquote>\n")
}

// renderRun renders the one-off prompt of docs/05 D5, without a status line.
func renderRun(p approval.RunPrompt) string {
	var sb strings.Builder
	sb.WriteString("<b>Run request</b> on ")
	sb.WriteString(code(p.Target))
	sb.WriteString("\n")
	renderRunAs(&sb, p.RunAs)
	renderAgent(&sb, p.Agent)
	sb.WriteString("\n<b>Request:</b>\n<pre>")
	sb.WriteString(show(p.Argv, false))
	sb.WriteString("</pre>\n")
	if p.Stdin != "" {
		sb.WriteString("<b>stdin:</b>\n<pre>")
		sb.WriteString(show(p.Stdin, true))
		sb.WriteString("</pre>\n")
	}
	if p.Interactive {
		sb.WriteString("<b>Interactive:</b> yes (terminal session)\n")
	}
	sb.WriteString("\n")
	renderReason(&sb, p.Reason)
	sb.WriteString("\n<b>Answer by:</b> " + clock(p.ExpiresAt) + " UTC")
	return sb.String()
}

// renderElevation renders the elevation prompt of docs/05 D7.
func renderElevation(p approval.ElevationPrompt) string {
	var sb strings.Builder
	sb.WriteString("<b>Elevation request</b>\n<b>Targets:</b> ")
	for i, t := range p.Targets {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(code(t))
	}
	sb.WriteString("\n<b>Duration:</b> " + duration(p.Duration) + "\n")
	renderRunAs(&sb, p.RunAs)
	renderAgent(&sb, p.Agent)
	sb.WriteString("\n")
	renderReason(&sb, p.Reason)
	sb.WriteString("\n<b>Answer by:</b> " + clock(p.ExpiresAt) + " UTC")
	return sb.String()
}

func duration(d time.Duration) string {
	d = d.Round(time.Second)
	if d > 0 && d%time.Minute == 0 {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return d.String()
}

// statusLine is the line a settled prompt gains (docs/05 D6, D7). An
// unknown kind is an error: the prompt keeps its buttons rather than
// claiming an outcome nobody decided.
func statusLine(o approval.Outcome, now time.Time) (string, error) {
	at := o.At
	if at.IsZero() {
		at = now
	}
	var s string
	switch o.Kind {
	case approval.Approved:
		s = "Approved at " + clock(at) + " UTC"
	case approval.Denied:
		s = "Denied at " + clock(at) + " UTC"
	case approval.Expired:
		s = "Expired: denied"
	case approval.Withdrawn:
		s = "Withdrawn by the agent"
	case approval.Failed:
		s = "Failed: not completed"
	case approval.ElevationLive:
		if o.Until.IsZero() {
			return "", fmt.Errorf("telegram: ElevationLive without Until")
		}
		s = "Live until " + clock(o.Until) + " UTC"
	case approval.ElevationEnded:
		s = "Ended at " + clock(at) + " UTC"
	case approval.ElevationExpired:
		s = "Expired at " + clock(at) + " UTC"
	default:
		return "", fmt.Errorf("telegram: unknown outcome kind %d", o.Kind)
	}
	return "<b>" + s + "</b>", nil
}

func withStatus(body, status string) string { return body + "\n\n" + status }

// textLen is the length Telegram checks against 4096: characters after
// entity parsing, counted in UTF-16 code units. Tags don't count and an
// entity counts as one. Every '<' and '&' in a rendered message is
// Nyyrikki's own markup, since agent text is escaped.
func textLen(html string) int {
	n := 0
	for i := 0; i < len(html); {
		switch html[i] {
		case '<':
			j := strings.IndexByte(html[i:], '>')
			if j < 0 {
				return n + len(html) - i
			}
			i += j + 1
			continue
		case '&':
			j := strings.IndexByte(html[i:], ';')
			if j < 0 {
				return n + len(html) - i
			}
			n++
			i += j + 1
			continue
		}
		r, size := utf8.DecodeRuneInString(html[i:])
		if l := utf16.RuneLen(r); l > 0 {
			n += l
		} else {
			n += 2 // invalid: count high
		}
		i += size
	}
	return n
}

// fits reports whether body, plus any status line it may later carry, is
// within Telegram's limit (docs/05 D9).
func fits(body string) bool {
	return textLen(body)+2+statusReserve <= maxMessageLen
}
