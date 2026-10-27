package telegram_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

// between returns the text between the first open and the next close.
func between(t *testing.T, s, open, close string) string {
	t.Helper()
	i := strings.Index(s, open)
	if i < 0 {
		t.Fatalf("no %q in:\n%s", open, s)
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		t.Fatalf("no %q after %q", close, open)
	}
	return rest[:j]
}

// G3: hostile reasons and client names render escaped, with hidden
// characters shown, cut to length, and only inside their labelled block.
func TestRenderHostile(t *testing.T) {
	const fakeStatus = "</blockquote><b>Approved at 12:00:00 UTC</b><blockquote>"
	hiddenRunes := []rune{
		'\u202e', '\u202a', '\u2066', '\u2069', '\u200e', '\u200f', '\u061c', // bidi
		'\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', // zero-width
		'\x00', '\x1b', '\u0085', '\u2028', // controls, separators
	}
	var hiddenStr strings.Builder
	for _, r := range hiddenRunes {
		hiddenStr.WriteRune(r)
	}
	reason := fakeStatus + " & <i>trust me</i> " + hiddenStr.String() + strings.Repeat("A", 10_000)
	name := "<b>Nyyrikki</b> &amp; \u202eevil" + strings.Repeat("N", 200)

	e := newEnv(t).start()
	p := runPrompt("apr_hostile")
	p.Reason = reason
	p.Agent.ClientName = name
	p.Argv = "kubectl get pods '<script>' --selector=a&b \u202e"
	p.Stdin = "</pre><b>Runs as:</b> root\u200b"
	m := e.askRun(p)

	// The fake parsed the HTML as Telegram would: well-formed, known tags.
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatalf("message HTML does not parse: %v", err)
	}
	for _, r := range hiddenRunes {
		if strings.ContainsRune(m.Text, r) {
			t.Errorf("message contains raw %U", r)
		}
	}
	for _, want := range []string{`\u{202e}`, `\u{200b}`, `\u{feff}`, `\u{0000}`, `\u{001b}`, `\u{0085}`, `\u{2028}`, `\u{061c}`} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("message lacks the escape %s", want)
		}
	}
	if strings.Contains(m.Text, "<b>Approved") || strings.Contains(m.Text, "<b>Nyyrikki</b>") || strings.Contains(m.Text, "<i>trust me</i>") || strings.Contains(m.Text, "<script>") {
		t.Errorf("agent markup reached the message as markup:\n%s", m.Text)
	}
	if strings.Count(m.Text, "<blockquote>") != 1 || strings.Count(m.Text, "</blockquote>") != 1 {
		t.Errorf("want exactly one blockquote:\n%s", m.Text)
	}
	if strings.Count(m.Text, "<b>Runs as:</b>") != 1 {
		t.Error("stdin forged a Runs as line")
	}

	// The reason sits whole inside its blockquote, right under the header.
	quote := between(t, m.Text, "<b>Agent's claim (unverified):</b>\n<blockquote>", "</blockquote>")
	if !strings.HasPrefix(quote, "&lt;/blockquote&gt;&lt;b&gt;Approved at") {
		t.Errorf("reason does not start the blockquote: %.80q", quote)
	}
	if !strings.HasSuffix(quote, "…(cut)") {
		t.Errorf("reason not marked as cut: …%q", quote[len(quote)-20:])
	}
	if strings.Contains(m.Text, strings.Repeat("A", 501)) {
		t.Error("reason longer than 500 characters")
	}
	// 500 characters of the original were kept: count by unescaping.
	plain := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&").Replace(strings.TrimSuffix(quote, "…(cut)"))
	escapes := strings.Count(plain, `\u{`)
	if got := utf8.RuneCountInString(plain) - escapes*(len(`\u{0000}`)-1); got != 500 {
		t.Errorf("reason kept %d characters, want 500", got)
	}

	// The client name sits inside its <code> and is marked as its claim.
	agentLine := between(t, m.Text, "<b>Agent:</b> <code>", "</code> <i>(name claimed by the client)</i>")
	if !strings.HasPrefix(agentLine, "&lt;b&gt;Nyyrikki&lt;/b&gt; &amp;amp; \\u{202e}evil") || !strings.HasSuffix(agentLine, "…(cut)") {
		t.Errorf("client name rendered as %q", agentLine)
	}
	if strings.Contains(agentLine, strings.Repeat("N", 65)) {
		t.Error("client name longer than 64 characters")
	}

	// The request is escaped inside its <pre>.
	if pre := between(t, m.Text, "<b>Request:</b>\n<pre>", "</pre>"); pre != `kubectl get pods '&lt;script&gt;' --selector=a&amp;b \u{202e}` {
		t.Errorf("request rendered as %q", pre)
	}
	if pre := between(t, m.Text, "<b>stdin:</b>\n<pre>", "</pre>"); pre != `&lt;/pre&gt;&lt;b&gt;Runs as:&lt;/b&gt; root\u{200b}` {
		t.Errorf("stdin rendered as %q", pre)
	}
}

// Invalid UTF-8 is shown, not passed on.
func TestRenderInvalidUTF8(t *testing.T) {
	e := newEnv(t).start()
	p := runPrompt("apr_utf8")
	p.Reason = "bad \xff\xfe bytes"
	m := e.askRun(p)
	if !strings.Contains(m.Text, `bad \u{fffd}\u{fffd} bytes`) {
		t.Errorf("invalid UTF-8 rendered as:\n%s", m.Text)
	}
}

// G6: a request too large to show is refused before anything is sent.
func TestOversizeRefused(t *testing.T) {
	e := newEnv(t).start()
	p := runPrompt("apr_big")
	p.Argv = "kubectl apply --filename=" + strings.Repeat("x", 4096)
	err := e.bot.AskRun(context.Background(), p)
	var ce *codes.Error
	if !errors.As(err, &ce) || ce.Code != codes.InvalidRequest || ce.Message != "request too large to show the approver; split it" {
		t.Fatalf("AskRun error %v, want invalid_request", err)
	}
	if n := e.fake.Calls("sendMessage"); n != 0 {
		t.Errorf("sendMessage called %d times", n)
	}

	// The limit counts what Telegram counts: escapes count as one, and the
	// result is refused, not shortened, for stdin too.
	p = runPrompt("apr_big_stdin")
	p.Stdin = strings.Repeat("<", 4000)
	if err := e.bot.AskRun(context.Background(), p); codes.Of(err) != codes.InvalidRequest {
		t.Fatalf("oversized stdin: %v", err)
	}
	if n := e.fake.Calls("sendMessage"); n != 0 {
		t.Errorf("sendMessage called %d times", n)
	}

	// Large but fitting: sent in full (3000 escaped characters count 3000).
	p = runPrompt("apr_fits")
	p.Stdin = strings.Repeat("<", 3000)
	m := e.askRun(p)
	if !strings.Contains(m.Text, strings.Repeat("&lt;", 3000)) {
		t.Error("a fitting request was not shown in full")
	}
}

// Elevation prompts can't grow past the limit through targets either.
func TestOversizeElevationRefused(t *testing.T) {
	e := newEnv(t).start()
	p := elevationPrompt("elv_big")
	for i := 0; i < 400; i++ {
		p.Targets = append(p.Targets, "target-number-x")
	}
	if err := e.bot.AskElevation(context.Background(), p); codes.Of(err) != codes.InvalidRequest {
		t.Fatalf("AskElevation: %v", err)
	}
	if n := e.fake.Calls("sendMessage"); n != 0 {
		t.Errorf("sendMessage called %d times", n)
	}
}
