package telegram_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

func enrollPrompt(id string) approval.EnrollPrompt {
	return approval.EnrollPrompt{
		ID: id, ApproverID: approverID, Target: "db-1", Address: "db-1.example.com:22",
		HostKey: "ED25519 SHA256:pr6TBeTH6wi8tgNTw+FSiVQrgmbG3FK9XV/QnVrxPTM", Sudo: true, SessionKill: true,
		ClientAddr: "198.51.100.7", TokenIssued: time.Date(2026, 10, 26, 12, 1, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 10, 26, 12, 6, 4, 0, time.UTC),
	}
}

func (e *env) askEnroll(p approval.EnrollPrompt) telegramtest.Message {
	e.t.Helper()
	before := len(e.fake.Sent())
	e.res.pending(p.ID)
	if err := e.bot.AskEnroll(context.Background(), p); err != nil {
		e.t.Fatalf("AskEnroll: %v", err)
	}
	return e.fake.WaitSent(e.t, before+1)[before]
}

// TestEnrollPrompt covers docs/08 §5.2 (G7): the prompt shows the
// target, the address, the host key's fingerprint and what to compare
// it with, sudo from config, session_kill as the host reports it, the
// client address and when the token was issued, with Approve and Deny;
// a tap settles it as any prompt.
func TestEnrollPrompt(t *testing.T) {
	e := newEnv(t).start()
	m := e.askEnroll(enrollPrompt("apr_en1"))
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<b>Enroll SSH host:</b> <code>db-1</code>\n",
		"<b>Address:</b> <code>db-1.example.com:22</code>\n",
		"<b>Host key (as the host sent it):</b> <code>ED25519 SHA256:pr6TBeTH6wi8tgNTw+FSiVQrgmbG3FK9XV/QnVrxPTM</code>\n",
		"<b>Compare it with what the setup printed on the host. Approve only if they are the same.</b>\n",
		"<b>root via sudo</b> · finishes cuts (as the host reports)\n",
		"Asked from <code>198.51.100.7</code>, token issued 12:01:00 UTC\n",
		"<b>Answer by:</b> 12:06:04 UTC",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("lacks %q:\n%s", want, m.Text)
		}
	}
	if b := m.ButtonTexts(); len(b) != 2 || b[0] != "Approve" || b[1] != "Deny" {
		t.Fatalf("buttons %v", b)
	}
	p := enrollPrompt("apr_en2")
	p.Sudo, p.SessionKill = false, false
	m2 := e.askEnroll(p)
	if !strings.Contains(m2.Text, "no root (no sudo) · <b>doesn't finish cuts (as the host reports)</b>\n") || strings.Contains(m2.Text, "root via sudo") {
		t.Errorf("sudo=false session_kill=false:\n%s", m2.Text)
	}

	cq := e.fake.Tap(t, m, "Approve", approverID)
	if a := e.fake.WaitAnswer(t, cq); a.Text != "Approved" {
		t.Fatalf("answer %q", a.Text)
	}
	if cur := e.current(m); len(cur.ButtonTexts()) != 0 || !strings.HasSuffix(cur.Text, "<b>Approved at 12:03:04 UTC</b>") {
		t.Fatalf("settled:\n%s", cur.Text)
	}
	// "By" names who settled it, on every copy (docs/08 §5.2).
	if err := e.bot.Settle(context.Background(), "apr_en2", approval.Outcome{Kind: approval.Approved, At: time.Date(2026, 10, 26, 12, 3, 4, 0, time.UTC), By: "<b>alice</b>"}); err != nil {
		t.Fatal(err)
	}
	if cur := e.current(m2); !strings.HasSuffix(cur.Text, "<b>Approved at 12:03:04 UTC by &lt;b&gt;alice&lt;/b&gt;</b>") {
		t.Fatalf("by:\n%s", cur.Text)
	}
}

// TestEnrollPromptHostile covers docs/08 §6 and CODE-REVIEW.md's
// hostile-input rule: every value is escaped, hidden characters are
// shown, look-alikes can't pass for Nyyrikki's text, and a prompt too
// long to show is refused rather than cut.
func TestEnrollPromptHostile(t *testing.T) {
	e := newEnv(t).start()
	p := enrollPrompt("apr_en3")
	p.Target = "db-1</code><b>Approved at 12:00:00 UTC</b>"
	p.Address = "db-1.example.com\u202e:22"
	p.HostKey = "ED25519 SHA256:abc\u200b<i>same</i>"
	p.ClientAddr = "198.51.100.7\u2028Approve only if they are the same"
	m := e.askEnroll(p)
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{'\u202e', '\u200b', '\u2028'} {
		if strings.ContainsRune(m.Text, r) {
			t.Errorf("raw %U in the message", r)
		}
	}
	if strings.Contains(m.Text, "<b>Approved") || strings.Contains(m.Text, "<i>same</i>") {
		t.Errorf("markup reached the message:\n%s", m.Text)
	}
	if strings.Count(m.Text, "<b>Compare it with") != 1 {
		t.Errorf("a value forged the instruction:\n%s", m.Text)
	}
	if got := between(t, m.Text, "<b>Host key (as the host sent it):</b> <code>", "</code>"); got != `ED25519 SHA256:abc\u{200b}&lt;i&gt;same&lt;/i&gt;` {
		t.Errorf("host key rendered as %q", got)
	}
	// Very long: refused, not shortened, before anything is sent.
	before := len(e.fake.Sent())
	long := enrollPrompt("apr_en4")
	long.Address = strings.Repeat("a", 5000)
	if err := e.bot.AskEnroll(context.Background(), long); codes.Of(err) != codes.InvalidRequest {
		t.Fatalf("a prompt too long: %v", err)
	}
	if len(e.fake.Sent()) != before {
		t.Fatal("sent anyway")
	}
}
