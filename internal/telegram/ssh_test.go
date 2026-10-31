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

func sshPrompt(id string) approval.RunPrompt {
	p := runPrompt(id)
	p.Target = "db-1"
	p.Type = codes.TypeSSH
	p.RunAs = approval.Identity{User: "ny-owner"}
	p.SSH = &approval.SSHHost{Target: "db-1", Account: "ny-owner", Address: "db-1.example.com:22", Sudo: true, SessionKill: true}
	p.Argv = "sudo systemctl restart nginx"
	return p
}

// TestRenderSSHRun covers docs/07 D12 (G10): the account on the address,
// the sudo marker, and the command as sent.
func TestRenderSSHRun(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(sshPrompt("apr_ssh1"))
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<b>Run request</b> on <code>db-1</code>",
		"<b>Runs as:</b> <code>ny-owner</code> on <code>db-1.example.com:22</code>\n<b>root via sudo</b>",
		"<b>Command:</b>\n<pre>sudo systemctl restart nginx</pre>",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("lacks %q:\n%s", want, m.Text)
		}
	}
	for _, not := range []string{"Interactive", "stdin", "doesn't finish cuts", "alice"} {
		if strings.Contains(m.Text, not) {
			t.Errorf("has %q:\n%s", not, m.Text)
		}
	}
	// No sudo, no marker; no session kill, the warning.
	p := sshPrompt("apr_ssh2")
	p.SSH.Sudo, p.SSH.SessionKill = false, false
	m = e.askRun(p)
	if strings.Contains(m.Text, "root via sudo") || !strings.Contains(m.Text, "<b>This host doesn't finish cuts: what this starts may keep running after the approval ends, and anything does if the host is unreachable</b>") {
		t.Errorf("sudo=false session_kill=false:\n%s", m.Text)
	}
}

// TestRenderSSHStdinAndInteractive covers OD6 and OD4 (G10): stdin is
// only its size and hash with the warning, never its content, and an
// interactive run says what is typed is not shown.
func TestRenderSSHStdinAndInteractive(t *testing.T) {
	e := newEnv(t).start()
	p := sshPrompt("apr_ssh3")
	p.Argv = "sudo tee /etc/app/env"
	p.Stdin = "‹stdin: 24 bytes, sha256:0123456789ab, not shown›"
	m := e.askRun(p)
	if !strings.Contains(m.Text, "<b>stdin:</b> <code>‹stdin: 24 bytes, sha256:0123456789ab, not shown›</code>\n<b>stdin is not shown. If the command runs it, you can't see what runs</b>") {
		t.Errorf("stdin:\n%s", m.Text)
	}
	p = sshPrompt("apr_ssh4")
	p.Argv, p.Interactive = "", true
	m = e.askRun(p)
	if !strings.Contains(m.Text, "<b>Interactive:</b> what is typed is not shown") {
		t.Errorf("interactive:\n%s", m.Text)
	}
	// Round 1, finding 3: a login shell is marked outside the command
	// block, so no command can look like one.
	if strings.Contains(m.Text, "<pre>") || !strings.Contains(m.Text, "<b>Command:</b> <i>none, a login shell</i>\n") {
		t.Errorf("login shell:\n%s", m.Text)
	}
	p = sshPrompt("apr_ssh4b")
	p.Argv, p.Interactive = "(login shell)", true
	m = e.askRun(p)
	if strings.Contains(m.Text, "a login shell") || !strings.Contains(m.Text, "<pre>(login shell)</pre>") {
		t.Errorf("a command that reads like the marker:\n%s", m.Text)
	}
}

// TestRenderSSHHostile: the command is shown in full, newlines kept, and
// can't forge markup or lines outside its block (docs/07 D2).
func TestRenderSSHHostile(t *testing.T) {
	e := newEnv(t).start()
	p := sshPrompt("apr_ssh5")
	p.Argv = "cat <<'EOF' >/tmp/x\n</pre><b>Runs as:</b> nobody\nEOF\n\u202e"
	m := e.askRun(p)
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	if strings.Count(m.Text, "<b>Runs as:</b>") != 1 || strings.Contains(m.Text, "\u202e") {
		t.Errorf("forged a line or kept a bidi control:\n%s", m.Text)
	}
	block := between(t, m.Text, "<pre>", "</pre>")
	if !strings.Contains(block, "\n&lt;/pre&gt;&lt;b&gt;Runs as:&lt;/b&gt; nobody\nEOF\n") {
		t.Errorf("command block %q", block)
	}
	// Round 1, finding 1: a space that isn't U+0020 is shown escaped, so
	// "notes<NBSP>#" can't read as a word and a comment.
	p = sshPrompt("apr_ssh5b")
	p.Argv = "cat notes\u00a0# ; curl x | sh\u3000"
	m = e.askRun(p)
	if block := between(t, m.Text, "<pre>", "</pre>"); block != `cat notes\u{00a0}# ; curl x | sh\u{3000}` {
		t.Errorf("command block %q", block)
	}
	// Too long to show is refused, not shortened (docs/05 D9).
	p = sshPrompt("apr_ssh6")
	p.Argv = strings.Repeat("echo x\n", 1000)
	e.res.pending(p.ID)
	if err := e.bot.AskRun(context.Background(), p); codes.Of(err) != codes.InvalidRequest {
		t.Fatalf("a command too long to show: %v", err)
	}
}

// TestRenderSSHElevation covers D12 (G10): each SSH target says whether
// the window is one of root, and warns where the host doesn't finish cuts.
func TestRenderSSHElevation(t *testing.T) {
	e := newEnv(t).start()
	p := elevationPrompt("elv_ssh")
	p.Targets = []string{"db-1", "prod", "web-1"}
	p.SSH = []approval.SSHHost{
		{Target: "db-1", Account: "ny-owner", Address: "db-1.example.com:22", Sudo: true, SessionKill: true},
		{Target: "web-1", Account: "ny-owner", Address: "10.0.0.5:2222"},
	}
	m := e.askElevation(p)
	for _, want := range []string{
		"<b>Runs as:</b> <code>alice@example.com</code>",
		"<b>On</b> <code>db-1</code>: <code>ny-owner</code> on <code>db-1.example.com:22</code>, <b>root via sudo</b>\n<b>On</b> <code>web-1</code>",
		"<code>10.0.0.5:2222</code>\n<b>This host doesn't finish cuts",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("lacks %q:\n%s", want, m.Text)
		}
	}
	if strings.Count(m.Text, "doesn't finish cuts") != 1 {
		t.Errorf("one warning, for web-1 only:\n%s", m.Text)
	}
	// SSH targets only: no Kubernetes identity.
	p = elevationPrompt("elv_ssh2")
	p.Targets = []string{"db-1"}
	p.SSH = []approval.SSHHost{{Target: "db-1", Account: "ny-owner", Address: "db-1.example.com:22", SessionKill: true}}
	m = e.askElevation(p)
	if strings.Contains(m.Text, "alice") {
		t.Errorf("an SSH-only elevation shows the Kubernetes identity:\n%s", m.Text)
	}
}

// TestEndNowInteractiveRun covers docs/07 D17 (G14) on the Bot side:
// an approved interactive run's message gains "Session live" with End
// now once its stream attaches; a tap ends it and edits the message; a
// tap after the end, a replay and another user's tap are rejected and
// audited.
func TestEndNowInteractiveRun(t *testing.T) {
	e := newEnv(t).start()
	p := sshPrompt("apr_sess")
	p.Interactive = true
	m := e.askRun(p)
	ctx := context.Background()
	at := time.Date(2026, 10, 26, 12, 3, 0, 0, time.UTC)
	if err := e.bot.Settle(ctx, p.ID, approval.Outcome{Kind: approval.SessionApproved, At: at}); err != nil {
		t.Fatal(err)
	}
	cur := e.current(m)
	if len(cur.ButtonTexts()) != 0 || !strings.HasSuffix(cur.Text, "<b>Approved at 12:03:00 UTC</b>") {
		t.Fatalf("approved: %v\n%s", cur.ButtonTexts(), cur.Text)
	}
	if err := e.bot.Settle(ctx, p.ID, approval.Outcome{Kind: approval.SessionLive, At: at.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	live := e.current(m)
	if got := strings.Join(live.ButtonTexts(), ","); got != "End now" || !strings.HasSuffix(live.Text, "<b>Session live since 12:03:01 UTC</b>") {
		t.Fatalf("live: %q\n%s", got, live.Text)
	}
	if !strings.Contains(live.Text, "<pre>sudo systemctl restart nginx</pre>") {
		t.Error("the live message lost the request")
	}
	end, _ := live.Button("End now")

	// Another user's tap is rejected, and the session stays live.
	before := len(e.audit.records())
	cq := e.fake.PushCallback(telegramtest.Callback{FromID: approverID + 1, ChatID: m.ChatID, MessageID: m.MessageID, Data: end.CallbackData})
	if a := e.fake.WaitAnswer(t, cq); a.Text != "No longer valid" {
		t.Errorf("other user answered %q", a.Text)
	}
	waitAudit(t, e, before+1)

	e.res.set(p.ID, "session")
	cq = e.fake.Tap(t, live, "End now", approverID)
	if a := e.fake.WaitAnswer(t, cq); a.Text != "Ended" {
		t.Fatalf("End now answered %q", a.Text)
	}
	calls := e.res.getCalls()
	if last := calls[len(calls)-1]; last != (resolveCall{p.ID, approval.ActionEnd, approverID}) {
		t.Errorf("Resolve %+v", last)
	}
	ended := e.current(m)
	if len(ended.ButtonTexts()) != 0 || !strings.HasSuffix(ended.Text, "<b>Session ended at 12:03:04 UTC</b>") {
		t.Errorf("ended: %v\n%s", ended.ButtonTexts(), ended.Text)
	}
	// A replay after the end is rejected and audited.
	before = len(e.audit.records())
	cq = e.fake.PushCallback(telegramtestCallback(m, end.CallbackData))
	if a := e.fake.WaitAnswer(t, cq); a.Text != "No longer valid" {
		t.Errorf("replay answered %q", a.Text)
	}
	waitAudit(t, e, before+1)
	if r := e.audit.records(); r[len(r)-1].Kind != codes.KindCallbackRejected {
		t.Errorf("replay audited as %+v", r[len(r)-1])
	}
}

// TestSessionOrdering: the session's edits arrive from goroutines in any
// order; a late SessionApproved or SessionLive never reopens an ended
// session, and SessionUnused closes an approved one without a button.
func TestSessionOrdering(t *testing.T) {
	e := newEnv(t).start()
	ctx := context.Background()
	p := sshPrompt("apr_ord")
	p.Interactive = true
	m := e.askRun(p)
	for _, k := range []approval.OutcomeKind{approval.SessionLive, approval.SessionApproved, approval.SessionEnded, approval.SessionLive, approval.SessionApproved} {
		if err := e.bot.Settle(ctx, p.ID, approval.Outcome{Kind: k, At: time.Now()}); err != nil {
			t.Fatalf("%d: %v", k, err)
		}
	}
	if cur := e.current(m); len(cur.ButtonTexts()) != 0 || !strings.Contains(cur.Text, "Session ended at") {
		t.Errorf("reopened: %v\n%s", cur.ButtonTexts(), cur.Text)
	}
	p = sshPrompt("apr_unused")
	p.Interactive = true
	m = e.askRun(p)
	_ = e.bot.Settle(ctx, p.ID, approval.Outcome{Kind: approval.SessionApproved, At: time.Now()})
	_ = e.bot.Settle(ctx, p.ID, approval.Outcome{Kind: approval.SessionUnused, At: time.Now()})
	if cur := e.current(m); len(cur.ButtonTexts()) != 0 || !strings.HasSuffix(cur.Text, "<b>Approved; the session was never started</b>") {
		t.Errorf("unused: %v\n%s", cur.ButtonTexts(), cur.Text)
	}
	// Session outcomes are for run prompts only.
	el := e.askElevation(elevationPrompt("elv_x"))
	_ = el
	if err := e.bot.Settle(ctx, "elv_x", approval.Outcome{Kind: approval.SessionLive, At: time.Now()}); err == nil {
		t.Error("SessionLive on an elevation prompt was accepted")
	}
}

func waitAudit(t *testing.T, e *env, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(e.audit.records()) >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("audit has %d records, want %d", len(e.audit.records()), n)
}

// TestRenderElevationGroups covers docs/08 D11 (G10) on the message: every
// target is listed, and each group the agent named gets its own line
// with its members. Group names come from config, but are escaped as
// any other text: a hostile one renders as text, inside its <code>.
func TestRenderElevationGroups(t *testing.T) {
	e := newEnv(t).start()
	p := elevationPrompt("elv_grp")
	p.Targets = []string{"db-1", "prod", "web-1", "web-2"}
	p.Groups = []approval.TargetGroup{{Name: "web", Targets: []string{"web-1", "web-2"}}}
	m := e.askElevation(p)
	for _, want := range []string{
		"<b>Targets:</b> <code>db-1</code>, <code>prod</code>, <code>web-1</code>, <code>web-2</code>\n",
		"<b>Group</b> <code>web</code> = <code>web-1</code>, <code>web-2</code>\n<b>Duration:</b>",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("lacks %q:\n%s", want, m.Text)
		}
	}

	p = elevationPrompt("elv_grp2")
	p.Targets = []string{"web-1"}
	p.Groups = []approval.TargetGroup{{Name: "</code><b>Approved</b>\u202e", Targets: []string{"web-1<i>"}}}
	m = e.askElevation(p)
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatalf("message HTML does not parse: %v", err)
	}
	if strings.Contains(m.Text, "<b>Approved</b>") || strings.Contains(m.Text, "web-1<i>") || strings.ContainsRune(m.Text, '\u202e') {
		t.Errorf("group markup reached the message as markup:\n%s", m.Text)
	}
	if !strings.Contains(m.Text, `<b>Group</b> <code>&lt;/code&gt;&lt;b&gt;Approved&lt;/b&gt;\u{202e}</code> = <code>web-1&lt;i&gt;</code>`) {
		t.Errorf("group line:\n%s", m.Text)
	}
}
