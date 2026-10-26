package telegram_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// docs/05 D5: HTML, protected, no link previews, Approve and Deny, to the
// approver's private chat.
func TestPromptFormat(t *testing.T) {
	e := newEnv(t).start()
	p := runPrompt("apr_format")
	p.Stdin = "apiVersion: v1\nkind: Pod\n"
	p.Interactive = true
	m := e.askRun(p)

	if m.ChatID != approverID {
		t.Errorf("sent to chat %d, want the approver %d", m.ChatID, approverID)
	}
	if m.ParseMode != "HTML" || !m.ProtectContent || !m.LinkPreviewDisabled {
		t.Errorf("parse_mode=%q protect_content=%v previews disabled=%v", m.ParseMode, m.ProtectContent, m.LinkPreviewDisabled)
	}
	if got := strings.Join(m.ButtonTexts(), ","); got != "Approve,Deny" {
		t.Errorf("buttons %q", got)
	}
	a, _ := m.Button("Approve")
	d, _ := m.Button("Deny")
	if a.CallbackData == d.CallbackData {
		t.Error("Approve and Deny share callback data")
	}
	for _, want := range []string{
		"<b>Run request</b> on <code>prod</code>",
		"<b>Runs as:</b> <code>alice@example.com</code>, groups <code>oncall</code>, <code>system:authenticated</code>",
		"<code>Claude Code</code> <i>(name claimed by the client)</i>",
		"key <code>ab12cd34</code>, signed in 2026-10-26 11:00:00 UTC",
		"<pre>kubectl delete pod web-0 --namespace=shop</pre>",
		"<b>stdin:</b>\n<pre>apiVersion: v1\nkind: Pod\n</pre>",
		"<b>Interactive:</b> yes",
		"<b>Agent's claim (unverified):</b>\n<blockquote>web-0 is stuck in CrashLoopBackOff</blockquote>",
		"<b>Answer by:</b> 12:05:00 UTC",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("prompt lacks %q:\n%s", want, m.Text)
		}
	}
}

// G1: an approval settles the prompt and edits it.
func TestApproveSettlesAndEdits(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_1"))

	cq := e.fake.Tap(t, m, "Approve", approverID)
	if a := e.fake.WaitAnswer(t, cq); a.Text != "Approved" {
		t.Errorf("answer %q, want Approved", a.Text)
	}
	calls := e.res.getCalls()
	if len(calls) != 1 || calls[0] != (resolveCall{"apr_1", approval.ActionApprove, approverID}) {
		t.Fatalf("Resolve calls %+v", calls)
	}
	cur := e.current(m)
	if len(cur.ButtonTexts()) != 0 {
		t.Errorf("buttons left after approval: %v", cur.ButtonTexts())
	}
	if !strings.HasSuffix(cur.Text, "\n\n<b>Approved at 12:03:04 UTC</b>") {
		t.Errorf("edited text lacks the status line:\n%s", cur.Text)
	}
	if !strings.HasPrefix(cur.Text, m.Text) {
		t.Error("the edit changed the prompt's body")
	}
	if len(e.audit.records()) != 0 {
		t.Errorf("accepted tap audited as rejected: %+v", e.audit.records())
	}
}

// G1: a denial settles the prompt and edits it.
func TestDenySettlesAndEdits(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_2"))

	cq := e.fake.Tap(t, m, "Deny", approverID)
	if a := e.fake.WaitAnswer(t, cq); a.Text != "Denied" {
		t.Errorf("answer %q, want Denied", a.Text)
	}
	if calls := e.res.getCalls(); len(calls) != 1 || calls[0].Action != approval.ActionDeny {
		t.Fatalf("Resolve calls %+v", calls)
	}
	cur := e.current(m)
	if len(cur.ButtonTexts()) != 0 || !strings.HasSuffix(cur.Text, "<b>Denied at 12:03:04 UTC</b>") {
		t.Errorf("not settled as denied: buttons %v\n%s", cur.ButtonTexts(), cur.Text)
	}
}

// G1: expiry (and the other outcomes the decision point reports) edit the
// prompt; Settle is idempotent.
func TestSettleOutcomesEdit(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    approval.Outcome
		want string
	}{
		{"expired", approval.Outcome{Kind: approval.Expired}, "<b>Expired: denied</b>"},
		{"withdrawn", approval.Outcome{Kind: approval.Withdrawn}, "<b>Withdrawn by the agent</b>"},
		{"failed", approval.Outcome{Kind: approval.Failed}, "<b>Failed: not completed</b>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t).start()
			m := e.askRun(runPrompt("apr_" + tc.name))
			if err := e.bot.Settle(context.Background(), "apr_"+tc.name, tc.o); err != nil {
				t.Fatal(err)
			}
			cur := e.current(m)
			if len(cur.ButtonTexts()) != 0 || !strings.HasSuffix(cur.Text, tc.want) {
				t.Errorf("buttons %v, text:\n%s", cur.ButtonTexts(), cur.Text)
			}
			edits := len(e.fake.Edits())
			// Idempotent: a second Settle, of any outcome, changes nothing.
			for _, again := range []approval.Outcome{tc.o, {Kind: approval.Approved, At: time.Now()}} {
				if err := e.bot.Settle(context.Background(), "apr_"+tc.name, again); err != nil {
					t.Fatalf("second Settle: %v", err)
				}
			}
			if got := len(e.fake.Edits()); got != edits {
				t.Errorf("second Settle edited again (%d edits, want %d)", got, edits)
			}
		})
	}
}

func TestSettleUnknownPromptIsNoop(t *testing.T) {
	e := newEnv(t).start()
	if err := e.bot.Settle(context.Background(), "apr_never_sent", approval.Outcome{Kind: approval.Expired}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.fake.Edits()); n != 0 {
		t.Errorf("%d edits for a prompt never sent", n)
	}
}

func TestSettleUnknownOutcomeKind(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_kind"))
	err := e.bot.Settle(context.Background(), "apr_kind", approval.Outcome{Kind: 99})
	if err == nil || codes.Of(err) != codes.Internal {
		t.Fatalf("Settle with an unknown kind: %v", err)
	}
	if got := e.current(m).ButtonTexts(); len(got) != 2 {
		t.Errorf("prompt changed on an unknown outcome: %v", got)
	}
}

// G5 (the channel's half): approving an elevation shows "Live until" with
// End now; End now calls Resolve with ActionEnd, and the prompt then shows
// "Ended at" without buttons. Cutting the runs is the decision point's job
// (docs/02 D8), triggered by that Resolve.
func TestEndNow(t *testing.T) {
	e := newEnv(t).start()
	m := e.askElevation(elevationPrompt("elv_1"))
	for _, want := range []string{
		"<b>Elevation request</b>",
		"<b>Targets:</b> <code>prod</code>, <code>staging</code>",
		"<b>Duration:</b> 15 min",
		"<b>Agent's claim (unverified):</b>\n<blockquote>debugging the checkout outage</blockquote>",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("elevation prompt lacks %q:\n%s", want, m.Text)
		}
	}
	approveBtn, _ := m.Button("Approve")

	cq := e.fake.Tap(t, m, "Approve", approverID)
	e.fake.WaitAnswer(t, cq)
	live := e.current(m)
	if got := strings.Join(live.ButtonTexts(), ","); got != "End now" {
		t.Fatalf("live elevation buttons %q, want End now", got)
	}
	if !strings.HasSuffix(live.Text, "<b>Live until 12:18:04 UTC</b>") {
		t.Errorf("live text:\n%s", live.Text)
	}
	end, _ := live.Button("End now")
	if end.CallbackData == approveBtn.CallbackData {
		t.Error("End now reuses the Approve key")
	}
	// Settling live again is a no-op.
	edits := len(e.fake.Edits())
	if err := e.bot.Settle(context.Background(), "elv_1", approval.Outcome{Kind: approval.ElevationLive, Until: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if len(e.fake.Edits()) != edits {
		t.Error("a repeated ElevationLive edited the prompt")
	}

	// A tap on the old Approve button no longer counts.
	old := e.fake.PushCallback(telegramtestCallback(m, approveBtn.CallbackData))
	if a := e.fake.WaitAnswer(t, old); a.Text != "No longer valid" {
		t.Errorf("old Approve answered %q", a.Text)
	}

	cq = e.fake.Tap(t, live, "End now", approverID)
	if a := e.fake.WaitAnswer(t, cq); a.Text != "Ended" {
		t.Errorf("End now answered %q", a.Text)
	}
	calls := e.res.getCalls()
	if last := calls[len(calls)-1]; last != (resolveCall{"elv_1", approval.ActionEnd, approverID}) {
		t.Errorf("last Resolve %+v, want ActionEnd", last)
	}
	ended := e.current(m)
	if len(ended.ButtonTexts()) != 0 || !strings.HasSuffix(ended.Text, "<b>Ended at 12:03:04 UTC</b>") {
		t.Errorf("ended: buttons %v\n%s", ended.ButtonTexts(), ended.Text)
	}
	if strings.Contains(ended.Text, "Live until") {
		t.Error("ended prompt still says Live until")
	}

	// A second End now tap is rejected.
	cq = e.fake.PushCallback(telegramtestCallback(m, end.CallbackData))
	if a := e.fake.WaitAnswer(t, cq); a.Text != "No longer valid" {
		t.Errorf("second End now answered %q", a.Text)
	}
}

func TestElevationExpiresWhileLive(t *testing.T) {
	e := newEnv(t).start()
	m := e.askElevation(elevationPrompt("elv_2"))
	e.fake.WaitAnswer(t, e.fake.Tap(t, m, "Approve", approverID))
	at := time.Date(2026, 10, 26, 12, 18, 4, 0, time.UTC)
	if err := e.bot.Settle(context.Background(), "elv_2", approval.Outcome{Kind: approval.ElevationExpired, At: at}); err != nil {
		t.Fatal(err)
	}
	cur := e.current(m)
	if len(cur.ButtonTexts()) != 0 || !strings.HasSuffix(cur.Text, "<b>Expired at 12:18:04 UTC</b>") {
		t.Errorf("buttons %v\n%s", cur.ButtonTexts(), cur.Text)
	}
	// An outcome that can't follow a live elevation is refused.
	m2 := e.askElevation(elevationPrompt("elv_3"))
	e.fake.WaitAnswer(t, e.fake.Tap(t, m2, "Approve", approverID))
	if err := e.bot.Settle(context.Background(), "elv_3", approval.Outcome{Kind: approval.Approved}); codes.Of(err) != codes.Internal {
		t.Errorf("Approved after live: %v", err)
	}
}

func TestElevationLiveForRunRefused(t *testing.T) {
	e := newEnv(t).start()
	e.askRun(runPrompt("apr_x"))
	err := e.bot.Settle(context.Background(), "apr_x", approval.Outcome{Kind: approval.ElevationLive, Until: time.Now()})
	if codes.Of(err) != codes.Internal {
		t.Errorf("ElevationLive on a run prompt: %v", err)
	}
}

func TestDuplicatePromptIDRefused(t *testing.T) {
	e := newEnv(t).start()
	e.askRun(runPrompt("apr_dup"))
	err := e.bot.AskRun(context.Background(), runPrompt("apr_dup"))
	if err == nil {
		t.Fatal("second AskRun with the same ID succeeded")
	}
	if n := len(e.fake.Sent()); n != 1 {
		t.Errorf("%d messages sent, want 1", n)
	}
}
