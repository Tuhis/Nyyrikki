package telegram_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

func telegramtestCallback(m telegramtest.Message, data string) telegramtest.Callback {
	return telegramtest.Callback{FromID: approverID, ChatID: m.ChatID, MessageID: m.MessageID, Data: data}
}

// assertRejected checks the answer, the audit record and that Resolve was
// not reached (unless resolveCalls says how many calls are expected).
func assertRejected(t *testing.T, e *env, cqID, data, wantDetail, wantPrompt string, resolveCalls int) {
	t.Helper()
	if a := e.fake.WaitAnswer(t, cqID); a.Text != "No longer valid" {
		t.Errorf("answer %q, want No longer valid", a.Text)
	}
	var found bool
	e.fake.Wait(t, "the audit record", func() bool {
		for _, r := range e.audit.records() {
			if r.Kind == codes.KindCallbackRejected && strings.HasPrefix(r.Detail, wantDetail+" ") {
				found = true
			}
		}
		return found
	})
	for _, r := range e.audit.records() {
		if r.Kind != codes.KindCallbackRejected {
			t.Errorf("unexpected audit kind %q", r.Kind)
		}
		if r.Decision != codes.Deny {
			t.Errorf("decision %q, want deny", r.Decision)
		}
		if data != "" && strings.Contains(r.Detail, data) {
			t.Errorf("audit detail contains the callback data: %q", r.Detail)
		}
		if !strings.HasPrefix(r.Detail, wantDetail+" ") {
			continue
		}
		if got := r.ApprovalID + r.ElevationID; got != wantPrompt {
			t.Errorf("audited prompt %q, want %q", got, wantPrompt)
		}
	}
	if n := len(e.res.getCalls()); n != resolveCalls {
		t.Errorf("Resolve called %d times, want %d", n, resolveCalls)
	}
	if data != "" && strings.Contains(e.logs.String(), data) {
		t.Error("logs contain the callback data")
	}
}

// G2: every way a tap can fail docs/05 D4's checks.
func TestCallbackRejected(t *testing.T) {
	const stranger int64 = 777
	for _, tc := range []struct {
		name   string
		cb     func(m telegramtest.Message, approve string) telegramtest.Callback
		detail string
		prompt string
	}{
		{"OtherUser", func(m telegramtest.Message, k string) telegramtest.Callback {
			// A stranger tapping in their own chat with the bot.
			return telegramtest.Callback{FromID: stranger, ChatID: stranger, MessageID: m.MessageID, Data: k}
		}, "wrong_user", "apr_cb"},
		{"OtherUserInApproverChat", func(m telegramtest.Message, k string) telegramtest.Callback {
			return telegramtest.Callback{FromID: stranger, ChatID: m.ChatID, MessageID: m.MessageID, Data: k}
		}, "wrong_user", "apr_cb"},
		{"OtherChat", func(m telegramtest.Message, k string) telegramtest.Callback {
			// The approver, but from a group chat the message was forwarded to.
			return telegramtest.Callback{FromID: approverID, ChatID: -100123, MessageID: m.MessageID, Data: k}
		}, "wrong_chat", "apr_cb"},
		{"OtherMessage", func(m telegramtest.Message, k string) telegramtest.Callback {
			return telegramtest.Callback{FromID: approverID, ChatID: m.ChatID, MessageID: m.MessageID + 100, Data: k}
		}, "wrong_message", "apr_cb"},
		{"UnknownData", func(m telegramtest.Message, _ string) telegramtest.Callback {
			return telegramtestCallback(m, "v1:AAAAAAAAAAAAAAAAAAAAAA")
		}, "unknown_key", ""},
		{"MalformedData", func(m telegramtest.Message, _ string) telegramtest.Callback {
			return telegramtestCallback(m, "approve:apr_cb")
		}, "malformed_data", ""},
		{"OverlongData", func(m telegramtest.Message, k string) telegramtest.Callback {
			return telegramtestCallback(m, k+"x")
		}, "malformed_data", ""},
		{"NoMessage", func(m telegramtest.Message, k string) telegramtest.Callback {
			return telegramtest.Callback{FromID: approverID, NoMessage: true, Data: k}
		}, "no_message", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t).start()
			m := e.askRun(runPrompt("apr_cb"))
			approve, _ := m.Button("Approve")
			cb := tc.cb(m, approve.CallbackData)
			cq := e.fake.PushCallback(cb)
			assertRejected(t, e, cq, approve.CallbackData, tc.detail, tc.prompt, 0)
			if got := e.current(m).ButtonTexts(); len(got) != 2 {
				t.Errorf("prompt changed after a rejected tap: %v", got)
			}
			// The genuine tap still works afterwards.
			cq = e.fake.Tap(t, m, "Approve", approverID)
			if a := e.fake.WaitAnswer(t, cq); a.Text != "Approved" {
				t.Errorf("genuine tap after a rejected one answered %q", a.Text)
			}
		})
	}
}

// G2: a tap on a prompt that was already settled (here: expired).
func TestCallbackRejectedAfterSettle(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_exp"))
	approve, _ := m.Button("Approve")
	if err := e.bot.Settle(context.Background(), "apr_exp", approval.Outcome{Kind: approval.Expired}); err != nil {
		t.Fatal(err)
	}
	cq := e.fake.PushCallback(telegramtestCallback(m, approve.CallbackData))
	assertRejected(t, e, cq, approve.CallbackData, "unknown_key", "", 0)
}

// G2: a second tap before the decision point settled the prompt reaches
// Resolve, which refuses it; the channel audits that too.
func TestCallbackRejectedSecondTap(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_twice"))
	approve, _ := m.Button("Approve")
	deny, _ := m.Button("Deny")
	e.fake.WaitAnswer(t, e.fake.Tap(t, m, "Approve", approverID))

	// Replays of both keys after the settle: unknown.
	for _, k := range []string{approve.CallbackData, deny.CallbackData} {
		cq := e.fake.PushCallback(telegramtestCallback(m, k))
		assertRejected(t, e, cq, k, "unknown_key", "", 1)
	}
}

// G2: the decision point refuses (expired, or a second tap racing the
// settle): the tap is rejected and audited with the prompt named.
func TestCallbackRejectedByResolver(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_late"))
	approve, _ := m.Button("Approve")
	e.res.mu.Lock()
	e.res.state["apr_late"] = "expired" // the decision point saw it expire
	e.res.mu.Unlock()
	cq := e.fake.Tap(t, m, "Approve", approverID)
	assertRejected(t, e, cq, approve.CallbackData, "resolver_refused", "apr_late", 1)
}

func TestCallbackResolverErrorRejected(t *testing.T) {
	e := newEnv(t).start()
	e.res.err = errors.New("database is locked")
	m := e.askRun(runPrompt("apr_err"))
	approve, _ := m.Button("Approve")
	cq := e.fake.Tap(t, m, "Approve", approverID)
	assertRejected(t, e, cq, approve.CallbackData, "resolve_failed", "apr_err", 1)
}

// docs/05 M5: a tap on a message Telegram reports as inaccessible still
// carries chat and message ID, and counts.
func TestCallbackInaccessibleMessageAccepted(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_inacc"))
	approve, _ := m.Button("Approve")
	cb := telegramtestCallback(m, approve.CallbackData)
	cb.Inaccessible = true
	if a := e.fake.WaitAnswer(t, e.fake.PushCallback(cb)); a.Text != "Approved" {
		t.Errorf("answer %q", a.Text)
	}
	if n := len(e.res.getCalls()); n != 1 {
		t.Errorf("Resolve called %d times", n)
	}
}

// An elevation prompt's ID is its approval's ID (apr_…): the elv_ ID
// exists only once it is approved. A rejected tap is audited under the
// approval (found in review of #10).
func TestCallbackRejectedElevationAuditsApprovalID(t *testing.T) {
	e := newEnv(t).start()
	m := e.askElevation(elevationPrompt("apr_cb"))
	approve, _ := m.Button("Approve")
	cq := e.fake.PushCallback(telegramtest.Callback{FromID: 999, ChatID: 999, MessageID: m.MessageID, Data: approve.CallbackData})
	assertRejected(t, e, cq, approve.CallbackData, "wrong_user", "apr_cb", 0)
	if r := e.audit.records()[0]; r.ApprovalID != "apr_cb" || r.ElevationID != "" {
		t.Errorf("record %+v", r)
	}
}

// /start gets the sender's user ID; nothing else gets an answer, and no
// message changes state.
func TestTextMessages(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(runPrompt("apr_txt"))
	e.fake.PushMessage(telegramtest.TextMessage{FromID: approverID, ChatID: approverID, Text: "/approve apr_txt"})
	e.fake.PushMessage(telegramtest.TextMessage{FromID: approverID, ChatID: approverID, Text: "yes"})
	e.fake.PushMessage(telegramtest.TextMessage{FromID: 55, ChatID: -100, ChatType: "group", Text: "/start"})
	e.fake.PushMessage(telegramtest.TextMessage{FromID: 31337, ChatID: 31337, Text: "/start"})

	sent := e.fake.WaitSent(t, 2)
	reply := sent[1]
	if reply.ChatID != 31337 || !strings.Contains(reply.Text, "<code>31337</code>") {
		t.Errorf("/start reply %+v", reply)
	}
	if len(reply.Buttons) != 0 {
		t.Error("/start reply has buttons")
	}
	// Let the poller drain the rest, then check nothing else happened.
	e.fake.Wait(t, "all updates confirmed", func() bool { return e.fake.LastOffset() > 1004 })
	if n := len(e.fake.Sent()); n != 2 {
		t.Errorf("%d messages sent, want the prompt and one /start reply", n)
	}
	if n := len(e.res.getCalls()); n != 0 {
		t.Errorf("a text message reached Resolve %d times", n)
	}
	if got := e.current(m).ButtonTexts(); len(got) != 2 {
		t.Errorf("prompt changed: %v", got)
	}
}
