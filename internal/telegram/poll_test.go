package telegram_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/telegram"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

// G4: a failed send denies (docs/05 D3) and leaves nothing behind.
func TestSendFailureDenies(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadRequest, http.StatusTooManyRequests, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := newEnv(t).start()
			e.fake.FailNext("sendMessage", status)
			err := e.bot.AskRun(context.Background(), runPrompt("apr_fail"))
			if err == nil || codes.Of(err) != codes.Unavailable {
				t.Fatalf("AskRun after a failed send: %v, want unavailable", err)
			}
			// Nothing stored: Settle has nothing to edit, and a retry with the
			// same ID is a fresh prompt.
			if err := e.bot.Settle(context.Background(), "apr_fail", approval.Outcome{Kind: approval.Denied}); err != nil {
				t.Fatal(err)
			}
			if n := len(e.fake.Edits()); n != 0 {
				t.Errorf("%d edits", n)
			}
			e.askRun(runPrompt("apr_fail"))
		})
	}
}

// G4: a send that can't reach the API at all denies too.
func TestSendUnreachableDenies(t *testing.T) {
	e := newEnv(t).start()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	cfg := e.cfg
	cfg.APIURL = deadURL
	b, err := telegram.New(cfg, e.db, e.audit)
	if err != nil {
		t.Fatal(err)
	}
	// Not healthy before Run: refused without trying.
	if err := b.AskRun(context.Background(), runPrompt("apr_dead")); codes.Of(err) != codes.Unavailable {
		t.Fatalf("AskRun on a bot that is not running: %v", err)
	}
}

// G4: 409 and 401 from getUpdates stop polling for good; the channel is
// unhealthy and every new prompt is denied without being sent.
func TestConflictStopsPolling(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := newEnv(t).start()
			e.fake.FailNext("getUpdates", status)
			// Wake the long poll so the failure is served now.
			e.fake.PushMessage(telegramtest.TextMessage{FromID: 1, ChatID: 1, Text: "hi"})
			err := e.runErr()
			if !errors.Is(err, telegram.ErrStopped) {
				t.Fatalf("Run returned %v, want ErrStopped", err)
			}
			if e.bot.Healthy() {
				t.Error("healthy after a stop")
			}
			calls := e.fake.Calls("getUpdates")
			sends := e.fake.Calls("sendMessage")
			if err := e.bot.AskRun(context.Background(), runPrompt("apr_after")); codes.Of(err) != codes.Unavailable {
				t.Errorf("AskRun after a stop: %v, want unavailable", err)
			}
			if err := e.bot.AskElevation(context.Background(), elevationPrompt("elv_after")); codes.Of(err) != codes.Unavailable {
				t.Errorf("AskElevation after a stop: %v, want unavailable", err)
			}
			time.Sleep(50 * time.Millisecond)
			if got := e.fake.Calls("getUpdates"); got != calls {
				t.Errorf("getUpdates called again after a stop (%d → %d)", calls, got)
			}
			if got := e.fake.Calls("sendMessage"); got != sends {
				t.Error("a prompt was sent after a stop")
			}
			if !strings.Contains(e.logs.String(), "polling stopped") {
				t.Error("the stop was not logged")
			}
		})
	}
}

// A 401 from deleteWebhook at startup stops the bot before it polls.
func TestUnauthorizedAtStartup(t *testing.T) {
	e := newEnv(t)
	e.fake.SetToken("999:other")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.bot.Run(ctx); !errors.Is(err, telegram.ErrStopped) {
		t.Fatalf("Run: %v", err)
	}
	if e.bot.Healthy() || e.fake.Calls("getUpdates") != 0 {
		t.Error("polled after a 401 at startup")
	}
}

// Other errors back off and polling resumes; taps still arrive.
func TestTransientErrorsBackOff(t *testing.T) {
	e := newEnv(t)
	e.fake.FailNext("deleteWebhook", http.StatusBadGateway)
	e.start()
	m := e.askRun(runPrompt("apr_retry"))
	for i := 0; i < 3; i++ {
		e.fake.FailNext("getUpdates", http.StatusInternalServerError)
	}
	cq := e.fake.Tap(t, m, "Approve", approverID)
	if a := e.fake.WaitAnswer(t, cq); a.Text != "Approved" {
		t.Errorf("answer %q", a.Text)
	}
	if !e.bot.Healthy() {
		t.Error("unhealthy after transient errors")
	}
	if got := e.fake.Calls("deleteWebhook"); got != 2 {
		t.Errorf("deleteWebhook called %d times, want a retry", got)
	}
}

// docs/05 D2: deleteWebhook keeps pending updates, getUpdates asks only for
// messages and callbacks, and the offset survives a restart.
func TestPollingContract(t *testing.T) {
	db := openDB(t)
	e := newEnv(t, withDB(db)).start()
	for _, drop := range e.fake.DeleteWebhookCalls() {
		if drop {
			t.Error("deleteWebhook dropped pending updates")
		}
	}
	e.fake.PushMessage(telegramtest.TextMessage{FromID: 1, ChatID: 1, Text: "a"})
	e.fake.PushMessage(telegramtest.TextMessage{FromID: 1, ChatID: 1, Text: "b"})
	e.fake.Wait(t, "offset past both updates", func() bool { return e.fake.LastOffset() == 1003 })
	// Read only once it has polled: Healthy turns true just before the
	// first getUpdates.
	if got := strings.Join(e.fake.AllowedUpdates(), ","); got != "message,callback_query" {
		t.Errorf("allowed_updates %q", got)
	}
	if err := e.stop(); !errors.Is(err, context.Canceled) {
		t.Errorf("Run after cancel: %v", err)
	}
	if e.bot.Healthy() {
		t.Error("healthy after Run returned")
	}

	// A new bot on the same database starts from the stored offset.
	// Healthy turns true just before the first getUpdates, so the offset
	// is waited for, not read. With no updates pending, a bot that ignored
	// the stored offset would keep polling from 0 and never get there.
	e2 := newEnv(t, withDB(db)).start()
	e2.fake.Wait(t, "a restarted bot polling from the stored offset 1003", func() bool { return e2.fake.LastOffset() == 1003 })
}

func TestRunRequiresResolver(t *testing.T) {
	e := newEnv(t)
	e.bot.SetResolver(nil)
	if err := e.bot.Run(context.Background()); err == nil {
		t.Fatal("Run without a resolver started")
	}
	if e.bot.Healthy() {
		t.Error("healthy without a resolver")
	}
}

func TestNotHealthyBeforeRun(t *testing.T) {
	e := newEnv(t)
	if e.bot.Healthy() {
		t.Fatal("healthy before Run")
	}
	if err := e.bot.AskRun(context.Background(), runPrompt("apr_early")); codes.Of(err) != codes.Unavailable {
		t.Errorf("AskRun before Run: %v", err)
	}
	if n := e.fake.Calls("sendMessage"); n != 0 {
		t.Errorf("sent %d before Run", n)
	}
}

// docs/05 D10: the token is read on every call, so rotation needs no restart.
func TestTokenRotation(t *testing.T) {
	e := newEnv(t).start()
	e.askRun(runPrompt("apr_rot1"))
	const rotated = "987654:RotatedToken_abc-DEF"
	e.fake.SetToken(rotated)
	if err := os.WriteFile(e.cfg.TokenFile, []byte(rotated), 0o600); err != nil {
		t.Fatal(err)
	}
	e.askRun(runPrompt("apr_rot2"))
}

func TestBadTokenFile(t *testing.T) {
	e := newEnv(t)
	for name, content := range map[string]string{
		"empty":     "  \n",
		"slash":     "123:abc/../../evil",
		"query":     "123:abc?x=1",
		"space":     "123 abc",
		"too long":  strings.Repeat("a", 300),
		"multiline": "123:abc\n456:def",
	} {
		t.Run(name, func(t *testing.T) {
			p := t.TempDir() + "/tok"
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := e.cfg
			cfg.TokenFile = p
			_, err := telegram.New(cfg, e.db, e.audit)
			if err == nil {
				t.Fatal("New accepted the token file")
			}
			if strings.TrimSpace(content) != "" && strings.Contains(err.Error(), strings.TrimSpace(content)) {
				t.Error("the error shows the file's contents")
			}
		})
	}
	cfg := e.cfg
	cfg.TokenFile = t.TempDir() + "/missing"
	if _, err := telegram.New(cfg, e.db, e.audit); err == nil {
		t.Error("New accepted a missing token file")
	}
}

func TestBadAPIURL(t *testing.T) {
	e := newEnv(t)
	for _, u := range []string{"ftp://x", "http://", "https://u:p@api.telegram.org", "https://api.telegram.org/?a=b", "::"} {
		cfg := e.cfg
		cfg.APIURL = u
		if _, err := telegram.New(cfg, e.db, e.audit); err == nil {
			t.Errorf("New accepted api_url %q", u)
		}
	}
}

// docs/05 D11: messages to one chat are spaced at least SendInterval apart.
func TestSendRateLimit(t *testing.T) {
	const gap = 60 * time.Millisecond
	e := newEnv(t, withConfig(func(c *telegram.Config) { c.SendInterval = gap })).start()
	start := time.Now()
	e.askRun(runPrompt("apr_r1"))
	e.askRun(runPrompt("apr_r2"))
	e.askRun(runPrompt("apr_r3"))
	if el := time.Since(start); el < 2*gap {
		t.Errorf("three sends took %v, want at least %v", el, 2*gap)
	}
}

// G7: the token never reaches the logs or an error, whatever fails.
func TestTokenNotLogged(t *testing.T) {
	e := newEnv(t).start()
	tok := e.fake.Token()
	var errs []error

	// API errors on send and edit, and a rejected callback.
	e.fake.FailNext("sendMessage", http.StatusInternalServerError)
	errs = append(errs, e.bot.AskRun(context.Background(), runPrompt("apr_t1")))
	m := e.askRun(runPrompt("apr_t2"))
	e.fake.FailNext("editMessageText", http.StatusInternalServerError)
	errs = append(errs, e.bot.Settle(context.Background(), "apr_t2", approval.Outcome{Kind: approval.Expired}))
	e.fake.WaitAnswer(t, e.fake.PushCallback(telegramtest.Callback{FromID: 5, ChatID: 5, MessageID: m.MessageID, Data: "v1:AAAAAAAAAAAAAAAAAAAAAA"}))
	e.fake.FailNext("answerCallbackQuery", http.StatusInternalServerError)
	e.fake.PushCallback(telegramtest.Callback{FromID: 5, ChatID: 5, MessageID: m.MessageID, Data: "x"})
	e.fake.Wait(t, "the failed answer", func() bool { return e.fake.Calls("answerCallbackQuery") == 2 })

	// Transient getUpdates errors, then a 409.
	e.fake.FailNext("getUpdates", http.StatusBadGateway)
	e.fake.FailNext("getUpdates", http.StatusConflict)
	e.fake.PushMessage(telegramtest.TextMessage{FromID: 1, ChatID: 1, Text: "x"})
	errs = append(errs, e.runErr())

	// A transport error: net/http puts the full URL, token included, in
	// *url.Error.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	cfg := e.cfg
	cfg.APIURL = deadURL
	b, err := telegram.New(cfg, openDB(t), e.audit)
	if err != nil {
		t.Fatal(err)
	}
	b.SetResolver(e.res)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	errs = append(errs, b.Run(ctx))
	cancel()

	// A server that redirects must not be followed.
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1"+r.URL.Path, http.StatusFound)
	}))
	defer redirect.Close()
	cfg.APIURL = redirect.URL
	b2, err := telegram.New(cfg, openDB(t), e.audit)
	if err != nil {
		t.Fatal(err)
	}
	b2.SetResolver(e.res)
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	errs = append(errs, b2.Run(ctx))
	cancel()

	logs := e.logs.String()
	if !strings.Contains(logs, "getUpdates") || !strings.Contains(logs, "deleteWebhook") {
		t.Fatalf("the failures were not logged at all:\n%s", logs)
	}
	for _, s := range []string{tok, "bot" + tok, strings.SplitN(tok, ":", 2)[1]} {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain the token (%q):\n%s", s, logs)
		}
	}
	for _, err := range errs {
		if err == nil {
			t.Error("a forced failure returned no error")
			continue
		}
		if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), strings.SplitN(tok, ":", 2)[1]) {
			t.Errorf("error contains the token: %v", err)
		}
	}
	for _, r := range e.audit.records() {
		if strings.Contains(r.Detail, tok) {
			t.Errorf("audit contains the token: %+v", r)
		}
	}
}
