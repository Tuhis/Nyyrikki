package telegram

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

type nopAudit struct{}

func (nopAudit) Append(context.Context, audit.Record) error { return nil }

type nopResolver struct{}

func (nopResolver) Resolve(context.Context, string, approval.Action, int64) (bool, error) {
	return false, nil
}

// internalBot is a running Bot against a fake Bot API, for tests that need
// the package's internals.
func internalBot(t *testing.T) (*Bot, *telegramtest.Fake) {
	t.Helper()
	fake := telegramtest.New(t)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{
		APIURL: fake.URL(), TokenFile: fake.TokenFile(t), PollTimeout: time.Second, SendInterval: -1,
		BackoffMin: 5 * time.Millisecond, BackoffMax: 20 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db, nopAudit{})
	if err != nil {
		t.Fatal(err)
	}
	b.SetResolver(nopResolver{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	fake.Wait(t, "a healthy bot", b.Healthy)
	return b, fake
}

func elevation(id string) approval.ElevationPrompt {
	return approval.ElevationPrompt{
		ID: id, ApproverID: 4242, Targets: []string{"prod"}, Duration: 15 * time.Minute,
		RunAs: approval.Identity{User: "alice"}, Agent: approval.Agent{ClientName: "c", KeyShort: "k"},
		Reason: "r", ExpiresAt: time.Now().Add(time.Minute),
	}
}

var (
	liveOutcome  = approval.Outcome{Kind: approval.ElevationLive, Until: time.Date(2026, 10, 27, 12, 18, 4, 0, time.UTC)}
	endedOutcome = approval.Outcome{Kind: approval.ElevationEnded, At: time.Date(2026, 10, 27, 12, 5, 0, 0, time.UTC)}
)

func assertEnded(t *testing.T, fake *telegramtest.Fake, m telegramtest.Message) {
	t.Helper()
	cur, _ := fake.Message(m.ChatID, m.MessageID)
	if len(cur.ButtonTexts()) != 0 || !strings.HasSuffix(cur.Text, "<b>Ended at 12:05:00 UTC</b>") {
		t.Errorf("an ended elevation shows buttons %v and:\n%s", cur.ButtonTexts(), cur.Text)
	}
}

// Review L1: Ended reads the prompt while it is still open, then Live
// commits open→live before Ended's compare-and-set. Ended must still win.
func TestSettleEndedWinsOverStaleLive(t *testing.T) {
	b, fake := internalBot(t)
	ctx := context.Background()
	if err := b.AskElevation(ctx, elevation("elv_stale")); err != nil {
		t.Fatal(err)
	}
	m := fake.WaitSent(t, 1)[0]

	var once sync.Once
	b.testHookBeforeTransition = func() {
		once.Do(func() {
			// Another writer commits open→live between Ended's read and
			// its compare-and-set.
			if won, err := b.transition(ctx, "elv_stale", stateOpen, stateLive,
				[]keyedAction{{newCallbackKey(), approval.ActionEnd}}); err != nil || !won {
				t.Errorf("open→live: won=%v err=%v", won, err)
			}
		})
	}
	if err := b.Settle(ctx, "elv_stale", endedOutcome); err != nil {
		t.Fatalf("Settle(Ended): %v", err)
	}
	assertEnded(t, fake, m)
}

// Review L1: racing Live and Ended, in either order, always end as Ended
// with no buttons, including the order of the edits.
func TestSettleLiveEndedRace(t *testing.T) {
	b, fake := internalBot(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		id := "elv_race_" + string(rune('a'+i))
		if err := b.AskElevation(ctx, elevation(id)); err != nil {
			t.Fatal(err)
		}
		m := fake.WaitSent(t, i+1)[i]
		var wg sync.WaitGroup
		for _, o := range []approval.Outcome{liveOutcome, endedOutcome} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := b.Settle(ctx, id, o); err != nil {
					t.Errorf("Settle: %v", err)
				}
			}()
		}
		wg.Wait()
		assertEnded(t, fake, m)
	}
}
