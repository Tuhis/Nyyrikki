package telegram_test

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/telegram"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

const approverID int64 = 424242

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nyyrikki.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := telegram.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	// Idempotent.
	if err := telegram.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

// fakeAudit records appended records.
type fakeAudit struct {
	mu   sync.Mutex
	recs []audit.Record
}

func (a *fakeAudit) Append(_ context.Context, r audit.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recs = append(a.recs, r)
	return nil
}

func (a *fakeAudit) records() []audit.Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Record(nil), a.recs...)
}

type resolveCall struct {
	ID         string
	Action     approval.Action
	ApproverID int64
}

// fakeResolver plays the decision point: a compare-and-set over a tiny
// state machine, then Settle on the bot, as decision.Point would.
type fakeResolver struct {
	mu     sync.Mutex
	bot    *telegram.Bot
	state  map[string]string // pending, approved, denied, live, ended
	calls  []resolveCall
	until  time.Time
	err    error
	settle error // last Settle error
}

func newResolver() *fakeResolver {
	return &fakeResolver{state: make(map[string]string), until: time.Date(2026, 10, 26, 12, 18, 4, 0, time.UTC)}
}

func (r *fakeResolver) set(id, state string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state[id] = state
}

func (r *fakeResolver) pending(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state[id] = "pending"
}

func (r *fakeResolver) Resolve(ctx context.Context, id string, action approval.Action, from int64) (bool, error) {
	r.mu.Lock()
	r.calls = append(r.calls, resolveCall{id, action, from})
	if r.err != nil {
		r.mu.Unlock()
		return false, r.err
	}
	var o approval.Outcome
	at := time.Date(2026, 10, 26, 12, 3, 4, 0, time.UTC)
	switch {
	case action == approval.ActionApprove && r.state[id] == "pending" && len(id) > 4 && id[:4] == "elv_":
		r.state[id] = "live"
		o = approval.Outcome{Kind: approval.ElevationLive, At: at, Until: r.until}
	case action == approval.ActionApprove && r.state[id] == "pending":
		r.state[id] = "approved"
		o = approval.Outcome{Kind: approval.Approved, At: at}
	case action == approval.ActionDeny && r.state[id] == "pending":
		r.state[id] = "denied"
		o = approval.Outcome{Kind: approval.Denied, At: at}
	case action == approval.ActionEnd && r.state[id] == "session":
		r.state[id] = "ended"
		o = approval.Outcome{Kind: approval.SessionEnded, At: at}
	case action == approval.ActionEnd && r.state[id] == "live":
		r.state[id] = "ended"
		o = approval.Outcome{Kind: approval.ElevationEnded, At: at}
	default:
		r.mu.Unlock()
		return false, nil
	}
	r.mu.Unlock()
	err := r.bot.Settle(ctx, id, o)
	r.mu.Lock()
	r.settle = err
	r.mu.Unlock()
	return true, nil
}

func (r *fakeResolver) getCalls() []resolveCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]resolveCall(nil), r.calls...)
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t     *testing.T
	fake  *telegramtest.Fake
	db    *sql.DB
	bot   *telegram.Bot
	res   *fakeResolver
	audit *fakeAudit
	logs  *syncBuffer
	cfg   telegram.Config

	cancel context.CancelFunc
	done   chan error
}

type option func(*env)

func withDB(db *sql.DB) option { return func(e *env) { e.db = db } }

func withConfig(f func(*telegram.Config)) option { return func(e *env) { f(&e.cfg) } }

// newEnv builds a bot against a fake Bot API without starting it.
func newEnv(t *testing.T, opts ...option) *env {
	t.Helper()
	e := &env{t: t, fake: telegramtest.New(t), res: newResolver(), audit: &fakeAudit{}, logs: &syncBuffer{}}
	e.cfg = telegram.Config{
		APIURL:       e.fake.URL(),
		TokenFile:    e.fake.TokenFile(t),
		PollTimeout:  time.Second,
		SendInterval: -1,
		BackoffMin:   5 * time.Millisecond,
		BackoffMax:   20 * time.Millisecond,
		Logger:       slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, o := range opts {
		o(e)
	}
	if e.db == nil {
		e.db = openDB(t)
	}
	bot, err := telegram.New(e.cfg, e.db, e.audit)
	if err != nil {
		t.Fatal(err)
	}
	e.bot = bot
	e.res.bot = bot
	bot.SetResolver(e.res)
	return e
}

// start runs the poller and waits until it is healthy.
func (e *env) start() *env {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan error, 1)
	go func() { e.done <- e.bot.Run(ctx) }()
	e.t.Cleanup(func() { e.stop() })
	e.fake.Wait(e.t, "a healthy bot", e.bot.Healthy)
	return e
}

// stop ends Run and returns its error.
func (e *env) stop() error {
	if e.cancel == nil {
		return nil
	}
	e.cancel()
	e.cancel = nil
	select {
	case err := <-e.done:
		e.done <- err // keep it for a second reader
		return err
	case <-time.After(5 * time.Second):
		e.t.Fatal("Run did not return")
		return nil
	}
}

// runErr waits for Run to return on its own.
func (e *env) runErr() error {
	e.t.Helper()
	select {
	case err := <-e.done:
		e.done <- err
		return err
	case <-time.After(5 * time.Second):
		e.t.Fatal("Run did not return")
		return nil
	}
}

func runPrompt(id string) approval.RunPrompt {
	return approval.RunPrompt{
		ID:         id,
		ApproverID: approverID,
		Target:     "prod",
		RunAs:      approval.Identity{User: "alice@example.com", Groups: []string{"oncall", "system:authenticated"}},
		Agent:      approval.Agent{ClientName: "Claude Code", KeyShort: "ab12cd34", SignedInAt: time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)},
		Argv:       "kubectl delete pod web-0 --namespace=shop",
		Reason:     "web-0 is stuck in CrashLoopBackOff",
		ExpiresAt:  time.Date(2026, 10, 26, 12, 5, 0, 0, time.UTC),
	}
}

func elevationPrompt(id string) approval.ElevationPrompt {
	return approval.ElevationPrompt{
		ID:         id,
		ApproverID: approverID,
		Targets:    []string{"prod", "staging"},
		Duration:   15 * time.Minute,
		RunAs:      approval.Identity{User: "alice@example.com"},
		Agent:      approval.Agent{ClientName: "Claude Code", KeyShort: "ab12cd34", SignedInAt: time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)},
		Reason:     "debugging the checkout outage",
		ExpiresAt:  time.Date(2026, 10, 26, 12, 5, 0, 0, time.UTC),
	}
}

// askRun sends a run prompt and returns the message the fake received.
func (e *env) askRun(p approval.RunPrompt) telegramtest.Message {
	e.t.Helper()
	before := len(e.fake.Sent())
	e.res.pending(p.ID)
	if err := e.bot.AskRun(context.Background(), p); err != nil {
		e.t.Fatalf("AskRun: %v", err)
	}
	return e.fake.WaitSent(e.t, before+1)[before]
}

func (e *env) askElevation(p approval.ElevationPrompt) telegramtest.Message {
	e.t.Helper()
	before := len(e.fake.Sent())
	e.res.pending(p.ID)
	if err := e.bot.AskElevation(context.Background(), p); err != nil {
		e.t.Fatalf("AskElevation: %v", err)
	}
	return e.fake.WaitSent(e.t, before+1)[before]
}

func (e *env) current(m telegramtest.Message) telegramtest.Message {
	e.t.Helper()
	cur, ok := e.fake.Message(m.ChatID, m.MessageID)
	if !ok {
		e.t.Fatalf("message %d not found", m.MessageID)
	}
	return cur
}
