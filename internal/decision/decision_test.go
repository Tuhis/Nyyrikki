package decision_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/store"
)

const approverID = 4242

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fakeAsker struct {
	mu       sync.Mutex
	prompts  chan string
	settled  map[string][]approval.OutcomeKind
	healthy  bool
	sendErr  error
	lastRun  approval.RunPrompt
	lastElev approval.ElevationPrompt
}

func newAsker() *fakeAsker {
	return &fakeAsker{prompts: make(chan string, 16), settled: map[string][]approval.OutcomeKind{}, healthy: true}
}
func (a *fakeAsker) AskRun(_ context.Context, p approval.RunPrompt) error {
	a.mu.Lock()
	a.lastRun = p
	err := a.sendErr
	a.mu.Unlock()
	if err == nil {
		a.prompts <- p.ID
	}
	return err
}
func (a *fakeAsker) AskElevation(_ context.Context, p approval.ElevationPrompt) error {
	a.mu.Lock()
	a.lastElev = p
	err := a.sendErr
	a.mu.Unlock()
	if err == nil {
		a.prompts <- p.ID
	}
	return err
}
func (a *fakeAsker) Settle(_ context.Context, id string, o approval.Outcome) error {
	a.mu.Lock()
	a.settled[id] = append(a.settled[id], o.Kind)
	a.mu.Unlock()
	return nil
}
func (a *fakeAsker) Healthy() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.healthy }
func (a *fakeAsker) outcomes(id string) []approval.OutcomeKind {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approval.OutcomeKind(nil), a.settled[id]...)
}

type fakeIntro struct {
	mu  sync.Mutex
	err error
}

func (f *fakeIntro) Introspect(context.Context, *authn.Principal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// flakyAudit fails every write once failing is set.
type flakyAudit struct {
	*audit.Writer
	mu      sync.Mutex
	failing bool
}

func (f *flakyAudit) Append(ctx context.Context, r audit.Record) error {
	f.mu.Lock()
	failing := f.failing
	f.mu.Unlock()
	if failing {
		return errors.New("disk full")
	}
	return f.Writer.Append(ctx, r)
}

type env struct {
	t     *testing.T
	p     *decision.Point
	asker *fakeAsker
	intro *fakeIntro
	audit *flakyAudit
	clock *clock
	cfg   *config.Config
	dir   string
}

func testConfig() *config.Config {
	c := config.Defaults()
	c.Approval.Timeout = config.Duration(time.Minute)
	c.Humans = []config.Human{{ID: "owner", Subject: "owner-sub", Kubernetes: config.KubeIdent{User: "owner@example.com", Groups: []string{"admins"}}, TelegramUserID: approverID}}
	c.Targets = []config.Target{
		{Name: "prod", Humans: []string{"owner"}, Kubernetes: config.KubeTarget{InCluster: true}},
		{Name: "lab", Humans: []string{"owner"}, Kubernetes: config.KubeTarget{InCluster: true}},
		{Name: "claude-only", Humans: []string{"owner"}, Clients: []string{"claude-code"}, Kubernetes: config.KubeTarget{InCluster: true}},
	}
	return c
}

func newEnv(t *testing.T) *env {
	return newEnvAt(t, t.TempDir())
}

func newEnvAt(t *testing.T, dir string) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &clock{t: time.Now()}
	w, err := audit.NewWriter(ctx, db, io.Discard, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, asker: newAsker(), intro: &fakeIntro{}, audit: &flakyAudit{Writer: w}, clock: clk, cfg: testConfig(), dir: dir}
	e.p, err = decision.New(ctx, decision.Config{Config: e.cfg, DB: db, Audit: e.audit, Asker: e.asker, Introspector: e.intro, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.p.Close)
	return e
}

func principal(key string) *authn.Principal {
	return authn.NewPrincipalForTest(authn.Principal{Human: "owner", Subject: "owner-sub", AgentKey: key, ClientID: "nyyrikki-cli"}, "tok")
}

func canonical(t *testing.T, args ...string) *request.Canonical {
	t.Helper()
	c, err := request.Parse(args, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type result struct {
	g   *decision.Grant
	err error
}

func (e *env) runAsync(ctx context.Context, r decision.RunRequest) chan result {
	ch := make(chan result, 1)
	go func() {
		g, err := e.p.DecideRun(ctx, r)
		ch <- result{g, err}
	}()
	return ch
}

func (e *env) prompt() string {
	e.t.Helper()
	select {
	case id := <-e.asker.prompts:
		return id
	case <-time.After(5 * time.Second):
		e.t.Fatal("no prompt sent")
		return ""
	}
}

func (e *env) noPrompt() {
	e.t.Helper()
	select {
	case id := <-e.asker.prompts:
		e.t.Fatalf("unexpected prompt %s", id)
	default:
	}
}

func get(t *testing.T, ch chan result) result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("decision did not return")
		return result{}
	}
}

func runReq(t *testing.T, key, target string, args ...string) decision.RunRequest {
	return decision.RunRequest{Principal: principal(key), RunID: decision.NewRunID(), Target: target, Canonical: canonical(t, args...), Reason: "because"}
}

func TestOneOffApproved(t *testing.T) {
	e := newEnv(t)
	r := runReq(t, "agent-a", "prod", "delete", "pod", "api-7f", "-n", "shop")
	ch := e.runAsync(context.Background(), r)
	id := e.prompt()
	if got := e.asker.lastRun; got.ApproverID != approverID || got.Target != "prod" || got.RunAs.User != "owner@example.com" || got.Reason != "because" {
		t.Fatalf("prompt %+v", got)
	}
	if ok, err := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); !ok || err != nil {
		t.Fatalf("approve: %v %v", ok, err)
	}
	res := get(t, ch)
	if res.err != nil {
		t.Fatal(res.err)
	}
	g := res.g
	if g.CoveredBy() != codes.CoveredOneOff || g.ApprovalID() != id || g.Digest() != request.Digest("prod", r.Canonical) ||
		g.RunAs().User != "owner@example.com" || g.Target() != "prod" {
		t.Fatalf("grant %+v", g)
	}
	// A second tap changes nothing.
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionDeny, approverID); ok {
		t.Fatal("second tap acted")
	}
	waitOutcome(t, e, id, approval.Approved)
	g.Release()
	if g.Context().Err() == nil {
		t.Fatal("released grant context still live")
	}
}

func TestOneOffDeniedAndWrongApprover(t *testing.T) {
	e := newEnv(t)
	ch := e.runAsync(context.Background(), runReq(t, "agent-a", "prod", "get", "pods"))
	id := e.prompt()
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, 999); ok {
		t.Fatal("foreign approver acted")
	}
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionDeny, approverID); !ok {
		t.Fatal("deny did nothing")
	}
	if res := get(t, ch); codes.Of(res.err) != codes.Denied || res.g != nil {
		t.Fatalf("got %v", res.err)
	}
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); ok {
		t.Fatal("approve after deny acted")
	}
}

func TestOneOffExpires(t *testing.T) {
	e := newEnv(t)
	e.cfg.Approval.Timeout = config.Duration(100 * time.Millisecond)
	ch := e.runAsync(context.Background(), runReq(t, "agent-a", "prod", "get", "pods"))
	id := e.prompt()
	if res := get(t, ch); codes.Of(res.err) != codes.Expired {
		t.Fatalf("got %v", res.err)
	}
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); ok {
		t.Fatal("tap after expiry acted")
	}
	waitOutcome(t, e, id, approval.Expired)
}

func waitOutcome(t *testing.T, e *env, id string, want approval.OutcomeKind) {
	t.Helper()
	for i := 0; i < 100; i++ {
		for _, k := range e.asker.outcomes(id) {
			if k == want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("prompt %s never settled to %v (got %v)", id, want, e.asker.outcomes(id))
}

func TestRunClientDisconnectWithdraws(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch := e.runAsync(ctx, runReq(t, "agent-a", "prod", "get", "pods"))
	id := e.prompt()
	cancel()
	if res := get(t, ch); codes.Of(res.err) != codes.Withdrawn {
		t.Fatalf("got %v", res.err)
	}
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); ok {
		t.Fatal("approval without a waiter acted")
	}
	waitOutcome(t, e, id, approval.Withdrawn)
}

func TestDecideTargetNotAllowed(t *testing.T) {
	e := newEnv(t)
	for _, target := range []string{"nope", "claude-only"} {
		_, err := e.p.DecideRun(context.Background(), runReq(t, "agent-a", target, "get", "pods"))
		if codes.Of(err) != codes.TargetNotAllowed || err.Error() != "target_not_allowed: no such target, or not available to this agent" {
			t.Fatalf("%s: %v", target, err)
		}
	}
	e.noPrompt()
	if got := len(e.p.VisibleTargets(principal("a"))); got != 2 {
		t.Fatalf("visible %d", got)
	}
}

func TestDependencyFailuresDeny(t *testing.T) {
	t.Run("introspection", func(t *testing.T) {
		e := newEnv(t)
		e.intro.err = codes.New(codes.IntrospectionFailed, "down")
		if _, err := e.p.DecideRun(context.Background(), runReq(t, "a", "prod", "get", "pods")); codes.Of(err) != codes.IntrospectionFailed {
			t.Fatal(err)
		}
		e.intro.err = codes.New(codes.SessionInactive, "gone")
		if _, err := e.p.Elevate(context.Background(), decision.ElevateRequest{Principal: principal("a"), Targets: []string{"prod"}, Reason: "r"}); codes.Of(err) != codes.SessionInactive {
			t.Fatal(err)
		}
		e.noPrompt()
	})
	t.Run("approval channel unhealthy", func(t *testing.T) {
		e := newEnv(t)
		e.asker.healthy = false
		if _, err := e.p.DecideRun(context.Background(), runReq(t, "a", "prod", "get", "pods")); codes.Of(err) != codes.Unavailable {
			t.Fatal(err)
		}
	})
	t.Run("send fails", func(t *testing.T) {
		e := newEnv(t)
		e.asker.sendErr = errors.New("telegram down")
		if _, err := e.p.DecideRun(context.Background(), runReq(t, "a", "prod", "get", "pods")); codes.Of(err) != codes.Unavailable {
			t.Fatal(err)
		}
	})
	t.Run("audit fails", func(t *testing.T) {
		e := newEnv(t)
		e.audit.failing = true
		if _, err := e.p.DecideRun(context.Background(), runReq(t, "a", "prod", "get", "pods")); codes.Of(err) != codes.Unavailable {
			t.Fatal(err)
		}
		e.noPrompt()
	})
	t.Run("audit fails after approval", func(t *testing.T) {
		e := newEnv(t)
		ch := e.runAsync(context.Background(), runReq(t, "a", "prod", "get", "pods"))
		id := e.prompt()
		e.audit.mu.Lock()
		e.audit.failing = true
		e.audit.mu.Unlock()
		e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID)
		if res := get(t, ch); res.g != nil || codes.Of(res.err) != codes.Unavailable {
			t.Fatalf("allowed with a failed audit write: %v", res.err)
		}
		// The chat must not say "Approved" for a request that didn't run.
		waitOutcome(t, e, id, approval.Failed)
		for _, k := range e.asker.outcomes(id) {
			if k == approval.Approved {
				t.Fatal("prompt shows Approved for a denied run")
			}
		}
	})
}

func (e *env) elevate(key string, targets []string, d time.Duration) *decision.Elevation {
	e.t.Helper()
	ch := make(chan *decision.Elevation, 1)
	errc := make(chan error, 1)
	go func() {
		el, err := e.p.Elevate(context.Background(), decision.ElevateRequest{Principal: principal(key), Targets: targets, Duration: d, Reason: "deploy"})
		if err != nil {
			errc <- err
			return
		}
		ch <- el
	}()
	id := e.prompt()
	if ok, err := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); !ok || err != nil {
		e.t.Fatalf("approve elevation: %v %v", ok, err)
	}
	select {
	case el := <-ch:
		return el
	case err := <-errc:
		e.t.Fatal(err)
	case <-time.After(5 * time.Second):
		e.t.Fatal("elevate did not return")
	}
	return nil
}

func TestElevationCovers(t *testing.T) {
	e := newEnv(t)
	el := e.elevate("agent-a", []string{"prod"}, 10*time.Minute)
	if len(el.Handle) != 48 || el.Handle[:5] != "nyel_" {
		t.Fatalf("handle %q", el.Handle)
	}
	r := runReq(t, "agent-a", "prod", "get", "pods")
	r.Handle = el.Handle
	g, err := e.p.DecideRun(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if g.CoveredBy() != codes.CoveredElevation || g.ElevationID() != el.ID || !g.NotAfter().Equal(el.ExpiresAt) {
		t.Fatalf("grant %+v", g)
	}
	e.noPrompt()
	g.Release()
}

func TestElevationNotCoveredFallsBackToOneOff(t *testing.T) {
	e := newEnv(t)
	el := e.elevate("agent-a", []string{"prod"}, 10*time.Minute)
	cases := map[string]decision.RunRequest{
		"no handle": runReq(t, "agent-a", "prod", "get", "pods"),
		"other target": func() decision.RunRequest {
			r := runReq(t, "agent-a", "lab", "get", "pods")
			r.Handle = el.Handle
			return r
		}(),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			ch := e.runAsync(ctx, r)
			e.prompt() // went to the one-off path
			cancel()
			get(t, ch)
		})
	}
}

func TestElevationHandleUnknownDenies(t *testing.T) {
	e := newEnv(t)
	el := e.elevate("agent-a", []string{"prod"}, 10*time.Minute)
	for name, h := range map[string]string{
		"other agent key": el.Handle,
		"never issued":    "nyel_" + strings.Repeat("A", 43),
		"malformed":       "garbage",
	} {
		r := runReq(t, "agent-b", "prod", "get", "pods")
		if name != "other agent key" {
			r = runReq(t, "agent-a", "prod", "get", "pods")
		}
		r.Handle = h
		if _, err := e.p.DecideRun(context.Background(), r); codes.Of(err) != codes.HandleUnknown {
			t.Fatalf("%s: %v", name, err)
		}
	}
	e.noPrompt()
}

func TestElevationExpiryAndEnd(t *testing.T) {
	e := newEnv(t)
	el := e.elevate("agent-a", []string{"prod"}, 10*time.Minute)
	r := runReq(t, "agent-a", "prod", "get", "pods", "-w")
	r.Handle = el.Handle
	g, err := e.p.DecideRun(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	// End now from the chat cuts the running request.
	var aid string
	for id := range e.asker.settled {
		aid = id
	}
	if ok, err := e.p.Resolve(context.Background(), aid, approval.ActionEnd, approverID); !ok || err != nil {
		t.Fatalf("end: %v %v", ok, err)
	}
	select {
	case <-g.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("run not cut when the elevation ended")
	}
	waitOutcome(t, e, aid, approval.ElevationEnded)
	ctx, cancel := context.WithCancel(context.Background())
	ch := e.runAsync(ctx, r)
	e.prompt() // ended → one-off
	cancel()
	get(t, ch)

	// Expiry by the server clock, checked on every request.
	el2 := e.elevate("agent-a", []string{"prod"}, 5*time.Minute)
	e.clock.add(6 * time.Minute)
	r.Handle = el2.Handle
	ctx, cancel = context.WithCancel(context.Background())
	ch = e.runAsync(ctx, r)
	e.prompt()
	cancel()
	get(t, ch)
}

func TestElevationClamp(t *testing.T) {
	if d, _ := decision.ClampDuration(2 * time.Hour); d != 30*time.Minute {
		t.Fatalf("2h → %v", d)
	}
	if _, err := decision.ClampDuration(10 * time.Second); codes.Of(err) != codes.InvalidRequest {
		t.Fatal(err)
	}
	e := newEnv(t)
	el := e.elevate("agent-a", []string{"prod"}, 2*time.Hour)
	if got := el.ExpiresAt.Sub(e.clock.now()); got > 30*time.Minute+time.Second {
		t.Fatalf("elevation lasts %v", got)
	}
	if e.asker.lastElev.Duration != 30*time.Minute {
		t.Fatalf("approver shown %v", e.asker.lastElev.Duration)
	}
}

func TestElevationWithdrawnWhenCallerGone(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := e.p.Elevate(ctx, decision.ElevateRequest{Principal: principal("a"), Targets: []string{"prod"}, Reason: "r"})
		errc <- err
	}()
	id := e.prompt()
	cancel()
	if err := <-errc; codes.Of(err) != codes.Withdrawn {
		t.Fatal(err)
	}
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); ok {
		t.Fatal("approval without waiter acted")
	}
}

func TestStartupExpiresPending(t *testing.T) {
	dir := t.TempDir()
	e := newEnvAt(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := e.runAsync(ctx, runReq(t, "a", "prod", "get", "pods"))
	id := e.prompt()
	// Simulate a crash: a second process opens the same database while the
	// approval is still pending.
	e2 := newEnvAt(t, dir)
	if ok, _ := e2.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); ok {
		t.Fatal("approval left by an earlier process acted")
	}
	cancel()
	get(t, ch)
}

func TestStreamTicket(t *testing.T) {
	e := newEnv(t)
	c, err := request.Parse([]string{"exec", "-it", "pod", "--", "sh"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	ch := e.runAsync(context.Background(), decision.RunRequest{Principal: principal("agent-a"), RunID: decision.NewRunID(), Target: "prod", Canonical: c, Reason: "debug"})
	e.p.Resolve(context.Background(), e.prompt(), approval.ActionApprove, approverID)
	res := get(t, ch)
	if res.err != nil {
		t.Fatal(res.err)
	}
	tk, _, err := e.p.IssueTicket(res.g, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.p.Redeem(context.Background(), tk, principal("agent-b")); err == nil {
		t.Fatal("ticket redeemed by another agent key")
	}
	g, got, err := e.p.Redeem(context.Background(), tk, principal("agent-a"))
	if err != nil || g != res.g || got != c {
		t.Fatalf("redeem: %v", err)
	}
	if _, _, err := e.p.Redeem(context.Background(), tk, principal("agent-a")); err == nil {
		t.Fatal("ticket redeemed twice")
	}
	// A non-interactive grant gets no ticket.
	nc := canonical(t, "get", "pods")
	if _, _, err := e.p.IssueTicket(res.g, nc); err == nil {
		t.Fatal("ticket for a non-interactive request")
	}
}

// TestElevateValidatesBeforeAuditing: an elevate naming too many targets is
// refused before anything is written, so one call can't write an
// arbitrarily large audit row (docs/02 D13; found in review of #10, L7).
func TestElevateValidatesBeforeAuditing(t *testing.T) {
	e := newEnv(t)
	targets := make([]string, 11)
	for i := range targets {
		targets[i] = strings.Repeat("x", 60)
	}
	if _, err := e.p.Elevate(context.Background(), decision.ElevateRequest{Principal: principal("a"), Targets: targets, Reason: "r"}); codes.Of(err) != codes.InvalidRequest {
		t.Fatal(err)
	}
	db, _ := store.Open(context.Background(), filepath.Join(e.dir, "db"))
	defer db.Close()
	var n int
	db.QueryRow("SELECT COUNT(*) FROM audit WHERE record LIKE '%xxxxxxxxxxxxxxxxxxxx%'").Scan(&n)
	if n != 0 {
		t.Fatalf("%d audit records carry the unvalidated targets", n)
	}
	e.noPrompt()
}
