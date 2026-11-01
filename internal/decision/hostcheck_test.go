package decision_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
)

// hostResult is what fakeHosts answers for one target.
type hostResult struct {
	facts decision.HostFacts
	err   error
}

// fakeHosts is the host check of docs/08 D10 without a host: by default
// it reads the facts a pinned host shows, the target's config value.
type fakeHosts struct {
	cfg     *config.Config
	mu      sync.Mutex
	results map[string]hostResult
	calls   []string
}

func (f *fakeHosts) CheckHost(_ context.Context, target string) (decision.HostFacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, target)
	if r, ok := f.results[target]; ok {
		return r.facts, r.err
	}
	t, _ := f.cfg.TargetByName(target)
	return decision.HostFacts{SessionKill: t != nil && t.SSH != nil && t.SSH.SessionKill}, nil
}

func (f *fakeHosts) set(target string, r hostResult) {
	f.mu.Lock()
	f.results[target] = r
	f.mu.Unlock()
}

func (f *fakeHosts) checked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func unavailable(detail string) error {
	return codes.WithDetail(codes.Unavailable, detail, "check failed")
}

// TestHostCheckBeforeRunPrompt covers docs/08 D10 (G9): every SSH run
// prompt, interactive or not, is preceded by a host check of its
// target; the prompt's session_kill is what the check read, not the
// config value, and the grant carries what the approver was shown. A
// Kubernetes run is never checked.
func TestHostCheckBeforeRunPrompt(t *testing.T) {
	for _, tc := range []struct {
		name        string
		interactive bool
		read        bool
	}{
		{"read true", false, true},
		{"read false", false, false},
		{"interactive", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := withSSH(newEnv(t))
			// web-1's config says false: only the check can make it true.
			e.hosts.set("web-1", hostResult{facts: decision.HostFacts{SessionKill: tc.read}})
			args := []string{"uptime"}
			if tc.interactive {
				args = nil
			}
			ch := e.runAsync(context.Background(), sshReq(t, "web-1", tc.interactive, args...))
			id := e.prompt()
			if got := e.hosts.checked(); len(got) != 1 || got[0] != "web-1" {
				t.Fatalf("checked %v before the prompt", got)
			}
			if p := e.asker.lastRun; p.SSH == nil || p.SSH.SessionKill != tc.read || p.SSH.CheckFailed != "" {
				t.Fatalf("prompt SSH %+v", p.SSH)
			}
			if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); !ok {
				t.Fatal("approve")
			}
			res := get(t, ch)
			if res.err != nil {
				t.Fatal(res.err)
			}
			if res.g.SessionKillShown() != tc.read {
				t.Fatalf("grant shown %v, want %v", res.g.SessionKillShown(), tc.read)
			}
			res.g.Release()
			recs := auditRecords(t, e, codes.KindHostChecked)
			want := "no_session_kill"
			if tc.read {
				want = "session_kill"
			}
			if len(recs) != 1 || recs[0]["detail"] != want || recs[0]["run_id"] == nil || recs[0]["approval_id"] != id {
				t.Fatalf("host_checked %v", recs)
			}
		})
	}
	e := withSSH(newEnv(t))
	ctx, cancel := context.WithCancel(context.Background())
	ch := e.runAsync(ctx, runReq(t, "agent-a", "prod", "get", "pods"))
	e.prompt()
	if got := e.hosts.checked(); len(got) != 0 {
		t.Fatalf("a Kubernetes run checked %v", got)
	}
	cancel()
	get(t, ch)
}

// TestHostCheckFailedRunDenied covers docs/08 D10 (G9): a run whose host
// check fails is denied with its detail, the approver is never asked,
// and the check and the deny are audited.
func TestHostCheckFailedRunDenied(t *testing.T) {
	for _, detail := range []string{"host_unreachable", "host_key_mismatch", "host_key_revoked", "host_not_pinned", "ca_key_unreadable"} {
		t.Run(detail, func(t *testing.T) {
			e := withSSH(newEnv(t))
			e.hosts.set("db-1", hostResult{err: unavailable(detail)})
			_, err := e.p.DecideRun(context.Background(), sshReq(t, "db-1", false, "id"))
			if codes.Of(err) != codes.Unavailable || codes.DetailOf(err) != detail {
				t.Fatalf("err %v", err)
			}
			e.noPrompt()
			checked := auditRecords(t, e, codes.KindHostChecked)
			if len(checked) != 1 || checked[0]["detail"] != detail || checked[0]["code"] != string(codes.Unavailable) {
				t.Fatalf("host_checked %v", checked)
			}
			var denied bool
			for _, r := range auditRecords(t, e, codes.KindDecision) {
				if r["decision"] == codes.Deny && r["detail"] == detail {
					denied = true
				}
			}
			if !denied {
				t.Fatal("no audited deny")
			}
			if len(auditRecords(t, e, codes.KindApprovalSent)) != 0 {
				t.Fatal("an approval was sent")
			}
		})
	}
}

// TestHostCheckFailClosed covers the host check's own dependencies
// failing (CODE-REVIEW.md: fail closed): no checker configured with an
// SSH target, a checker breaking its contract (an error without code
// or detail), and the audit write of the check failing. Each denies the
// run unprompted. An elevation with no checker shows the warning.
func TestHostCheckFailClosed(t *testing.T) {
	t.Run("no checker", func(t *testing.T) {
		e := withSSH(newEnv(t))
		p, err := decision.New(context.Background(), decision.Config{Config: e.cfg, DB: e.db, Audit: e.audit, Asker: e.asker, Introspector: e.intro, Now: e.clock.now})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		_, err = p.DecideRun(context.Background(), sshReq(t, "db-1", false, "id"))
		if codes.Of(err) != codes.Unavailable || codes.DetailOf(err) != decision.DetailHostCheckUnavailable {
			t.Fatalf("err %v", err)
		}
		e.noPrompt()
		ch := make(chan error, 1)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			_, err := p.Elevate(ctx, decision.ElevateRequest{Principal: principal("agent-a"), Targets: []string{"db-1"}, Reason: "r"})
			ch <- err
		}()
		e.prompt()
		if h := e.asker.lastElev.SSH; len(h) != 1 || h[0].SessionKill || h[0].CheckFailed != decision.DetailHostCheckUnavailable {
			t.Fatalf("elevation SSH %+v", h)
		}
		cancel()
		<-ch
	})
	t.Run("checker breaks its contract", func(t *testing.T) {
		e := withSSH(newEnv(t))
		e.hosts.set("db-1", hostResult{facts: decision.HostFacts{SessionKill: true}, err: errors.New("boom")})
		_, err := e.p.DecideRun(context.Background(), sshReq(t, "db-1", false, "id"))
		if codes.Of(err) != codes.Unavailable || codes.DetailOf(err) != decision.DetailHostCheckUnavailable {
			t.Fatalf("err %v", err)
		}
		e.noPrompt()
	})
	t.Run("audit of the check fails", func(t *testing.T) {
		e := withSSH(newEnv(t))
		e.audit.mu.Lock()
		e.audit.failKind = codes.KindHostChecked
		e.audit.mu.Unlock()
		_, err := e.p.DecideRun(context.Background(), sshReq(t, "db-1", false, "id"))
		if codes.Of(err) != codes.Unavailable {
			t.Fatalf("run: %v", err)
		}
		err = e.elevateErr("db-1", "prod")
		if codes.Of(err) != codes.Unavailable {
			t.Fatalf("elevate: %v", err)
		}
		e.noPrompt()
	})
}

// TestHostCheckElevation covers docs/08 D10 (G9) for an elevation: each
// SSH target is checked before the prompt, Kubernetes targets are not;
// a failed check doesn't block the elevation, and its target is shown
// with the warning and as not finishing cuts. What was shown is kept
// with the elevation: its runs carry it, so a target shown with the
// warning can never trip host_changed, and one shown as finishing cuts
// can.
func TestHostCheckElevation(t *testing.T) {
	e := withSSH(newEnv(t))
	e.hosts.set("db-1", hostResult{err: unavailable("host_unreachable")})
	e.hosts.set("web-1", hostResult{facts: decision.HostFacts{SessionKill: true}})
	el := e.elevate("agent-a", []string{"db-1", "prod", "web-1"}, 5*time.Minute)
	got := e.hosts.checked()
	slices.Sort(got)
	if !slices.Equal(got, []string{"db-1", "web-1"}) {
		t.Fatalf("checked %v", got)
	}
	pr := e.asker.lastElev
	if len(pr.SSH) != 2 || pr.SSH[0].Target != "db-1" || pr.SSH[0].SessionKill || pr.SSH[0].CheckFailed != "host_unreachable" ||
		pr.SSH[1].Target != "web-1" || !pr.SSH[1].SessionKill || pr.SSH[1].CheckFailed != "" {
		t.Fatalf("prompt SSH %+v", pr.SSH)
	}
	// The hosts change after the prompt; runs carry what was shown, and
	// no new check runs for a covered run.
	e.hosts.set("db-1", hostResult{facts: decision.HostFacts{SessionKill: true}})
	for target, want := range map[string]bool{"db-1": false, "web-1": true} {
		r := sshReq(t, target, false, "id")
		r.Handle = el.Handle
		g, err := e.p.DecideRun(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if g.CoveredBy() != codes.CoveredElevation || g.SessionKillShown() != want {
			t.Fatalf("%s: covered by %s, shown %v", target, g.CoveredBy(), g.SessionKillShown())
		}
		g.Release()
	}
	if n := len(e.hosts.checked()); n != 2 {
		t.Fatalf("%d checks; a covered run needs none", n)
	}
	e.noPrompt()
	// A Kubernetes run under it doesn't need host facts.
	k := runReq(t, "agent-a", "prod", "get", "pods")
	k.Handle = el.Handle
	if g, err := e.p.DecideRun(context.Background(), k); err != nil {
		t.Fatal(err)
	} else {
		g.Release()
	}
}

// TestHostCheckElevationFactsMissing: an elevation whose shown facts
// can't be found doesn't cover an SSH run; the run asks for a one-off,
// with a check of its own. Corrupt facts deny.
func TestHostCheckElevationFactsMissing(t *testing.T) {
	e := withSSH(newEnv(t))
	el := e.elevate("agent-a", []string{"db-1"}, 5*time.Minute)
	if _, err := e.db.Exec("DELETE FROM approval_host_facts"); err != nil {
		t.Fatal(err)
	}
	r := sshReq(t, "db-1", false, "id")
	r.Handle = el.Handle
	ch := e.runAsync(context.Background(), r)
	id := e.prompt()
	if n := len(e.hosts.checked()); n != 2 {
		t.Fatalf("%d checks; the one-off needs its own", n)
	}
	e.p.Resolve(context.Background(), id, approval.ActionDeny, approverID)
	get(t, ch)

	e2 := withSSH(newEnv(t))
	el2 := e2.elevate("agent-a", []string{"db-1"}, 5*time.Minute)
	if _, err := e2.db.Exec("UPDATE approval_host_facts SET facts = 'not json'"); err != nil {
		t.Fatal(err)
	}
	r2 := sshReq(t, "db-1", false, "id")
	r2.Handle = el2.Handle
	if _, err := e2.p.DecideRun(context.Background(), r2); err == nil {
		t.Fatal("corrupt facts allowed a run")
	}
	e2.noPrompt()
}

// TestHostCheckElevationParallel: an elevation's checks run in parallel,
// at most four at a time, and all finish before the prompt.
func TestHostCheckElevationParallel(t *testing.T) {
	e := newEnv(t)
	var names []string
	for i := range 8 {
		n := fmt.Sprintf("h-%d", i)
		names = append(names, n)
		e.cfg.Targets = append(e.cfg.Targets, config.Target{Name: n, Humans: []string{"owner"}, SSH: &config.SSHTarget{Address: n + ".example.com:22"}})
	}
	slow := &slowHosts{delay: 100 * time.Millisecond}
	p, err := decision.New(context.Background(), decision.Config{Config: e.cfg, DB: e.db, Audit: e.audit, Asker: e.asker, Introspector: e.intro, Hosts: slow, Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go p.Elevate(ctx, decision.ElevateRequest{Principal: principal("agent-a"), Targets: names, Reason: "r"})
	e.prompt()
	took := time.Since(start)
	slow.mu.Lock()
	defer slow.mu.Unlock()
	if slow.done != 8 || slow.max > 4 || slow.max < 2 {
		t.Fatalf("done %d, at most %d at once", slow.done, slow.max)
	}
	if took > 700*time.Millisecond {
		t.Fatalf("checks took %v: not parallel", took)
	}
}

type slowHosts struct {
	delay    time.Duration
	mu       sync.Mutex
	cur, max int
	done     int
}

func (s *slowHosts) CheckHost(context.Context, string) (decision.HostFacts, error) {
	s.mu.Lock()
	s.cur++
	s.max = max(s.max, s.cur)
	s.mu.Unlock()
	time.Sleep(s.delay)
	s.mu.Lock()
	s.cur--
	s.done++
	s.mu.Unlock()
	return decision.HostFacts{}, nil
}
