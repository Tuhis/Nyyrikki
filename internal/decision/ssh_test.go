package decision_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/sshtarget"
)

func withSSH(e *env) *env {
	e.cfg.Targets = append(e.cfg.Targets,
		config.Target{Name: "db-1", Humans: []string{"owner"}, SSH: &config.SSHTarget{Address: "db-1.example.com:22", Sudo: true, SessionKill: true}},
		config.Target{Name: "web-1", Humans: []string{"owner"}, SSH: &config.SSHTarget{Address: "10.0.0.5:2222"}})
	return e
}

func sshReq(t *testing.T, target string, interactive bool, args ...string) decision.RunRequest {
	t.Helper()
	r, err := sshtarget.Build(args, []byte(nil), interactive)
	if err != nil {
		t.Fatal(err)
	}
	return decision.RunRequest{Principal: principal("agent-a"), RunID: decision.NewRunID(), Target: target, Request: r, Reason: "because"}
}

// TestSSHOneOff covers docs/07 D2, D3, D12: the prompt names the account
// on the host and the sudo marker, and the grant binds the digest to the
// target and the account from the registry.
func TestSSHOneOff(t *testing.T) {
	e := withSSH(newEnv(t))
	r := sshReq(t, "db-1", false, "sudo", "systemctl", "restart", "nginx")
	ch := e.runAsync(context.Background(), r)
	id := e.prompt()
	p := e.asker.lastRun
	if p.Type != codes.TypeSSH || p.SSH == nil || p.SSH.Account != "ny-owner" || p.SSH.Address != "db-1.example.com:22" ||
		!p.SSH.Sudo || !p.SSH.SessionKill || p.Argv != "sudo systemctl restart nginx" || p.RunAs.User != "ny-owner" {
		t.Fatalf("prompt %+v %+v", p, p.SSH)
	}
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); !ok {
		t.Fatal("approve")
	}
	res := get(t, ch)
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.g.RunAs().User != "ny-owner" || res.g.Digest() != r.Request.Digest("db-1", "ny-owner") || len(res.g.RunAs().Groups) != 0 {
		t.Fatalf("grant %+v", res.g.RunAs())
	}
	res.g.Release()
}

// TestSSHTypeMismatch: a request built for one target type never runs on
// another (docs/07 D13).
func TestSSHTypeMismatch(t *testing.T) {
	e := withSSH(newEnv(t))
	k := runReq(t, "agent-a", "db-1", "get", "pods")
	if _, err := e.p.DecideRun(context.Background(), k); codes.Of(err) != codes.Internal || codes.DetailOf(err) != "target_type_mismatch" {
		t.Fatalf("kubectl request on an SSH target: %v", err)
	}
	s := sshReq(t, "prod", false, "id")
	if _, err := e.p.DecideRun(context.Background(), s); codes.Of(err) != codes.Internal {
		t.Fatalf("SSH request on a Kubernetes target: %v", err)
	}
	e.noPrompt()
}

// TestElevationSSH covers G11 (unit): an elevation covers an SSH target as
// it does a Kubernetes one, its prompt names each host and its sudo, and
// the grant ends at expiry.
func TestElevationSSH(t *testing.T) {
	e := withSSH(newEnv(t))
	el := e.elevate("agent-a", []string{"db-1", "prod", "web-1"}, 5*time.Minute)
	pr := e.asker.lastElev
	if len(pr.SSH) != 2 || pr.SSH[0].Target != "db-1" || !pr.SSH[0].Sudo || pr.SSH[1].Target != "web-1" || pr.SSH[1].SessionKill {
		t.Fatalf("elevation prompt SSH %+v", pr.SSH)
	}
	r := sshReq(t, "db-1", true, "top")
	r.Handle = el.Handle
	g, err := e.p.DecideRun(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if g.CoveredBy() != codes.CoveredElevation || g.RunAs().User != "ny-owner" || g.NotAfter().IsZero() {
		t.Fatalf("grant %s %s", g.CoveredBy(), g.RunAs().User)
	}
	e.noPrompt()
	// Ending the elevation ends the run's grant, with no approver cause.
	if ok, _ := e.p.Resolve(context.Background(), e.asker.lastElev.ID, approval.ActionEnd, approverID); !ok {
		t.Fatal("end")
	}
	select {
	case <-g.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the run's grant outlived its elevation")
	}
	if errors.Is(context.Cause(g.Context()), decision.ErrEndedByApprover) {
		t.Error("an elevation's end is not a session's End now")
	}
}

// TestEndNowSession covers docs/07 D17 (G14) at the decision point: an
// interactive one-off run's message goes live when its stream attaches;
// End now ends its grant with ErrEndedByApprover, once, while live; the
// end is audited; when it is over the message says so.
func TestEndNowSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  func(t *testing.T) decision.RunRequest
	}{
		{"ssh", func(t *testing.T) decision.RunRequest { return sshReq(t, "db-1", true) }},
		{"kubectl", func(t *testing.T) decision.RunRequest {
			c, err := requestParse([]string{"exec", "-it", "web", "--", "sh"}, true)
			if err != nil {
				t.Fatal(err)
			}
			return decision.RunRequest{Principal: principal("agent-a"), RunID: decision.NewRunID(), Target: "prod", Request: c, Reason: "x"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := withSSH(newEnv(t))
			ch := e.runAsync(context.Background(), tc.req(t))
			id := e.prompt()
			if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); !ok {
				t.Fatal("approve")
			}
			res := get(t, ch)
			if res.err != nil {
				t.Fatal(res.err)
			}
			g := res.g
			waitOutcome(t, e, id, approval.SessionApproved)
			if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionEnd, approverID); ok {
				t.Fatal("End now acted before the stream attached")
			}
			e.p.SessionStarted(g)
			waitOutcome(t, e, id, approval.SessionLive)
			if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionEnd, approverID+1); ok {
				t.Fatal("another user's End now acted")
			}
			if ok, err := e.p.Resolve(context.Background(), id, approval.ActionEnd, approverID); !ok || err != nil {
				t.Fatalf("End now: %v %v", ok, err)
			}
			if !errors.Is(context.Cause(g.Context()), decision.ErrEndedByApprover) {
				t.Fatalf("cause %v", context.Cause(g.Context()))
			}
			if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionEnd, approverID); ok {
				t.Fatal("a second End now acted")
			}
			e.p.SessionEnded(g)
			waitOutcome(t, e, id, approval.SessionEnded)
			if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionEnd, approverID); ok {
				t.Fatal("End now acted after the session ended")
			}
		})
	}
}

// TestSessionUnderElevationNoEndNow: a session covered by an elevation
// keeps the elevation's own End now; its run gets no message of its own.
func TestSessionUnderElevationNoEndNow(t *testing.T) {
	e := withSSH(newEnv(t))
	el := e.elevate("agent-a", []string{"db-1"}, 5*time.Minute)
	r := sshReq(t, "db-1", true)
	r.Handle = el.Handle
	g, err := e.p.DecideRun(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	e.p.SessionStarted(g)
	time.Sleep(50 * time.Millisecond)
	if got := e.asker.outcomes(e.asker.lastElev.ID); len(got) != 1 || got[0] != approval.ElevationLive {
		t.Fatalf("the elevation's message got %v", got)
	}
	e.p.SessionEnded(g)
	g.Release()
}

// TestTicketUnused covers D17: an approved session whose ticket is never
// redeemed leaves its message approved, without a button.
func TestTicketUnused(t *testing.T) {
	e := withSSH(newEnv(t))
	r := sshReq(t, "db-1", true)
	ch := e.runAsync(context.Background(), r)
	id := e.prompt()
	e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID)
	res := get(t, ch)
	tk, _, err := e.p.IssueTicket(res.g, r.Request)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.add(31 * time.Second)
	if _, _, err := e.p.Redeem(context.Background(), tk, r.Principal); codes.Of(err) != codes.Expired {
		t.Fatalf("redeem after expiry: %v", err)
	}
	waitOutcome(t, e, id, approval.SessionUnused)
	if res.g.Context().Err() == nil {
		t.Fatal("the unused grant is still live")
	}
}

func requestParse(args []string, interactive bool) (*request.Canonical, error) {
	return request.Parse(args, nil, interactive)
}

// TestTicketRefusedClosesPrompt: a session approved but given no ticket
// leaves no message stuck at "Approved" with its grant live (review round
// 1, finding 6): it is closed as unused.
func TestTicketRefusedClosesPrompt(t *testing.T) {
	e := withSSH(newEnv(t))
	r := sshReq(t, "db-1", true)
	ch := e.runAsync(context.Background(), r)
	id := e.prompt()
	e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID)
	res := get(t, ch)
	if _, _, err := e.p.IssueTicket(res.g, canonical(t, "get", "pods")); err == nil {
		t.Fatal("a ticket for a request that isn't the grant's")
	}
	waitOutcome(t, e, id, approval.SessionUnused)
	if res.g.Context().Err() == nil {
		t.Fatal("the grant is still live")
	}
}
