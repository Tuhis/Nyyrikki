package decision_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
)

const aliceID int64 = 777

// withEnrollTarget adds alice and db-1, whose humans are owner and
// alice, so an enrollment asks two people.
func withEnrollTarget(e *env) *env {
	withSSH(e)
	e.cfg.Humans = append(e.cfg.Humans, config.Human{ID: "alice", Subject: "alice-sub", TelegramUserID: aliceID})
	for i := range e.cfg.Targets {
		if e.cfg.Targets[i].Name == "db-1" {
			e.cfg.Targets[i].Humans = []string{"owner", "alice"}
		}
	}
	return e
}

func enrollReq() decision.EnrollRequest {
	return decision.EnrollRequest{Target: "db-1", HostKey: "ED25519 SHA256:abc", Fingerprint: "SHA256:abc", SessionKill: true,
		ClientAddr: "198.51.100.7", TokenIssued: time.Unix(1_800_000_000, 0), TokenSHA256: "feed"}
}

type issuer struct {
	calls atomic.Int32
	err   error
}

func (i *issuer) issue(context.Context, string) error { i.calls.Add(1); return i.err }

func (e *env) enrollAsync(ctx context.Context, iss *issuer) chan error {
	ch := make(chan error, 1)
	go func() { ch <- e.p.DecideEnroll(ctx, enrollReq(), iss.issue) }()
	return ch
}

func waitErr(t *testing.T, ch chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("DecideEnroll did not return")
		return nil
	}
}

// prompts returns the two enrollment prompts, owner's first.
func (e *env) enrollPrompts() (owner, alice approval.EnrollPrompt) {
	e.t.Helper()
	e.prompt()
	e.prompt()
	e.asker.mu.Lock()
	defer e.asker.mu.Unlock()
	for _, p := range e.asker.enrolls {
		switch p.ApproverID {
		case approverID:
			owner = p
		case aliceID:
			alice = p
		}
	}
	if owner.ID == "" || alice.ID == "" || owner.ID == alice.ID {
		e.t.Fatalf("prompts %+v", e.asker.enrolls)
	}
	return owner, alice
}

func (e *env) waitSettled(id string, want approval.OutcomeKind) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, k := range e.asker.outcomes(id) {
			if k == want {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("%s not settled %v: %v", id, want, e.asker.outcomes(id))
}

// TestEnrollPromptsEveryHuman covers docs/08 D7 and §5.2 (G7): every
// human of the target gets a prompt with the fingerprint, address, sudo
// from config, session_kill as reported, the client and the token's
// issue time; the first valid tap settles all of them, every copy says
// who settled it, and a later tap on another copy changes nothing.
func TestEnrollPromptsEveryHuman(t *testing.T) {
	e := withEnrollTarget(newEnv(t))
	iss := &issuer{}
	ch := e.enrollAsync(context.Background(), iss)
	owner, alice := e.enrollPrompts()
	for _, p := range []approval.EnrollPrompt{owner, alice} {
		if p.Target != "db-1" || p.Address != "db-1.example.com:22" || p.HostKey != "ED25519 SHA256:abc" || !p.Sudo || !p.SessionKill ||
			p.ClientAddr != "198.51.100.7" || !p.TokenIssued.Equal(time.Unix(1_800_000_000, 0)) || !p.ExpiresAt.After(e.clock.now()) {
			t.Fatalf("prompt %+v", p)
		}
	}
	// alice's tap counts only from alice.
	if ok, _ := e.p.Resolve(context.Background(), alice.ID, approval.ActionApprove, approverID); ok {
		t.Fatal("owner approved alice's copy")
	}
	if ok, err := e.p.Resolve(context.Background(), alice.ID, approval.ActionApprove, aliceID); !ok || err != nil {
		t.Fatalf("alice approves: %v %v", ok, err)
	}
	if err := waitErr(t, ch); err != nil {
		t.Fatal(err)
	}
	if iss.calls.Load() != 1 {
		t.Fatalf("issued %d times", iss.calls.Load())
	}
	for _, id := range []string{owner.ID, alice.ID} {
		e.waitSettled(id, approval.Approved)
		e.asker.mu.Lock()
		by := e.asker.by[id]
		e.asker.mu.Unlock()
		if by != "alice" {
			t.Errorf("%s: by %q", id, by)
		}
	}
	// The other copy is settled too: a late tap changes nothing.
	for _, a := range []approval.Action{approval.ActionApprove, approval.ActionDeny} {
		if ok, _ := e.p.Resolve(context.Background(), owner.ID, a, approverID); ok {
			t.Fatalf("a late %v counted", a)
		}
	}
	if recs := auditRecords(t, e, codes.KindHostEnrollApproved); len(recs) != 1 || recs[0]["human"] != "alice" || recs[0]["host_key"] != "SHA256:abc" {
		t.Fatalf("approved audit %v", recs)
	}
	if recs := auditRecords(t, e, codes.KindHostEnrollRequested); len(recs) != 1 || recs[0]["token_sha256"] != "feed" || recs[0]["client_addr"] != "198.51.100.7" {
		t.Fatalf("requested audit %v", recs)
	}
}

// TestEnrollDeniedExpiredWithdrawn covers docs/08 G7: a deny by either
// human, nobody answering, and the caller going away return no
// certificate (issue never runs) and audit why.
func TestEnrollDeniedExpiredWithdrawn(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		iss := &issuer{}
		ch := e.enrollAsync(context.Background(), iss)
		owner, alice := e.enrollPrompts()
		if ok, _ := e.p.Resolve(context.Background(), owner.ID, approval.ActionDeny, approverID); !ok {
			t.Fatal("deny")
		}
		if err := waitErr(t, ch); codes.Of(err) != codes.Denied {
			t.Fatalf("err %v", err)
		}
		e.waitSettled(alice.ID, approval.Denied)
		// alice can't approve what owner denied.
		if ok, _ := e.p.Resolve(context.Background(), alice.ID, approval.ActionApprove, aliceID); ok || iss.calls.Load() != 0 {
			t.Fatal("approved after a deny")
		}
		if recs := auditRecords(t, e, codes.KindHostEnrollDenied); len(recs) != 1 || recs[0]["code"] != string(codes.Denied) {
			t.Fatalf("denied audit %v", recs)
		}
	})
	t.Run("expired", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		e.cfg.Approval.Timeout = config.Duration(50 * time.Millisecond)
		iss := &issuer{}
		ch := e.enrollAsync(context.Background(), iss)
		owner, _ := e.enrollPrompts()
		if err := waitErr(t, ch); codes.Of(err) != codes.Expired || iss.calls.Load() != 0 {
			t.Fatalf("err %v", err)
		}
		e.waitSettled(owner.ID, approval.Expired)
		if recs := auditRecords(t, e, codes.KindHostEnrollDenied); len(recs) != 1 || recs[0]["code"] != string(codes.Expired) {
			t.Fatalf("expired audit %v", recs)
		}
	})
	t.Run("caller gone", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		iss := &issuer{}
		ctx, cancel := context.WithCancel(context.Background())
		ch := e.enrollAsync(ctx, iss)
		owner, alice := e.enrollPrompts()
		cancel()
		if err := waitErr(t, ch); codes.Of(err) != codes.Withdrawn || iss.calls.Load() != 0 {
			t.Fatalf("err %v", err)
		}
		e.waitSettled(alice.ID, approval.Withdrawn)
		if ok, _ := e.p.Resolve(context.Background(), owner.ID, approval.ActionApprove, approverID); ok {
			t.Fatal("approved after the caller left")
		}
		if recs := auditRecords(t, e, codes.KindHostEnrollDenied); len(recs) != 1 || recs[0]["code"] != string(codes.Withdrawn) {
			t.Fatalf("withdrawn audit %v", recs)
		}
	})
}

// TestEnrollConcurrentTaps: approve and deny on two copies at once, many
// times: exactly one wins, and the call's answer matches it.
func TestEnrollConcurrentTaps(t *testing.T) {
	for range 20 {
		e := withEnrollTarget(newEnv(t))
		iss := &issuer{}
		ch := e.enrollAsync(context.Background(), iss)
		owner, alice := e.enrollPrompts()
		var wg sync.WaitGroup
		var approved, denied atomic.Bool
		wg.Add(2)
		go func() {
			defer wg.Done()
			ok, _ := e.p.Resolve(context.Background(), owner.ID, approval.ActionApprove, approverID)
			approved.Store(ok)
		}()
		go func() {
			defer wg.Done()
			ok, _ := e.p.Resolve(context.Background(), alice.ID, approval.ActionDeny, aliceID)
			denied.Store(ok)
		}()
		wg.Wait()
		err := waitErr(t, ch)
		switch {
		case approved.Load() == denied.Load():
			t.Fatalf("approve %v, deny %v: exactly one must win", approved.Load(), denied.Load())
		case approved.Load() && (err != nil || iss.calls.Load() != 1):
			t.Fatalf("approved, but %v, issued %d", err, iss.calls.Load())
		case denied.Load() && (codes.Of(err) != codes.Denied || iss.calls.Load() != 0):
			t.Fatalf("denied, but %v, issued %d", err, iss.calls.Load())
		}
	}
}

// TestEnrollFailClosed covers each dependency of an enrollment: Telegram
// unhealthy or failing to send to any one human, the audit log failing
// before the prompt, after the approval, and the certificate failing to
// be issued. Each is a refusal with no certificate.
func TestEnrollFailClosed(t *testing.T) {
	t.Run("telegram down", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		e.asker.mu.Lock()
		e.asker.healthy = false
		e.asker.mu.Unlock()
		iss := &issuer{}
		if err := waitErr(t, e.enrollAsync(context.Background(), iss)); codes.Of(err) != codes.Unavailable || iss.calls.Load() != 0 {
			t.Fatalf("err %v", err)
		}
		e.noPrompt()
	})
	t.Run("one send fails", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		e.asker.mu.Lock()
		e.asker.enrollErr = map[int64]error{aliceID: errors.New("telegram 500")}
		e.asker.mu.Unlock()
		iss := &issuer{}
		err := waitErr(t, e.enrollAsync(context.Background(), iss))
		if codes.Of(err) != codes.Unavailable || iss.calls.Load() != 0 {
			t.Fatalf("err %v", err)
		}
		// owner's copy, already sent, is retired and can't be approved.
		owner := e.asker.enrolls[0]
		e.waitSettled(owner.ID, approval.Failed)
		if ok, _ := e.p.Resolve(context.Background(), owner.ID, approval.ActionApprove, approverID); ok {
			t.Fatal("approved a failed enrollment")
		}
	})
	t.Run("audit before the prompt", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		e.audit.failKind = codes.KindHostEnrollRequested
		iss := &issuer{}
		if err := waitErr(t, e.enrollAsync(context.Background(), iss)); codes.Of(err) != codes.Unavailable {
			t.Fatalf("err %v", err)
		}
		e.noPrompt()
	})
	t.Run("audit of the approval", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		e.audit.failKind = codes.KindHostEnrollApproved
		iss := &issuer{}
		ch := e.enrollAsync(context.Background(), iss)
		owner, _ := e.enrollPrompts()
		e.p.Resolve(context.Background(), owner.ID, approval.ActionApprove, approverID)
		if err := waitErr(t, ch); codes.Of(err) != codes.Unavailable || iss.calls.Load() != 0 {
			t.Fatalf("err %v, issued %d", err, iss.calls.Load())
		}
		e.waitSettled(owner.ID, approval.Failed)
	})
	t.Run("issue fails", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		iss := &issuer{err: codes.WithDetail(codes.Unavailable, "ca_key_unreadable", "broken")}
		ch := e.enrollAsync(context.Background(), iss)
		owner, alice := e.enrollPrompts()
		e.p.Resolve(context.Background(), owner.ID, approval.ActionApprove, approverID)
		if err := waitErr(t, ch); codes.DetailOf(err) != "ca_key_unreadable" {
			t.Fatalf("err %v", err)
		}
		e.waitSettled(alice.ID, approval.Failed)
		if recs := auditRecords(t, e, codes.KindHostEnrollDenied); len(recs) != 1 || recs[0]["detail"] != "ca_key_unreadable" {
			t.Fatalf("audit %v", recs)
		}
	})
	t.Run("no approver", func(t *testing.T) {
		e := withEnrollTarget(newEnv(t))
		for i := range e.cfg.Targets {
			if e.cfg.Targets[i].Name == "db-1" {
				e.cfg.Targets[i].Humans = nil
			}
		}
		if err := waitErr(t, e.enrollAsync(context.Background(), &issuer{})); codes.Of(err) != codes.Unavailable {
			t.Fatalf("err %v", err)
		}
		e.noPrompt()
	})
}

// TestEnrollPendingExpiresOnRestart: an enrollment left pending by a
// stopped process is expired on start, every copy, as any approval.
func TestEnrollPendingExpiresOnRestart(t *testing.T) {
	dir := t.TempDir()
	e := withEnrollTarget(newEnvAt(t, dir))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := e.enrollAsync(ctx, &issuer{})
	owner, alice := e.enrollPrompts()
	e.p.Close()
	e2 := withEnrollTarget(newEnvAt(t, dir))
	for _, id := range []string{owner.ID, alice.ID} {
		e2.waitSettled(id, approval.Expired)
		if ok, _ := e2.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); ok {
			t.Fatal("approved after a restart")
		}
	}
	cancel()
	waitErr(t, ch)
}
