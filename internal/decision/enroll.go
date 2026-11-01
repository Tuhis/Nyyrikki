package decision

import (
	"context"
	"encoding/json"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// EnrollRequest is a host enrollment that passed its token and body
// checks (docs/08 D6, D7). Everything in it was checked by the caller:
// the target is an SSH target in the registry, HostKey is Nyyrikki's own
// rendering of an ed25519 key's fingerprint, ClientAddr an address.
type EnrollRequest struct {
	Target string
	// HostKey is the key's type and SHA256 fingerprint, as the approver
	// is shown it; Fingerprint the SHA256 fingerprint alone, for the
	// audit.
	HostKey     string
	Fingerprint string
	// Digest binds the approvals to the target, the host key and
	// session_kill.
	Digest      [32]byte
	SessionKill bool
	ClientAddr  string
	TokenIssued time.Time
	TokenSHA256 string
}

// DecideEnroll asks every human of the target to approve an enrollment
// (docs/08 D7, §5.2): one approval and one prompt per human, all in one
// group, so that the first valid tap settles every one of them and
// edits every copy. The call waits up to approval.timeout and is settled
// as any approval is (docs/02 D7). Once approved, and while the caller
// still waits, issue runs: it makes and audits the certificate. A nil
// error means issue succeeded for an approved enrollment; anything else
// is a refusal, audited as host_enroll_denied with its code and detail,
// and issue never ran or its result goes nowhere.
func (p *Point) DecideEnroll(ctx context.Context, r EnrollRequest, issue func(ctx context.Context, approvalID string) error) error {
	t, ok := p.cfg.TargetByName(r.Target)
	if !ok || t.SSH == nil || issue == nil {
		return codes.New(codes.Internal, "incomplete enrollment")
	}
	rec := audit.Record{
		Kind: codes.KindHostEnrollRequested, Targets: []string{r.Target},
		HostKey: r.Fingerprint, TokenSHA256: r.TokenSHA256, ClientAddr: r.ClientAddr,
		Detail: sessionKillDetail(r.SessionKill),
	}
	// Records after the wait outlive the caller: a withdrawn enrollment
	// is audited too.
	bg := context.WithoutCancel(ctx)
	deny := func(err error) error {
		d := rec
		d.Kind = codes.KindHostEnrollDenied
		d.Decision = codes.Deny
		d.Code = string(codes.Of(err))
		d.Detail = codes.DetailOf(err)
		if aerr := p.audit.Append(bg, d); aerr != nil {
			p.log.Error("audit write failed", "err", aerr)
		}
		return err
	}

	var approvers []groupApprover
	for _, name := range t.Humans {
		if h, ok := p.cfg.HumanByID(name); ok && h.TelegramUserID > 0 {
			approvers = append(approvers, groupApprover{h.ID, h.TelegramUserID})
		}
	}
	if len(approvers) == 0 {
		return deny(codes.WithDetail(codes.Unavailable, "no_approver", "the target has no human to approve its enrollment"))
	}
	if err := p.audit.Append(ctx, rec); err != nil {
		return codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}
	if !p.asker.Healthy() {
		return deny(codes.New(codes.Unavailable, "the approval channel is unavailable"))
	}

	expires := p.now().Add(p.cfg.Approval.Timeout.D())
	ids := make([]string, len(approvers))
	for i := range ids {
		ids[i] = "apr_" + ulid.Make().String()
	}
	group := ids[0]
	rec.ApprovalID = group

	ch := make(chan string, 1)
	p.mu.Lock()
	for _, id := range ids {
		p.waiters[id] = ch
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		for _, id := range ids {
			delete(p.waiters, id)
			delete(p.settledBy, id)
		}
		p.mu.Unlock()
	}()

	targets, _ := json.Marshal([]string{r.Target})
	if err := p.insertGroup(ctx, ids, approvers, string(targets), r.Digest[:], expires); err != nil {
		return deny(codes.Wrap(codes.Unavailable, err, "state unavailable"))
	}
	sent := rec
	sent.Kind = codes.KindApprovalSent
	if err := p.audit.Append(ctx, sent); err != nil {
		p.settle(group, statePending, stateFailed, nil)
		return codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}
	for i, a := range approvers {
		err := p.asker.AskEnroll(ctx, approval.EnrollPrompt{
			ID: ids[i], ApproverID: a.id, Target: r.Target, Address: t.SSH.Address,
			HostKey: r.HostKey, Sudo: t.SSH.Sudo, SessionKill: r.SessionKill,
			ClientAddr: r.ClientAddr, TokenIssued: r.TokenIssued, ExpiresAt: expires,
		})
		if err != nil {
			// Fail closed: every copy already sent is edited to say so.
			p.settle(group, statePending, stateFailed, nil)
			if codes.Of(err) == codes.InvalidRequest {
				return deny(err)
			}
			return deny(codes.Wrap(codes.Unavailable, err, "the approver could not be asked"))
		}
	}

	state := p.wait(ctx, group, ch, expires, nil)
	if state != stateApproved {
		return deny(stateError(state))
	}
	p.mu.Lock()
	by := p.settledBy[group]
	for _, id := range ids[1:] {
		if by == "" {
			by = p.settledBy[id]
		}
	}
	p.mu.Unlock()
	if ctx.Err() != nil {
		// Approved, but the host's call is gone: no certificate.
		p.settle(group, stateApproved, stateWithdrawn, nil)
		return deny(codes.New(codes.Withdrawn, "the call ended before the approval arrived"))
	}
	approved := rec
	approved.Kind = codes.KindHostEnrollApproved
	approved.Decision = codes.Allow
	approved.Human = by
	if err := p.audit.Append(bg, approved); err != nil {
		p.settle(group, stateApproved, stateFailed, nil)
		return codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}
	if err := issue(ctx, group); err != nil {
		p.settle(group, stateApproved, stateFailed, nil)
		if codes.Of(err) == codes.Internal {
			err = codes.Wrap(codes.Unavailable, err, "the host certificate could not be issued")
		}
		return deny(err)
	}
	for _, id := range ids {
		go p.settlePrompt(id, approval.Outcome{Kind: approval.Approved, At: p.now(), By: by})
	}
	return nil
}

// groupApprover is one human asked to approve an enrollment.
type groupApprover struct {
	human string
	id    int64
}

// insertGroup writes one pending enroll approval per approver, all with
// group_id ids[0], in one transaction.
func (p *Point) insertGroup(ctx context.Context, ids []string, approvers []groupApprover, targets string, digest []byte, expires time.Time) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := p.now().UnixMilli()
	for i, a := range approvers {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO approvals (id, kind, state, human, agent_key, approver_id, targets, digest, created_ms, expires_ms, group_id)
			 VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)`,
			ids[i], kindEnroll, statePending, a.human, a.id, targets, digest, now, expires.UnixMilli(), ids[0]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func sessionKillDetail(kill bool) string {
	if kill {
		return "session_kill"
	}
	return "no_session_kill"
}
