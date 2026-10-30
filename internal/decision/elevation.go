package decision

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision/internal/grant"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// ElevateRequest asks for an elevation (docs/02 D8).
type ElevateRequest struct {
	Principal *authn.Principal
	Targets   []string
	// Duration is what the agent asked for; zero means the default. More
	// than MaxElevation gives MaxElevation.
	Duration time.Duration
	Reason   string
	Progress func(msg string)
}

// Elevation is what an approved elevate returns, to the waiting call only
// (docs/01 D24).
type Elevation struct {
	ID        string
	Handle    string
	Targets   []string
	ExpiresAt time.Time
}

// ClampDuration applies docs/02 D8 to a requested duration.
func ClampDuration(d time.Duration) (time.Duration, error) {
	switch {
	case d == 0:
		return DefaultElevation, nil
	case d < MinElevation:
		return 0, codes.New(codes.InvalidRequest, "an elevation lasts at least 1m")
	case d > MaxElevation:
		return MaxElevation, nil
	}
	return d, nil
}

// Elevate asks the approver for an elevation and, once approved, returns
// its handle.
func (p *Point) Elevate(ctx context.Context, r ElevateRequest) (*Elevation, error) {
	pr := r.Principal
	if pr == nil {
		return nil, codes.New(codes.Internal, "incomplete request")
	}
	h, err := p.human(pr)
	if err != nil {
		return nil, err
	}
	// Validate before anything is written (docs/02 D13).
	dur, err := ClampDuration(r.Duration)
	if err != nil {
		return nil, err
	}
	if len(r.Targets) == 0 || len(r.Targets) > MaxTargets {
		return nil, codes.New(codes.InvalidRequest, "an elevation names 1 to %d targets", MaxTargets)
	}
	for _, t := range r.Targets {
		if !config.IsSlug(t) {
			return nil, codes.New(codes.InvalidRequest, "targets must be target names")
		}
	}
	rec := p.base_(pr, codes.KindElevationRequested)
	rec.Targets = r.Targets
	rec.Reason = r.Reason
	rec.RunAs = &audit.RunAs{User: h.Kubernetes.User, Groups: h.Kubernetes.Groups}
	if err := p.audit.Append(ctx, rec); err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}
	if err := p.intro.Introspect(ctx, pr); err != nil {
		if codes.Of(err) != codes.SessionInactive {
			err = codes.Wrap(codes.IntrospectionFailed, err, "could not confirm the session")
		}
		return nil, p.deny(ctx, rec, err)
	}
	targets := slices.Clone(r.Targets)
	slices.Sort(targets)
	targets = slices.Compact(targets)
	var hosts []approval.SSHHost
	for _, name := range targets {
		t, ok := p.cfg.TargetByName(name)
		if !ok || !t.Visible(pr.Human, pr.ClientID) {
			return nil, p.deny(ctx, rec, codes.New(codes.TargetNotAllowed, "no such target, or not available to this agent"))
		}
		if hh := sshHost(t, RunAs(h, t).User); hh != nil {
			hosts = append(hosts, *hh)
		}
	}
	rec.Targets = targets

	id := "apr_" + ulid.Make().String()
	rec.ApprovalID = id
	expires := p.now().Add(p.cfg.Approval.Timeout.D())
	prompt := approval.ElevationPrompt{
		ID: id, ApproverID: h.TelegramUserID, Targets: targets, Duration: dur,
		RunAs:  approval.Identity{User: h.Kubernetes.User, Groups: h.Kubernetes.Groups},
		SSH:    hosts,
		Agent:  approval.Agent{ClientName: pr.ClientID, KeyShort: p.audit.AgentHash(pr.AgentKey), SignedInAt: pr.SignedInAt},
		Reason: r.Reason, ExpiresAt: expires,
	}
	tj, _ := json.Marshal(targets)
	state, err := p.ask(ctx, rec, id, "elevation", h.TelegramUserID, pr, string(tj), nil, dur, expires,
		func(ctx context.Context) error { return p.asker.AskElevation(ctx, prompt) }, r.Progress)
	if err != nil || state != stateApproved {
		// A tap may still have approved it after ask gave up (its own
		// settle failed): end what nobody will receive.
		p.abandonElevation(id)
	}
	if err != nil {
		return nil, p.deny(ctx, rec, err)
	}
	if state != stateApproved {
		return nil, p.deny(ctx, rec, stateError(state))
	}
	return p.deliverElevation(ctx, id, rec, targets)
}

// deliverElevation hands an approved elevation to the call that asked for
// it. Whatever goes wrong after the approval won (the call is gone, a query
// fails, the audit write fails), the elevation ends and its handle is
// dropped: nobody may hold a live elevation the caller never received
// (docs/01 D24).
func (p *Point) deliverElevation(ctx context.Context, approvalID string, rec audit.Record, targets []string) (*Elevation, error) {
	p.mu.Lock()
	handle := p.handles[approvalID]
	delete(p.handles, approvalID)
	p.mu.Unlock()
	// The call's context may already be cancelled; the lookup must still
	// work so that the elevation can be ended.
	qctx, cancel := context.WithTimeout(p.base, 10*time.Second)
	defer cancel()
	var (
		elevID   string
		expiresM int64
	)
	if err := p.db.QueryRowContext(qctx, "SELECT id, expires_ms FROM elevations WHERE approval_id = ?", approvalID).Scan(&elevID, &expiresM); err != nil {
		p.endElevationByApproval(approvalID)
		return nil, p.deny(ctx, rec, codes.Wrap(codes.Unavailable, err, "state unavailable"))
	}
	if handle == "" || ctx.Err() != nil {
		// Approved, but the call that asked is gone: nobody can hold the
		// handle, so the elevation ends at once.
		p.endElevation(elevID, stateEnded, "the call ended before the approval arrived")
		return nil, p.deny(ctx, rec, codes.New(codes.Withdrawn, "the call ended before the approval arrived"))
	}
	rec.Kind = codes.KindDecision
	rec.Decision = codes.Allow
	rec.ElevationID = elevID
	if err := p.audit.Append(ctx, rec); err != nil {
		p.endElevation(elevID, stateEnded, "audit log unavailable")
		return nil, codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}
	return &Elevation{ID: elevID, Handle: handle, Targets: targets, ExpiresAt: time.UnixMilli(expiresM).UTC()}, nil
}

// abandonElevation drops the handle of an approval its call gave up on, and
// ends its elevation if one was created.
func (p *Point) abandonElevation(approvalID string) {
	p.mu.Lock()
	delete(p.handles, approvalID)
	p.mu.Unlock()
	p.endElevationByApproval(approvalID)
}

// endElevationByApproval ends the in-memory elevation of an approval when
// its row can't be read: its runs are cut in this process at least.
func (p *Point) endElevationByApproval(approvalID string) {
	p.mu.Lock()
	var id string
	for eid, le := range p.elevations {
		if le.approvalID == approvalID {
			id = eid
		}
	}
	p.mu.Unlock()
	if id != "" {
		p.endElevation(id, stateEnded, "state unavailable")
	}
}

// approveElevation settles an elevation's approval and creates the live
// elevation and its handle in the same transaction (docs/02 §5.3). The
// window starts now (docs/02 D8).
func (p *Point) approveElevation(approvalID string) (bool, error) {
	handle, err := randomSecret(handlePrefix)
	if err != nil {
		return false, err
	}
	hash := HashSecret(handle)
	elevID := "elv_" + ulid.Make().String()
	now := p.now()
	var expires time.Time
	waiting := false
	p.mu.Lock()
	p.handles[approvalID] = handle
	p.mu.Unlock()
	ok := p.settleThen(approvalID, statePending, stateApproved, func(tx *sql.Tx) error {
		var (
			human, agentKey, targets string
			approver, durMS          int64
		)
		if err := tx.QueryRow("SELECT human, agent_key, approver_id, targets, duration_ms FROM approvals WHERE id = ?", approvalID).
			Scan(&human, &agentKey, &approver, &targets, &durMS); err != nil {
			return err
		}
		d := min(time.Duration(durMS)*time.Millisecond, MaxElevation) // never more than 30m, whatever is stored
		expires = now.Add(d)
		_, err := tx.Exec(`INSERT INTO elevations (id, approval_id, handle_hash, state, human, agent_key, client_id, approver_id, targets, created_ms, expires_ms)
			VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?)`,
			elevID, approvalID, hash[:], stateLive, human, agentKey, approver, targets, now.UnixMilli(), expires.UnixMilli())
		return err
	}, func() {
		p.arm(elevID, approvalID, expires)
		// Checked after the commit and before the waiter is notified (it
		// removes itself once woken): the call may have gone between the
		// tap's waiter check and the commit, and then nobody will collect
		// the handle (docs/01 D24).
		p.mu.Lock()
		_, waiting = p.waiters[approvalID]
		if !waiting {
			delete(p.handles, approvalID)
		}
		p.mu.Unlock()
	})
	if !ok {
		p.mu.Lock()
		delete(p.handles, approvalID)
		p.mu.Unlock()
		return false, nil
	}
	if !waiting {
		p.endElevation(elevID, stateEnded, "no call was waiting for the approval")
		return true, nil
	}
	_ = p.audit.Append(p.base, audit.Record{Kind: codes.KindElevationLive, ElevationID: elevID, ApprovalID: approvalID})
	go p.settlePrompt(approvalID, approval.Outcome{Kind: approval.ElevationLive, At: now, Until: expires})
	return true, nil
}

// arm keeps a live elevation's context and its expiry timer.
func (p *Point) arm(elevID, approvalID string, expires time.Time) {
	ctx, cancel := context.WithDeadline(p.base, expires)
	le := &liveElevation{id: elevID, approvalID: approvalID, ctx: ctx, cancel: cancel}
	le.timer = time.AfterFunc(time.Until(expires), func() { p.endElevation(elevID, stateExpired, "expired") })
	p.mu.Lock()
	p.elevations[elevID] = le
	p.mu.Unlock()
}

// endElevation moves a live elevation to ended or expired, cuts its runs
// and edits its prompt. Only the winner of the compare-and-set acts.
func (p *Point) endElevation(elevID, to, detail string) bool {
	ctx, cancel := context.WithTimeout(p.base, 10*time.Second)
	defer cancel()
	res, err := p.db.ExecContext(ctx, "UPDATE elevations SET state = ?, ended_ms = ? WHERE id = ? AND state = ?",
		to, p.now().UnixMilli(), elevID, stateLive)
	p.mu.Lock()
	le := p.elevations[elevID]
	delete(p.elevations, elevID)
	p.mu.Unlock()
	// Cut the runs whatever the database said: if the write failed, the
	// elevation must not keep covering anything in this process either.
	if le != nil {
		le.timer.Stop()
		le.cancel()
	}
	if err != nil {
		p.log.Error("ending elevation failed", "elevation", elevID, "err", err)
		return false
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false
	}
	kind, ok := codes.KindElevationEnded, approval.ElevationEnded
	if to == stateExpired {
		kind, ok = codes.KindElevationExpired, approval.ElevationExpired
	}
	rec := audit.Record{Kind: kind, ElevationID: elevID, Detail: detail}
	if le != nil {
		rec.ApprovalID = le.approvalID
		go p.settlePrompt(le.approvalID, approval.Outcome{Kind: ok, At: p.now()})
	}
	_ = p.audit.Append(ctx, rec)
	return true
}

// IssueTicket makes the one-time stream ticket for an allowed interactive
// run (docs/02 D10). The ticket goes only to the call that asked. If it
// isn't redeemed within 30 s, the grant is released. On an error, g is
// released and its message closed as unused (docs/07 D17).
func (p *Point) IssueTicket(g *Grant, c target.Request) (string, time.Time, error) {
	if !g.Interactive() || !c.Interactive() {
		p.unused(g)
		return "", time.Time{}, codes.New(codes.Internal, "not an interactive run")
	}
	tk, err := randomSecret(ticketPrefix)
	if err != nil {
		p.unused(g)
		return "", time.Time{}, codes.Wrap(codes.Internal, err, "ticket")
	}
	hash := HashSecret(tk)
	expires := p.now().Add(ticketTTL)
	t := &ticket{grant: g, request: c, agentKey: g.AgentKey(), expires: expires}
	t.timer = time.AfterFunc(ticketTTL, func() {
		p.mu.Lock()
		cur := p.tickets[hash]
		delete(p.tickets, hash)
		p.mu.Unlock()
		if cur != nil {
			p.unused(cur.grant)
		}
	})
	p.mu.Lock()
	p.tickets[hash] = t
	p.mu.Unlock()
	return tk, expires, nil
}

// Redeem exchanges a stream ticket for its grant, once, for the agent key
// it was issued to.
func (p *Point) Redeem(ctx context.Context, tk string, pr *authn.Principal) (*Grant, target.Request, error) {
	hash := HashSecret(tk)
	p.mu.Lock()
	t := p.tickets[hash]
	if t != nil && pr != nil && subtle.ConstantTimeCompare([]byte(t.agentKey), []byte(pr.AgentKey)) == 1 {
		delete(p.tickets, hash)
	} else {
		t = nil
	}
	p.mu.Unlock()
	if t == nil {
		return nil, nil, codes.New(codes.Denied, "unknown or used stream ticket")
	}
	t.timer.Stop()
	if !p.now().Before(t.expires) || t.grant.Context().Err() != nil {
		p.unused(t.grant)
		return nil, nil, codes.New(codes.Expired, "stream ticket expired")
	}
	return t.grant, t.request, nil
}

// unused releases the grant of a ticket that was never attached, and
// closes its one-off approval's message as approved, without a button
// (docs/07 D17).
func (p *Point) unused(g *Grant) {
	g.Release()
	if g.CoveredBy() == codes.CoveredOneOff && g.Interactive() {
		go p.settlePrompt(g.ApprovalID(), approval.Outcome{Kind: approval.SessionUnused, At: p.now()})
	}
}

// SessionStarted is called once an interactive run's stream has
// attached (docs/07 D17). Under a one-off approval, the approver's
// message then shows "Session live" with an End now button, which ends g.
// Under an elevation nothing changes: its own End now ends the run.
// SessionEnded must follow, whatever happens to the run.
func (p *Point) SessionStarted(g *Grant) {
	if g == nil || g.CoveredBy() != codes.CoveredOneOff || !g.Interactive() || g.ApprovalID() == "" {
		return
	}
	p.mu.Lock()
	p.sessions[g.ApprovalID()] = g
	p.mu.Unlock()
	go p.settlePrompt(g.ApprovalID(), approval.Outcome{Kind: approval.SessionLive, At: p.now()})
}

// SessionEnded is called when an interactive run is over, for any
// reason: End now no longer acts, and the message shows when it ended.
func (p *Point) SessionEnded(g *Grant) {
	if g == nil || g.CoveredBy() != codes.CoveredOneOff || !g.Interactive() || g.ApprovalID() == "" {
		return
	}
	p.mu.Lock()
	delete(p.sessions, g.ApprovalID())
	p.mu.Unlock()
	go p.settlePrompt(g.ApprovalID(), approval.Outcome{Kind: approval.SessionEnded, At: p.now()})
}

// endSession is End now on a live session (docs/07 D17). It acts only
// while the run is live, and only once.
func (p *Point) endSession(approvalID string) bool {
	p.mu.Lock()
	g := p.sessions[approvalID]
	delete(p.sessions, approvalID)
	p.mu.Unlock()
	if g == nil || g.Context().Err() != nil {
		return false
	}
	grant.End(g, ErrEndedByApprover)
	_ = p.audit.Append(p.base, audit.Record{Kind: codes.KindDecision, RunID: g.RunID(), ApprovalID: approvalID,
		Human: g.Human(), Agent: g.AgentKey(), ClientID: g.ClientID(), Targets: []string{g.Target()},
		Decision: codes.Deny, Detail: DetailEndedByApprover})
	return true
}
