// Package decision is Nyyrikki's one decision point (docs/02 D6, §5.3).
// It alone makes Grants, owns the state of approvals, elevations and stream
// tickets, and answers every question that isn't a clear yes with a no.
package decision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision/internal/grant"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
)

const (
	// MaxElevation is the hard cap on an elevation (CLAUDE.md, docs/02 D8).
	MaxElevation     = 30 * time.Minute
	MinElevation     = time.Minute
	DefaultElevation = 15 * time.Minute
	MaxTargets       = 10
	ticketTTL        = 30 * time.Second
	progressInterval = 15 * time.Second

	handlePrefix = "nyel_"
	ticketPrefix = "nyst_"
)

// Approval and elevation states (docs/02 D8).
const (
	statePending   = "pending"
	stateApproved  = "approved"
	stateDenied    = "denied"
	stateExpired   = "expired"
	stateWithdrawn = "withdrawn"
	stateFailed    = "failed"
	stateLive      = "live"
	stateEnded     = "ended"
)

// Auditor appends records and hashes agent keys (docs/03 D3).
type Auditor interface {
	audit.Appender
	AgentHash(key string) string
}

// Config wires a Point.
type Config struct {
	Config       *config.Config
	DB           *sql.DB
	Audit        Auditor
	Asker        approval.Asker
	Introspector authn.Introspector
	Now          func() time.Time
	Logger       *slog.Logger
}

// Point is the decision point.
type Point struct {
	cfg    *config.Config
	db     *sql.DB
	audit  Auditor
	asker  approval.Asker
	intro  authn.Introspector
	now    func() time.Time
	log    *slog.Logger
	base   context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	waiters    map[string]chan string // approval id → final state, sent once by the winner
	elevations map[string]*liveElevation
	tickets    map[[32]byte]*ticket
	// handles holds the handle of an elevation between the approval's
	// commit and the waiting call picking it up.
	handles map[string]string
}

type liveElevation struct {
	id         string
	approvalID string
	ctx        context.Context
	cancel     context.CancelFunc
	timer      *time.Timer
}

type ticket struct {
	grant     *Grant
	canonical *request.Canonical
	agentKey  string
	expires   time.Time
	timer     *time.Timer
}

// New returns a Point, after expiring every approval left pending by an
// earlier process and re-arming live elevations (docs/02 D15).
func New(ctx context.Context, c Config) (*Point, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	base, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p := &Point{
		cfg: c.Config, db: c.DB, audit: c.Audit, asker: c.Asker, intro: c.Introspector,
		now: c.Now, log: c.Logger, base: base, cancel: cancel,
		waiters:    map[string]chan string{},
		elevations: map[string]*liveElevation{},
		tickets:    map[[32]byte]*ticket{},
		handles:    map[string]string{},
	}
	if err := p.recover(ctx); err != nil {
		cancel()
		return nil, err
	}
	return p, nil
}

// Close ends every live elevation's runs (the process is stopping).
func (p *Point) Close() { p.cancel() }

func (p *Point) recover(ctx context.Context) error {
	now := p.now().UnixMilli()
	rows, err := p.db.QueryContext(ctx, "SELECT id FROM approvals WHERE state = ?", statePending)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		stale = append(stale, id)
	}
	rows.Close()
	for _, id := range stale {
		if _, err := p.db.ExecContext(ctx, "UPDATE approvals SET state = ?, settled_ms = ? WHERE id = ? AND state = ?",
			stateExpired, now, id, statePending); err != nil {
			return err
		}
		_ = p.audit.Append(ctx, audit.Record{Kind: codes.KindApprovalSettled, ApprovalID: id, Code: string(codes.Expired), Detail: "restart"})
		go p.settlePrompt(id, approval.Outcome{Kind: approval.Expired, At: p.now()})
	}

	rows, err = p.db.QueryContext(ctx, "SELECT id, approval_id, expires_ms FROM elevations WHERE state = ?", stateLive)
	if err != nil {
		return err
	}
	type live struct {
		id, approvalID string
		expires        int64
	}
	var lives []live
	for rows.Next() {
		var l live
		if err := rows.Scan(&l.id, &l.approvalID, &l.expires); err != nil {
			rows.Close()
			return err
		}
		lives = append(lives, l)
	}
	rows.Close()
	for _, l := range lives {
		p.arm(l.id, l.approvalID, time.UnixMilli(l.expires))
	}
	return nil
}

// VisibleTargets returns the targets the principal may ask for
// (docs/02 D5).
func (p *Point) VisibleTargets(pr *authn.Principal) []config.Target {
	var out []config.Target
	for _, t := range p.cfg.Targets {
		if t.Visible(pr.Human, pr.ClientID) {
			out = append(out, t)
		}
	}
	return out
}

// RunRequest is one run asked for by an agent.
type RunRequest struct {
	Principal *authn.Principal
	RunID     string
	Target    string
	Canonical *request.Canonical
	Handle    string
	Reason    string
	// Progress, if set, is called while the call waits for an approval
	// (docs/02 D7).
	Progress func(msg string)
}

// NewRunID returns a fresh run ID.
func NewRunID() string { return "run_" + ulid.Make().String() }

func (p *Point) human(pr *authn.Principal) (*config.Human, error) {
	h, ok := p.cfg.HumanByID(pr.Human)
	if !ok {
		return nil, codes.New(codes.Unauthenticated, "unknown human")
	}
	return h, nil
}

func (p *Point) base_(pr *authn.Principal, kind string) audit.Record {
	return audit.Record{Kind: kind, Human: pr.Human, Agent: pr.AgentKey, ClientID: pr.ClientID}
}

// deny audits a denial and returns err. The audit write failing doesn't
// change the answer: it is already no.
func (p *Point) deny(ctx context.Context, r audit.Record, err error) error {
	r.Kind = codes.KindDecision
	r.Decision = codes.Deny
	r.Code = string(codes.Of(err))
	if d := codes.DetailOf(err); d != "" {
		r.Detail = d
	}
	if aerr := p.audit.Append(ctx, r); aerr != nil {
		p.log.Error("audit write failed", "err", aerr)
	}
	return err
}

// DecideRun decides one run (docs/02 §5.3). A nil error comes with a Grant
// for exactly this request; every other outcome is an error, and an error
// is a deny.
func (p *Point) DecideRun(ctx context.Context, r RunRequest) (*Grant, error) {
	pr := r.Principal
	if pr == nil || r.Canonical == nil {
		return nil, codes.New(codes.Internal, "incomplete request")
	}
	h, err := p.human(pr)
	if err != nil {
		return nil, err
	}
	rec := p.base_(pr, codes.KindRunRequested)
	rec.RunID = r.RunID
	rec.Targets = []string{r.Target}
	req := r.Canonical.Audit()
	rec.Request = &req
	rec.Reason = r.Reason
	rec.RunAs = &audit.RunAs{User: h.Kubernetes.User, Groups: h.Kubernetes.Groups}
	if err := p.audit.Append(ctx, rec); err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}

	// 1. Introspect (docs/02 D3).
	if err := p.intro.Introspect(ctx, pr); err != nil {
		if codes.Of(err) != codes.SessionInactive {
			err = codes.Wrap(codes.IntrospectionFailed, err, "could not confirm the session")
		}
		return nil, p.deny(ctx, rec, err)
	}
	// 2. Visibility (docs/02 D5).
	t, ok := p.cfg.TargetByName(r.Target)
	if !ok || !t.Visible(pr.Human, pr.ClientID) {
		return nil, p.deny(ctx, rec, codes.New(codes.TargetNotAllowed, "no such target, or not available to this agent"))
	}
	digest := request.Digest(r.Target, r.Canonical)
	spec := grant.Spec{
		RunID: r.RunID, Target: r.Target,
		RunAs:  approval.Identity{User: h.Kubernetes.User, Groups: h.Kubernetes.Groups},
		Digest: digest, Interactive: r.Canonical.Interactive(),
		Human: pr.Human, AgentKey: pr.AgentKey, ClientID: pr.ClientID,
	}

	// 3. Elevation coverage (docs/02 D9, docs/01 D24).
	notCovered := ""
	if r.Handle != "" {
		g, why, err := p.coveredByElevation(ctx, r, h, spec)
		if err != nil {
			return nil, p.deny(ctx, rec, err)
		}
		if g != nil {
			rec.Kind = codes.KindDecision
			rec.Decision = codes.Allow
			rec.CoveredBy = codes.CoveredElevation
			rec.ElevationID = g.ElevationID()
			if err := p.audit.Append(ctx, rec); err != nil {
				g.Release()
				return nil, codes.Wrap(codes.Unavailable, err, "audit log unavailable")
			}
			return g, nil
		}
		notCovered = why
	}

	// 4. One-off approval (docs/02 D7).
	expires := p.now().Add(p.cfg.Approval.Timeout.D())
	id := "apr_" + ulid.Make().String()
	rec.ApprovalID = id
	rec.Detail = notCovered
	prompt := approval.RunPrompt{
		ID: id, ApproverID: h.TelegramUserID, Target: r.Target,
		RunAs: spec.RunAs,
		Agent: approval.Agent{ClientName: pr.ClientID, KeyShort: p.audit.AgentHash(pr.AgentKey), SignedInAt: pr.SignedInAt},
		Argv:  r.Canonical.DisplayArgv(), Stdin: r.Canonical.DisplayStdin(),
		Interactive: r.Canonical.Interactive(),
		Reason:      r.Reason, ExpiresAt: expires,
	}
	targets, _ := json.Marshal([]string{r.Target})
	state, err := p.ask(ctx, rec, id, "run", h.TelegramUserID, pr, string(targets), digest[:], 0, expires,
		func(ctx context.Context) error { return p.asker.AskRun(ctx, prompt) }, r.Progress)
	if err != nil {
		return nil, p.deny(ctx, rec, err)
	}
	if state != stateApproved {
		return nil, p.deny(ctx, rec, stateError(state))
	}
	if ctx.Err() != nil {
		// Approved, but the call that waited is gone: the approval goes to
		// nobody (docs/01 D24), and the chat says so.
		p.settle(id, stateApproved, stateWithdrawn, nil)
		return nil, p.deny(ctx, rec, codes.New(codes.Withdrawn, "the call ended before the approval arrived"))
	}
	gctx, cancel := context.WithCancel(p.base)
	spec.CoveredBy = codes.CoveredOneOff
	spec.ApprovalID = id
	g := grant.New(gctx, cancel, spec)
	rec.Kind = codes.KindDecision
	rec.Decision = codes.Allow
	rec.CoveredBy = codes.CoveredOneOff
	if err := p.audit.Append(ctx, rec); err != nil {
		g.Release()
		p.settle(id, stateApproved, stateFailed, nil)
		return nil, codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}
	go p.settlePrompt(id, approval.Outcome{Kind: approval.Approved, At: p.now()})
	return g, nil
}

func stateError(state string) error {
	switch state {
	case stateDenied:
		return codes.New(codes.Denied, "the approver denied the request")
	case stateExpired:
		return codes.New(codes.Expired, "nobody answered in time; denied")
	case stateWithdrawn:
		return codes.New(codes.Withdrawn, "the request was withdrawn")
	case stateFailed:
		return codes.New(codes.Unavailable, "the approver could not be asked")
	default:
		return codes.New(codes.Internal, "unexpected approval state")
	}
}

// HashSecret returns the SHA-256 of a handle or ticket.
func HashSecret(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func (p *Point) coveredByElevation(ctx context.Context, r RunRequest, h *config.Human, spec grant.Spec) (*Grant, string, error) {
	if !strings.HasPrefix(r.Handle, handlePrefix) || len(r.Handle) != len(handlePrefix)+43 {
		return nil, "", codes.New(codes.HandleUnknown, "unknown elevation handle")
	}
	hash := HashSecret(r.Handle)
	var (
		id, state, agentKey, human, targetsJSON string
		storedHash                              []byte
		expiresMS                               int64
	)
	err := p.db.QueryRowContext(ctx,
		"SELECT id, state, agent_key, human, targets, handle_hash, expires_ms FROM elevations WHERE handle_hash = ?", hash[:]).
		Scan(&id, &state, &agentKey, &human, &targetsJSON, &storedHash, &expiresMS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", codes.New(codes.HandleUnknown, "unknown elevation handle")
	}
	if err != nil {
		return nil, "", codes.Wrap(codes.Unavailable, err, "state unavailable")
	}
	// A handle stored under another agent key is as unknown as one never
	// issued: it is denied, never turned into a one-off (docs/01 D24).
	if subtle.ConstantTimeCompare(storedHash, hash[:]) != 1 ||
		subtle.ConstantTimeCompare([]byte(agentKey), []byte(r.Principal.AgentKey)) != 1 {
		return nil, "", codes.New(codes.HandleUnknown, "unknown elevation handle")
	}
	var targets []string
	if err := json.Unmarshal([]byte(targetsJSON), &targets); err != nil {
		return nil, "", codes.Wrap(codes.Internal, err, "corrupt elevation")
	}
	expires := time.UnixMilli(expiresMS)
	switch {
	case state != stateLive:
		return nil, "elevation_" + state, nil
	case !p.now().Before(expires):
		return nil, "elevation_expired", nil
	case human != h.ID:
		return nil, "elevation_other_human", nil
	case !slices.Contains(targets, r.Target):
		return nil, "elevation_other_target", nil
	}
	p.mu.Lock()
	le := p.elevations[id]
	p.mu.Unlock()
	if le == nil || le.ctx.Err() != nil {
		return nil, "elevation_ended", nil
	}
	gctx, cancel := context.WithDeadline(le.ctx, expires)
	spec.CoveredBy = codes.CoveredElevation
	spec.ElevationID = id
	spec.NotAfter = expires
	return grant.New(gctx, cancel, spec), "", nil
}

// ask writes a pending approval, sends the prompt and waits until exactly
// one of approve, deny, expire, withdraw or fail settles it. It returns the
// final state.
func (p *Point) ask(ctx context.Context, rec audit.Record, id, kind string, approverID int64, pr *authn.Principal,
	targets string, digest []byte, duration time.Duration, expires time.Time,
	send func(context.Context) error, progress func(string)) (string, error) {
	if !p.asker.Healthy() {
		return "", codes.New(codes.Unavailable, "the approval channel is unavailable")
	}
	ch := make(chan string, 1)
	p.mu.Lock()
	p.waiters[id] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, id)
		p.mu.Unlock()
	}()
	var durMS any
	if duration > 0 {
		durMS = duration.Milliseconds()
	}
	if _, err := p.db.ExecContext(ctx,
		`INSERT INTO approvals (id, kind, state, human, agent_key, approver_id, targets, digest, duration_ms, created_ms, expires_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, kind, statePending, pr.Human, pr.AgentKey, approverID, targets, digest, durMS, p.now().UnixMilli(), expires.UnixMilli()); err != nil {
		return "", codes.Wrap(codes.Unavailable, err, "state unavailable")
	}
	sent := rec
	sent.Kind = codes.KindApprovalSent
	if err := p.audit.Append(ctx, sent); err != nil {
		p.settle(id, statePending, stateFailed, nil)
		return "", codes.Wrap(codes.Unavailable, err, "audit log unavailable")
	}
	if err := send(ctx); err != nil {
		p.settle(id, statePending, stateFailed, nil)
		if codes.Of(err) == codes.InvalidRequest {
			return "", err
		}
		return "", codes.Wrap(codes.Unavailable, err, "the approver could not be asked")
	}

	timer := time.NewTimer(time.Until(expires))
	defer timer.Stop()
	tick := time.NewTicker(progressInterval)
	defer tick.Stop()
	for {
		select {
		case st := <-ch:
			return st, nil
		case <-timer.C:
			if p.settle(id, statePending, stateExpired, nil) {
				return <-ch, nil
			}
			return p.finalState(id, ch), nil
		case <-ctx.Done():
			if p.settle(id, statePending, stateWithdrawn, nil) {
				return <-ch, nil
			}
			return p.finalState(id, ch), nil
		case <-tick.C:
			if progress != nil {
				progress("waiting for the approver")
			}
		}
	}
}

// settle moves approval id from one state to another with a
// compare-and-set. Only the winner acts: it runs inTx in the same
// transaction, notifies the waiter, audits and edits the prompt. A loser
// changes nothing and returns false (CODE-REVIEW.md: one event, one
// authoritative signal).
func (p *Point) settle(id, from, to string, inTx func(*sql.Tx) error) bool {
	ctx, cancel := context.WithTimeout(p.base, 10*time.Second)
	defer cancel()
	ok, err := p.settleTx(ctx, id, from, to, inTx)
	if err != nil {
		p.log.Error("settle failed", "approval", id, "to", to, "err", err)
		if to == stateFailed || to == stateExpired || to == stateWithdrawn {
			// The waiter must still be released; nothing was allowed.
			p.notify(id, stateFailed)
		}
		return false
	}
	if !ok {
		return false
	}
	p.notify(id, to)
	code := map[string]codes.Code{stateApproved: "", stateDenied: codes.Denied, stateExpired: codes.Expired,
		stateWithdrawn: codes.Withdrawn, stateFailed: codes.Unavailable}[to]
	_ = p.audit.Append(ctx, audit.Record{Kind: codes.KindApprovalSettled, ApprovalID: id, Code: string(code), Detail: to})
	kind := map[string]approval.OutcomeKind{stateApproved: approval.Approved, stateDenied: approval.Denied,
		stateExpired: approval.Expired, stateWithdrawn: approval.Withdrawn, stateFailed: approval.Failed}[to]
	// An approved prompt is edited by whoever acts on the approval: the
	// run once its grant exists, the elevation once it is live. Until then
	// the chat must not claim more than happened.
	if to != stateApproved {
		go p.settlePrompt(id, approval.Outcome{Kind: kind, At: p.now()})
	}
	return true
}

func (p *Point) settleTx(ctx context.Context, id, from, to string, inTx func(*sql.Tx) error) (bool, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := p.now().UnixMilli()
	q := "UPDATE approvals SET state = ?, settled_ms = ? WHERE id = ? AND state = ?"
	args := []any{to, now, id, from}
	if to == stateApproved {
		// An approval counts only before it expires (INV-04), checked in
		// the same statement that settles it.
		q += " AND expires_ms > ?"
		args = append(args, now)
	}
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return false, err
	}
	if inTx != nil {
		if err := inTx(tx); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// finalState returns the state an approval was settled to by someone
// else, after this waiter lost the compare-and-set. The winner normally
// notifies; if it was another process (or nothing settled it at all),
// the database is the authority, and anything unclear is a failure.
func (p *Point) finalState(id string, ch chan string) string {
	select {
	case st := <-ch:
		return st
	default:
	}
	var st string
	ctx, cancel := context.WithTimeout(p.base, 5*time.Second)
	defer cancel()
	if err := p.db.QueryRowContext(ctx, "SELECT state FROM approvals WHERE id = ?", id).Scan(&st); err == nil && st != statePending {
		select {
		case notified := <-ch:
			return notified
		default:
		}
		return st
	}
	select {
	case st := <-ch:
		return st
	case <-ctx.Done():
		return stateFailed
	}
}

func (p *Point) notify(id, state string) {
	p.mu.Lock()
	ch := p.waiters[id]
	p.mu.Unlock()
	if ch != nil {
		select {
		case ch <- state:
		default:
		}
	}
}

func (p *Point) settlePrompt(id string, o approval.Outcome) {
	ctx, cancel := context.WithTimeout(p.base, 30*time.Second)
	defer cancel()
	if err := p.asker.Settle(ctx, id, o); err != nil {
		p.log.Warn("could not edit the prompt", "approval", id, "err", err)
	}
}

// Resolve is called by the approval channel for a tap that passed its own
// checks (docs/05 D4). It checks the approver and does the compare-and-set.
func (p *Point) Resolve(ctx context.Context, id string, action approval.Action, approverID int64) (bool, error) {
	var (
		kind, state string
		approver    int64
		expiresMS   int64
	)
	err := p.db.QueryRowContext(ctx, "SELECT kind, state, approver_id, expires_ms FROM approvals WHERE id = ?", id).
		Scan(&kind, &state, &approver, &expiresMS)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if approver != approverID {
		return false, nil
	}
	switch action {
	case approval.ActionApprove:
		if state != statePending || !p.now().Before(time.UnixMilli(expiresMS)) {
			return false, nil
		}
		if kind == "elevation" {
			return p.approveElevation(id)
		}
		return p.settle(id, statePending, stateApproved, nil), nil
	case approval.ActionDeny:
		if state != statePending {
			return false, nil
		}
		return p.settle(id, statePending, stateDenied, nil), nil
	case approval.ActionEnd:
		if kind != "elevation" {
			return false, nil
		}
		var elevID string
		if err := p.db.QueryRowContext(ctx, "SELECT id FROM elevations WHERE approval_id = ?", id).Scan(&elevID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		return p.endElevation(elevID, stateEnded, "ended by the approver"), nil
	default:
		return false, nil
	}
}

func randomSecret(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
