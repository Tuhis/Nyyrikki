// Package grant defines the Grant type. It is internal to the decision
// package tree, so only internal/decision (and its test helper) can make
// one (docs/02 D6, G7).
package grant

import (
	"context"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
)

// Spec is what a Grant is made from.
type Spec struct {
	RunID       string
	Target      string
	RunAs       approval.Identity
	Digest      [32]byte
	CoveredBy   string
	ApprovalID  string
	ElevationID string
	NotAfter    time.Time
	Interactive bool
	// SessionKillShown is whether the approver was shown that the host
	// finishes cuts (docs/08 D10). A run whose host no longer shows it
	// is refused as host_changed.
	SessionKillShown bool
	Human            string
	AgentKey         string
	ClientID         string
}

// Grant is the decision point's permission to run exactly one canonical
// request on one target. Its context ends when whatever covers it ends.
type Grant struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	spec   Spec
}

// New makes a Grant. ctx must end when the grant's cover ends, and
// cancel must end ctx with the cause it is given.
func New(ctx context.Context, cancel context.CancelCauseFunc, s Spec) *Grant {
	s.RunAs.Groups = append([]string(nil), s.RunAs.Groups...)
	return &Grant{ctx: ctx, cancel: cancel, spec: s}
}

// End ends g's context with cause, which the runner reads back with
// context.Cause to say why the run was cut. It is a function of this
// internal package, so only the decision point can call it.
func End(g *Grant, cause error) {
	if g.cancel != nil {
		g.cancel(cause)
	}
}

// Context ends when what covers the grant ends (elevation expiry or end,
// or the release of a one-off grant).
func (g *Grant) Context() context.Context { return g.ctx }

// Release ends the grant's context. The runner calls it when the run is
// over; calling it more than once is harmless.
func (g *Grant) Release() {
	if g.cancel != nil {
		g.cancel(nil)
	}
}

func (g *Grant) RunID() string  { return g.spec.RunID }
func (g *Grant) Target() string { return g.spec.Target }

// RunAs returns the human's identity on the target, from the registry.
func (g *Grant) RunAs() approval.Identity {
	return approval.Identity{User: g.spec.RunAs.User, Groups: append([]string(nil), g.spec.RunAs.Groups...)}
}

// Digest is the request digest the approval or elevation covers
// (docs/04 §5.3).
func (g *Grant) Digest() [32]byte    { return g.spec.Digest }
func (g *Grant) CoveredBy() string   { return g.spec.CoveredBy }
func (g *Grant) ApprovalID() string  { return g.spec.ApprovalID }
func (g *Grant) ElevationID() string { return g.spec.ElevationID }

// NotAfter is the latest time the run may last until (the elevation's
// expiry); zero for a one-off grant, whose limit is the run's own.
func (g *Grant) NotAfter() time.Time { return g.spec.NotAfter }
func (g *Grant) Interactive() bool   { return g.spec.Interactive }

// SessionKillShown is whether the approver was shown that the target's
// host finishes cuts (docs/08 D10); the SSH runner refuses a host that
// now shows less.
func (g *Grant) SessionKillShown() bool { return g.spec.SessionKillShown }
func (g *Grant) Human() string          { return g.spec.Human }
func (g *Grant) AgentKey() string       { return g.spec.AgentKey }
func (g *Grant) ClientID() string       { return g.spec.ClientID }
