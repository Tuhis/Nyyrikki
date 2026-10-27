// Package authn checks tokens and DPoP proofs (docs/01 D9, docs/02 D2).
package authn

import (
	"context"
	"time"
)

// Principal is the authenticated caller of one request: the human from
// the registry and the agent key (docs/01 D8). Nothing downstream of the
// middleware reads a header; it reads this.
type Principal struct {
	// Human is the human registry id.
	Human string
	// Subject is the token's sub.
	Subject string
	// AgentKey identifies the agent: (issuer, azp, cnf.jkt) for the CLI,
	// (issuer, azp, sid) for MCP clients. Never logged in clear
	// (docs/03 D3).
	AgentKey string
	// ClientID is the token's azp.
	ClientID string
	// SignedInAt is the sign-in time (auth_time, else iat).
	SignedInAt time.Time
	// JKT is cnf.jkt, empty for tokens that aren't DPoP-bound.
	JKT string

	token string
}

// Token returns the raw access token, for introspection only. It must
// never be logged, audited, returned or forwarded.
func (p *Principal) Token() string { return p.token }

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the request's principal.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok && p != nil
}

// NewPrincipalForTest returns a Principal with the given raw token.
func NewPrincipalForTest(p Principal, token string) *Principal {
	p.token = token
	return &p
}

// Introspector checks that a principal's session is live (docs/02 D3).
// Any error is a deny.
type Introspector interface {
	Introspect(ctx context.Context, p *Principal) error
}
