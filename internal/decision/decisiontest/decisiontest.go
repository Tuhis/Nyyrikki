// Package decisiontest makes Grants for tests of packages that consume
// them. It must only be imported from _test.go files; TestOnlyDecisionMakesGrants
// enforces that (docs/02 G7).
package decisiontest

import (
	"context"

	"github.com/Tuhis/Nyyrikki/internal/decision/internal/grant"
)

// Spec is the description of a test grant.
type Spec = grant.Spec

// Grant returns a Grant whose context is derived from ctx.
func Grant(ctx context.Context, s Spec) *grant.Grant {
	ctx, cancel := context.WithCancelCause(ctx)
	return grant.New(ctx, cancel, s)
}

// End ends g's context with cause, as the decision point does for "End
// now" (docs/07 D17).
func End(g *grant.Grant, cause error) { grant.End(g, cause) }
