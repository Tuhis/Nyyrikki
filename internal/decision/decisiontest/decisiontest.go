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
	ctx, cancel := context.WithCancel(ctx)
	return grant.New(ctx, cancel, s)
}
