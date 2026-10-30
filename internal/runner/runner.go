// Package runner hands a Grant and its request to the runner of the
// request's target type (docs/07 §5.2). It decides nothing: the request
// is the one the decision point bound the Grant to, and each runner
// checks the Grant's digest again before it reaches its target.
package runner

import (
	"time"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/sshtarget"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// Runners holds one runner per target type. SSH is nil when no target is
// an SSH target.
type Runners struct {
	Kubernetes *kubectl.Runner
	SSH        *sshtarget.Runner
}

// Run runs a non-interactive request. g is released on every path.
func (r Runners) Run(g *decision.Grant, req target.Request, timeout time.Duration) (*target.Result, error) {
	switch c := req.(type) {
	case *request.Canonical:
		if r.Kubernetes != nil {
			return r.Kubernetes.Run(g, c, timeout)
		}
	case *sshtarget.Request:
		if r.SSH != nil {
			return r.SSH.Run(g, c, timeout)
		}
	}
	return nil, noRunner(g)
}

// RunInteractive runs an interactive request. g is released on every
// path.
func (r Runners) RunInteractive(g *decision.Grant, req target.Request, term target.Terminal) (int, error) {
	switch c := req.(type) {
	case *request.Canonical:
		if r.Kubernetes != nil {
			return r.Kubernetes.RunInteractive(g, c, term)
		}
	case *sshtarget.Request:
		if r.SSH != nil {
			return r.SSH.RunInteractive(g, c, term)
		}
	}
	return -1, noRunner(g)
}

func noRunner(g *decision.Grant) error {
	if g != nil {
		g.Release()
	}
	return codes.New(codes.Internal, "no runner for this request's target type")
}
