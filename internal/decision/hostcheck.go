package decision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
)

// HostFacts are what a host check read about an SSH host (docs/08 D9,
// D10): from a certificate Nyyrikki's own host CA signed, or else from
// the target's config.
type HostFacts struct {
	SessionKill bool
}

// HostChecker is the host check of docs/08 D10: dial an SSH target's
// host, verify it, read its facts and disconnect without
// authenticating. It decides nothing: its answer is input to the
// decision point, which alone allows or denies. An error is a
// *codes.Error with codes.Unavailable and the check's detail.
type HostChecker interface {
	CheckHost(ctx context.Context, target string) (HostFacts, error)
}

// DetailHostCheckUnavailable is the detail of a check that could not run
// at all: no checker is configured although an SSH target exists.
const DetailHostCheckUnavailable = "host_check_unavailable"

// detailElevationHostFacts is why an elevation doesn't cover a run on an
// SSH target whose shown facts can't be found: the run falls back to a
// one-off approval, with a check of its own.
const detailElevationHostFacts = "elevation_host_facts_missing"

// maxParallelChecks bounds the host checks of one elevation.
const maxParallelChecks = 4

// checkHost runs the host check of one SSH target and audits it as part
// of the request rec records (docs/08 §6). checkErr is a failed check;
// auditErr a failed audit write, which denies whatever asked: nothing is
// shown that the log doesn't hold.
func (p *Point) checkHost(ctx context.Context, rec audit.Record, target string) (facts HostFacts, checkErr, auditErr error) {
	var err error
	if p.hosts == nil {
		err = codes.WithDetail(codes.Unavailable, DetailHostCheckUnavailable, "the SSH host check is not available")
	} else {
		facts, err = p.hosts.CheckHost(ctx, target)
		if err != nil && (codes.Of(err) != codes.Unavailable || codes.DetailOf(err) == "") {
			// The checker's contract is broken: still a failed check.
			err = codes.WithDetail(codes.Unavailable, DetailHostCheckUnavailable, "the SSH host check failed")
		}
	}
	r := rec
	r.Kind = codes.KindHostChecked
	r.Targets = []string{target}
	r.Decision = ""
	if err != nil {
		r.Code, r.Detail = string(codes.Unavailable), codes.DetailOf(err)
	} else if facts.SessionKill {
		r.Detail = "session_kill"
	} else {
		r.Detail = "no_session_kill"
	}
	if aerr := p.audit.Append(ctx, r); aerr != nil {
		return HostFacts{}, nil, codes.Wrap(codes.Unavailable, aerr, "audit log unavailable")
	}
	if err != nil {
		return HostFacts{}, err, nil
	}
	return facts, nil, nil
}

// hostCheck is one SSH target's check for an elevation.
type hostCheck struct {
	facts HostFacts
	err   error
}

// checkHosts runs the checks of an elevation's SSH targets in parallel,
// at most maxParallelChecks at a time. An audit failure is returned as
// auditErr: the elevation is then denied, unlike a failed check, which
// only shows a warning (docs/08 D10).
func (p *Point) checkHosts(ctx context.Context, rec audit.Record, targets []*config.Target) (out []hostCheck, auditErr error) {
	out = make([]hostCheck, len(targets))
	sem := make(chan struct{}, maxParallelChecks)
	done := make(chan struct{})
	auditErrs := make([]error, len(targets))
	for i, t := range targets {
		go func() {
			sem <- struct{}{}
			defer func() { <-sem; done <- struct{}{} }()
			facts, err, aerr := p.checkHost(ctx, rec, t.Name)
			auditErrs[i] = aerr
			out[i] = hostCheck{facts: facts, err: err}
		}()
	}
	for range targets {
		<-done
	}
	for _, err := range auditErrs {
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// elevationFacts reads what an elevation's approver was shown about its
// SSH targets: target → session_kill shown (docs/08 D10). ok is false
// when nothing was stored for the approval.
func (p *Point) elevationFacts(ctx context.Context, approvalID string) (map[string]bool, bool, error) {
	var raw string
	err := p.db.QueryRowContext(ctx, "SELECT facts FROM approval_host_facts WHERE approval_id = ?", approvalID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, codes.Wrap(codes.Unavailable, err, "state unavailable")
	}
	var m map[string]bool
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, false, codes.Wrap(codes.Internal, err, "corrupt elevation")
	}
	return m, true, nil
}
