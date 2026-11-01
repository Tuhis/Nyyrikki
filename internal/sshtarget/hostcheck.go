package sshtarget

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
)

// errCheckDone is what the host check's host-key callback returns once it
// has verified the host and read its facts. Returning an error from the
// callback ends the handshake inside key exchange, before the client
// asks for the ssh-userauth service, so no authentication request, not
// even "none", is ever sent (docs/08 D10).
var errCheckDone = errors.New("sshtarget: host check done")

// checkUser is the user name in the check's client config. It is never
// sent: authentication doesn't start.
const checkUser = "nyyrikki-host-check"

// CheckHost is the host check of docs/08 D10: it dials target's host
// within ssh.connect_timeout, completes key exchange, verifies the host
// as a run would (docs/08 D9), reads its facts, and disconnects without
// authenticating. Nothing is presented and nothing runs: what the host
// sees is a key exchange, as from ssh-keyscan. A failure is a
// *codes.Error with codes.Unavailable and one of the details
// host_unreachable, host_key_mismatch, host_key_revoked,
// host_not_pinned, unknown_target, or the CA loader's (a broken host-ca
// file fails closed, docs/08 D1). It decides nothing: the decision point
// reads its answer.
func (r *Runner) CheckHost(ctx context.Context, name string) (decision.HostFacts, error) {
	t, ok := r.targets[name]
	if !ok {
		return decision.HostFacts{}, codes.WithDetail(codes.Unavailable, DetailUnknownTarget, "the target is not configured")
	}
	set, err := r.ca.load()
	if err != nil {
		return decision.HostFacts{}, err
	}
	hv := newHostVerifier(t, hostCA(set), r.revoked, r.now)
	set = nil
	if !hv.anyTrust() {
		return decision.HostFacts{}, errNotPinned()
	}
	fail := func(detail, msg string, err error) (decision.HostFacts, error) {
		e := codes.WithDetail(codes.Unavailable, detail, "%s", msg)
		e.Err = err
		return decision.HostFacts{}, e
	}

	dctx, cancel := context.WithTimeout(ctx, r.connectTimeout)
	defer cancel()
	nc, err := r.dial(dctx, "tcp", t.Address)
	if err != nil {
		return fail(DetailHostUnreachable, "the host could not be reached", err)
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(r.connectTimeout))
	stop := context.AfterFunc(dctx, func() { _ = nc.Close() })
	defer stop()

	var (
		mu       sync.Mutex
		verified bool
		facts    decision.HostFacts
		vErr     error
	)
	cfg := &ssh.ClientConfig{
		User: checkUser,
		// No method: even if the callback's error were ignored, there
		// would be no credential to present.
		Auth: nil,
		HostKeyCallback: func(_ string, a net.Addr, k ssh.PublicKey) error {
			f, err := hv.verify(a, k)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				vErr = err
				return err
			}
			verified, facts = true, f
			return errCheckDone
		},
		HostKeyAlgorithms: hv.algorithms(t.HostKeys),
		Timeout:           r.connectTimeout,
	}
	sc, _, _, err := ssh.NewClientConn(nc, t.Address, cfg)
	if err == nil {
		// Can't happen: the callback never returns nil. Fail closed.
		_ = sc.Close()
		return fail(DetailHostKeyMismatch, "the host check completed a handshake it must abort", nil)
	}
	mu.Lock()
	defer mu.Unlock()
	switch {
	case verified:
		return facts, nil
	case errors.Is(vErr, errHostKeyRevoked):
		return fail(DetailHostKeyRevoked, "the host's key is listed in ssh.revoked_host_keys", err)
	case vErr != nil:
		return fail(DetailHostKeyMismatch, "the host's key matches no pin and no host CA", err)
	default:
		return fail(DetailHostUnreachable, "the SSH handshake with the host failed", err)
	}
}
