package sshtarget

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// What the probe found for one account (docs/08 D7).
const (
	ProbeOK         = "ok"
	ProbeRefused    = "refused"
	ProbeNotChecked = "not_checked" // after the first refusal (M5)
)

// DetailHostCertMismatch: the host doesn't present the certificate the
// enrollment just issued (docs/08 D7).
const DetailHostCertMismatch = "host_cert_mismatch"

// ProbeAccount is the probe's answer for one human's account.
type ProbeAccount struct {
	Human   string
	Account string
	Status  string
	// CertSerial is the serial of the run certificate it presented, in
	// decimal; empty when not checked.
	CertSerial string
}

// errProbeCertMismatch: the host presented another key or certificate.
var errProbeCertMismatch = errors.New("sshtarget: the host doesn't present the enrolled certificate")

// Probe is the check after an enrollment (docs/08 D7): for each human
// of the target in turn, it dials the host, checks that the host
// presents exactly issued, which must also pass host verification as
// Nyyrikki's own certificate for this target (docs/08 D9), and
// authenticates once as the human's account with a run certificate
// (docs/07 D5). It opens no channel: once authenticated, it disconnects,
// so nothing runs. It stops at the first refusal, so that a wrong
// source address trips sshd's PerSourcePenalties once (M5); the
// accounts after it are ProbeNotChecked. beforeAuth is called with each
// certificate's serial before the host is dialled for it, to audit the
// credential first; its error stops the probe. A host that can't be
// reached, or presents anything else, is a *codes.Error with
// codes.Unavailable and detail host_unreachable, host_cert_mismatch or
// host_key_revoked, returned with the accounts checked so far.
func (r *Runner) Probe(ctx context.Context, name string, issued *ssh.Certificate, humans []string,
	beforeAuth func(human, account, serial string) error) ([]ProbeAccount, error) {
	t, ok := r.targets[name]
	if !ok {
		return nil, codes.WithDetail(codes.Unavailable, DetailUnknownTarget, "the target is not configured")
	}
	if issued == nil || beforeAuth == nil {
		return nil, codes.New(codes.Internal, "incomplete probe")
	}
	set, err := r.ca.load()
	if err != nil {
		return nil, err
	}
	own := hostCA(set)
	if own == nil {
		return nil, codes.WithDetail(codes.Unavailable, sshca.DetailHostCAAbsent, "there is no SSH host CA key (host-ca)")
	}
	// The enrolled certificate is checked whatever else verifies the
	// target: a pinned target accepts no certificate (docs/08 SE4), but
	// its enrollment is checked all the same.
	pt := t
	pt.HostKeys, pt.HostCAs = nil, nil
	hv := newHostVerifier(pt, own, r.revoked, r.now)
	want := issued.Marshal()

	out := make([]ProbeAccount, len(humans))
	for i, h := range humans {
		out[i] = ProbeAccount{Human: h, Account: config.SSHAccount(h), Status: ProbeNotChecked}
	}
	for i := range out {
		a := &out[i]
		id, err := probeID()
		if err != nil {
			return out, codes.Wrap(codes.Unavailable, err, "could not make the probe's ID")
		}
		cert, err := r.ca.mint(set, id, a.Human, name, false)
		if err != nil {
			return out, err
		}
		a.CertSerial = strconv.FormatUint(cert.Serial, 10)
		if err := beforeAuth(a.Human, a.Account, a.CertSerial); err != nil {
			a.CertSerial = ""
			return out, err
		}
		status, err := r.probeOne(ctx, t, a.Account, cert, hv, want)
		if err != nil {
			return out, err
		}
		a.Status = status
		if status == ProbeRefused {
			break
		}
	}
	return out, nil
}

// probeOne authenticates once as account and disconnects.
func (r *Runner) probeOne(ctx context.Context, t Target, account string, cert *Cert, hv *hostVerifier, want []byte) (string, error) {
	fail := func(detail, msg string, err error) (string, error) {
		e := codes.WithDetail(codes.Unavailable, detail, "%s", msg)
		e.Err = err
		return "", e
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
		hostErr  error
		verified bool
	)
	cfg := &ssh.ClientConfig{
		User: account,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(cert.signer)},
		HostKeyCallback: func(_ string, a net.Addr, k ssh.PublicKey) error {
			mu.Lock()
			defer mu.Unlock()
			if _, err := hv.verify(a, k); err != nil {
				hostErr = err
				return err
			}
			if !bytes.Equal(k.Marshal(), want) {
				hostErr = errProbeCertMismatch
				return hostErr
			}
			verified = true
			return nil
		},
		// Only the certificate enrollment issued can match.
		HostKeyAlgorithms: []string{ssh.CertAlgoED25519v01},
		Timeout:           r.connectTimeout,
	}
	sc, _, _, err := ssh.NewClientConn(nc, t.Address, cfg)
	mu.Lock()
	defer mu.Unlock()
	switch {
	case err == nil && verified:
		// Authenticated. No channel is opened, no request sent.
		_ = sc.Close()
		return ProbeOK, nil
	case err == nil:
		_ = sc.Close()
		return fail(DetailHostCertMismatch, "the host check completed without verifying the host", nil)
	case errors.Is(hostErr, errHostKeyRevoked):
		return fail(DetailHostKeyRevoked, "the host's key is listed in ssh.revoked_host_keys", err)
	case hostErr != nil:
		return fail(DetailHostCertMismatch, "the host doesn't present the certificate just issued", err)
	case verified && isAuthError(err):
		return ProbeRefused, nil
	default:
		return fail(DetailHostUnreachable, "the SSH handshake with the host failed", err)
	}
}

// probeID names a probe's certificate: key ID nyyrikki:chk_<hex>, as a
// run's is nyyrikki:<run id> (docs/07 D5).
func probeID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "chk_" + hex.EncodeToString(b[:]), nil
}
