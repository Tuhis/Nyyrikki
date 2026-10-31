package sshtarget

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSSHRun covers docs/07 D9, D10: the command runs as the account,
// with stdin, and the exit status, stdout and stderr come back as sent.
func TestSSHRun(t *testing.T) {
	h := newHarness(t, nil)
	req := build(t, []string{"echo", "hello"}, nil, false)
	res, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
	if err != nil || res.ExitCode != 0 || string(res.Stdout) != "hello\n" {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if got := h.audit.kinds(); len(got) != 2 || got[0] != codes.KindRunStarted || got[1] != codes.KindRunFinished {
		t.Fatalf("audit kinds %v", got)
	}
	start, _ := h.audit.last(codes.KindRunStarted)
	fin, _ := h.audit.last(codes.KindRunFinished)
	if start.CertSerial == "" || start.CertSerial != fin.CertSerial || start.RunAs.User != "ny-owner" || start.Request.Command != "echo hello" {
		t.Errorf("run_started %+v", start)
	}
	h.host.mu.Lock()
	cert := h.host.certs[0]
	h.host.mu.Unlock()
	if cert.KeyId != "nyyrikki:run_test" || start.CertSerial != itoa(cert.Serial) {
		t.Errorf("the host saw key ID %q serial %d; audit says %s", cert.KeyId, cert.Serial, start.CertSerial)
	}

	req = build(t, []string{"fail"}, nil, false)
	res, err = h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
	if err != nil || res.ExitCode != 3 || string(res.Stderr) != "it failed\n" {
		t.Fatalf("fail = %+v, %v", res, err)
	}
	req = build(t, []string{"cat"}, []byte("in\x00put"), false)
	res, err = h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
	if err != nil || string(res.Stdout) != "in\x00put" {
		t.Fatalf("cat = %+v, %v", res, err)
	}
	// docs/07 D9: an exit signal is 128 plus its number, named in detail.
	req = build(t, []string{"die"}, nil, false)
	res, err = h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
	if err != nil || res.ExitCode != 128+11 || res.Detail != "signal: SEGV" {
		t.Fatalf("die = %+v, %v", res, err)
	}
	req = build(t, []string{"noexit"}, nil, false)
	res, err = h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
	if res == nil || res.ExitCode != -1 {
		t.Fatalf("noexit = %+v", res)
	}
	wantCode(t, err, codes.Unavailable, DetailConnectionLost)
}

func itoa(u uint64) string {
	b := []byte{}
	for u > 0 || len(b) == 0 {
		b = append([]byte{byte('0' + u%10)}, b...)
		u /= 10
	}
	return string(b)
}

// TestSSHRunDigestMismatch covers G2: the runner refuses a Grant whose
// digest differs, for a different account, command or interactive flag,
// before anything is dialled.
func TestSSHRunDigestMismatch(t *testing.T) {
	h := newHarness(t, nil)
	req := build(t, []string{"echo", "hi"}, nil, false)
	cases := map[string]func(*decisiontest.Spec){
		"other command": func(s *decisiontest.Spec) {
			s.Digest = build(t, []string{"echo", "ho"}, nil, false).Digest("db-1", "ny-owner")
		},
		"other account": func(s *decisiontest.Spec) { s.RunAs.User = "ny-root" },
		"other target":  func(s *decisiontest.Spec) { s.Target = "db-2" },
		"interactive":   func(s *decisiontest.Spec) { s.Interactive = true },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := h.runner.Run(grantFor(t.Context(), req, mod), req, 0)
			if codes.Of(err) != codes.Internal {
				t.Fatalf("err %v", err)
			}
		})
	}
	if h.host.loginCount() != 0 || len(h.host.allEvents()) != 0 {
		t.Fatal("a mismatched grant reached the host")
	}
}

// TestHostKeyPinned covers docs/07 D8 (G4): a host key that matches no
// pin is refused before authentication, and audited.
func TestHostKeyPinned(t *testing.T) {
	h := newHarness(t, func(c *RunnerConfig, _ *fakeHost) {
		tg := c.Targets["db-1"]
		tg.HostKeys = []ssh.PublicKey{newSigner(t).PublicKey()}
		c.Targets["db-1"] = tg
	})
	req := build(t, []string{"echo", "x"}, nil, false)
	_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
	wantCode(t, err, codes.Unavailable, DetailHostKeyMismatch)
	if h.host.loginCount() != 0 {
		t.Fatal("authenticated to an unverified host")
	}
	if rec, ok := h.audit.last(codes.KindDependencyFailed); !ok || rec.Detail != DetailHostKeyMismatch {
		t.Fatalf("audit %+v", rec)
	}
}

// TestHostKeyNotPinned covers docs/07 §5.5: a target without pins or
// CAs is unavailable, and never dialled.
func TestHostKeyNotPinned(t *testing.T) {
	dialled := false
	h := newHarness(t, func(c *RunnerConfig, _ *fakeHost) {
		tg := c.Targets["db-1"]
		tg.HostKeys = nil
		c.Targets["db-1"] = tg
		c.Dial = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, net.ErrClosed }
	})
	req := build(t, []string{"echo", "x"}, nil, false)
	_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
	wantCode(t, err, codes.Unavailable, DetailHostNotPinned)
	if dialled {
		t.Fatal("dialled a host that isn't pinned")
	}
}

// TestHostKeyCertificate covers docs/07 D8 (G4): a host certificate from
// a host CA, valid now, naming the host, is accepted; an expired one, one
// for another host name, one without principals, a user certificate and
// one from an unknown CA are refused before authentication.
func TestHostKeyCertificate(t *testing.T) {
	hostCA := newSigner(t)
	now := time.Now()
	mk := func(mod func(*ssh.Certificate), signer ssh.Signer) func(*fakeHost) {
		return func(h *fakeHost) {
			c := &ssh.Certificate{
				Key: h.hostKey.PublicKey(), CertType: ssh.HostCert, KeyId: "db-1",
				ValidPrincipals: []string{"db-1.example.com"},
				ValidAfter:      uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix()),
			}
			if mod != nil {
				mod(c)
			}
			if err := c.SignCert(rand.Reader, signer); err != nil {
				t.Fatal(err)
			}
			h.hostCert = c
		}
	}
	cases := map[string]struct {
		host func(*fakeHost)
		ok   bool
	}{
		"valid":         {mk(nil, hostCA), true},
		"expired":       {mk(func(c *ssh.Certificate) { c.ValidBefore = uint64(now.Add(-time.Minute).Unix()) }, hostCA), false},
		"not yet valid": {mk(func(c *ssh.Certificate) { c.ValidAfter = uint64(now.Add(time.Hour).Unix()) }, hostCA), false},
		"other host":    {mk(func(c *ssh.Certificate) { c.ValidPrincipals = []string{"db-2.example.com"} }, hostCA), false},
		"no principals": {mk(func(c *ssh.Certificate) { c.ValidPrincipals = nil }, hostCA), false},
		"user cert":     {mk(func(c *ssh.Certificate) { c.CertType = ssh.UserCert }, hostCA), false},
		"unknown CA":    {mk(nil, newSigner(t)), false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(cfg *RunnerConfig, host *fakeHost) {
				c.host(host)
				tg := cfg.Targets["db-1"]
				tg.HostKeys = nil
				tg.HostCAs = []ssh.PublicKey{hostCA.PublicKey()}
				cfg.Targets["db-1"] = tg
			})
			req := build(t, []string{"echo", "x"}, nil, false)
			_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
			if c.ok {
				if err != nil {
					t.Fatalf("refused a valid host certificate: %v", err)
				}
				return
			}
			wantCode(t, err, codes.Unavailable, DetailHostKeyMismatch)
			if h.host.loginCount() != 0 {
				t.Fatal("authenticated to an unverified host")
			}
		})
	}
	// A pin alone doesn't accept a certificate: with no host CA, the
	// runner doesn't even offer certificate algorithms.
	h := newHarness(t, func(_ *RunnerConfig, host *fakeHost) { mk(nil, hostCA)(host) })
	req := build(t, []string{"echo", "x"}, nil, false)
	if _, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0); codes.Of(err) != codes.Unavailable {
		t.Fatalf("a certificate-only host with only a pin: %v", err)
	}
}

// TestHostKeyRevoked covers docs/08 D9 (G8, the revocation part): a key
// in revoked_host_keys is refused before authentication, with detail
// host_key_revoked, whether the host presents it plainly (a pin), as its
// certificate's key, or as the key that signed its certificate. An
// unrelated revoked key changes nothing.
func TestHostKeyRevoked(t *testing.T) {
	hostCA := newSigner(t)
	now := time.Now()
	certify := func(h *fakeHost) {
		c := &ssh.Certificate{
			Key: h.hostKey.PublicKey(), CertType: ssh.HostCert, KeyId: "db-1",
			ValidPrincipals: []string{"db-1.example.com"},
			ValidAfter:      uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}
		if err := c.SignCert(rand.Reader, hostCA); err != nil {
			t.Fatal(err)
		}
		h.hostCert = c
	}
	viaCA := func(cfg *RunnerConfig) {
		tg := cfg.Targets["db-1"]
		tg.HostKeys = nil
		tg.HostCAs = []ssh.PublicKey{hostCA.PublicKey()}
		cfg.Targets["db-1"] = tg
	}
	cases := map[string]struct {
		mod func(*RunnerConfig, *fakeHost)
		ok  bool
	}{
		"pinned key revoked": {func(cfg *RunnerConfig, h *fakeHost) {
			cfg.RevokedHostKeys = []ssh.PublicKey{h.hostKey.PublicKey()}
		}, false},
		"certificate's key revoked": {func(cfg *RunnerConfig, h *fakeHost) {
			certify(h)
			viaCA(cfg)
			cfg.RevokedHostKeys = []ssh.PublicKey{h.hostKey.PublicKey()}
		}, false},
		"signing CA revoked": {func(cfg *RunnerConfig, h *fakeHost) {
			certify(h)
			viaCA(cfg)
			cfg.RevokedHostKeys = []ssh.PublicKey{hostCA.PublicKey()}
		}, false},
		"other key revoked, pinned": {func(cfg *RunnerConfig, _ *fakeHost) {
			cfg.RevokedHostKeys = []ssh.PublicKey{newSigner(t).PublicKey()}
		}, true},
		"other key revoked, certified": {func(cfg *RunnerConfig, h *fakeHost) {
			certify(h)
			viaCA(cfg)
			cfg.RevokedHostKeys = []ssh.PublicKey{newSigner(t).PublicKey()}
		}, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, c.mod)
			req := build(t, []string{"echo", "x"}, nil, false)
			_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			wantCode(t, err, codes.Unavailable, DetailHostKeyRevoked)
			if h.host.loginCount() != 0 {
				t.Fatal("authenticated to a revoked host")
			}
			if rec, ok := h.audit.last(codes.KindDependencyFailed); !ok || rec.Detail != DetailHostKeyRevoked {
				t.Fatalf("audit %+v", rec)
			}
		})
	}
}

// TestSSHRunRequests covers G5: no env request is ever sent; pty-req
// only for an interactive run, with a checked TERM.
func TestSSHRunRequests(t *testing.T) {
	h := newHarness(t, nil)
	req := build(t, []string{"echo", "x"}, nil, false)
	if _, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0); err != nil {
		t.Fatal(err)
	}
	if got := h.host.allEvents(); len(got) != 1 || got[0] != "exec" {
		t.Fatalf("non-interactive requests %v", got)
	}
	for term, want := range map[string]string{"": DefaultTerm, "screen-256color": "screen-256color", "x;rm -rf /": DefaultTerm, "VT100": DefaultTerm} {
		h := newHarness(t, nil)
		req := build(t, nil, nil, true)
		ft := newFakeTerm()
		ft.term = term
		done := make(chan error, 1)
		go func() { _, err := h.runner.RunInteractive(grantFor(t.Context(), req, nil), req, ft); done <- err }()
		ft.waitFor(t, "READY")
		ft.inW.Write([]byte("exit 0\n"))
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		ev := h.host.allEvents()
		if len(ev) < 2 || ev[0] != "pty-req" || ev[1] != "shell" {
			t.Fatalf("interactive requests %v", ev)
		}
		for _, e := range ev {
			if e == "env" {
				t.Fatal("an env request was sent")
			}
		}
		if got := sshString(h.host.eventsOf("pty-req")[0].Payload); got != want {
			t.Errorf("TERM %q sent as %q, want %q", term, got, want)
		}
	}
}

// TestSSHRunInteractive covers D9: a login shell or a command on a pty,
// bytes both ways, resizes, exit status.
func TestSSHRunInteractive(t *testing.T) {
	h := newHarness(t, nil)
	req := build(t, nil, nil, true)
	ft := newFakeTerm()
	ft.resizes <- targetSize(120, 50)
	done := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		c, err := h.runner.RunInteractive(grantFor(t.Context(), req, nil), req, ft)
		done <- struct {
			code int
			err  error
		}{c, err}
	}()
	ft.waitFor(t, "READY")
	ft.resizes <- targetSize(100, 40)
	ft.inW.Write([]byte("hello\n"))
	ft.waitFor(t, "got:hello")
	ft.inW.Write([]byte("exit 5\n"))
	r := <-done
	if r.err != nil || r.code != 5 {
		t.Fatalf("RunInteractive = %d, %v", r.code, r.err)
	}
	pty := h.host.eventsOf("pty-req")[0].Payload
	var p struct {
		Term             string
		Cols, Rows, W, H uint32
		Modes            string
	}
	if err := ssh.Unmarshal(pty, &p); err != nil || p.Cols != 120 || p.Rows != 50 {
		t.Fatalf("pty-req %+v %v", p, err)
	}
	if len(h.host.eventsOf("window-change")) == 0 {
		t.Error("the resize never reached the host")
	}
	h.host.mu.Lock()
	cert := h.host.certs[0]
	h.host.mu.Unlock()
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("an interactive run's certificate lacks permit-pty")
	}
}

// TestSSHCut covers docs/07 D11 (G6, unit): a cut sends TERM, then KILL
// after the grace period if the session hasn't ended, then closes; a
// command that ends on TERM gets no KILL. Each cause is named.
func TestSSHCut(t *testing.T) {
	t.Run("TERM ends it", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"sleep"}, nil, false)
		ctx, cancel := context.WithCancel(t.Context())
		g := grantFor(ctx, req, nil)
		done := make(chan error, 1)
		go func() { _, err := h.runner.Run(g, req, 0); done <- err }()
		waitEvent(t, h.host, "exec")
		cancel()
		wantCode(t, <-done, codes.Expired, DetailGrantEnded)
		if len(h.host.eventsOf("got-TERM")) != 1 || len(h.host.eventsOf("got-KILL")) != 0 {
			t.Fatalf("signals %v", h.host.allEvents())
		}
		if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.Detail != DetailGrantEnded || rec.CertSerial == "" {
			t.Fatalf("run_cut %+v", rec)
		}
	})
	t.Run("ignores TERM", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"ignore-term"}, nil, false)
		g := grantFor(t.Context(), req, nil)
		done := make(chan error, 1)
		go func() { _, err := h.runner.Run(g, req, 0); done <- err }()
		waitEvent(t, h.host, "exec")
		// Past the exec reply: the cut is wait's, with its KILL.
		time.Sleep(100 * time.Millisecond)
		decisiontest.End(g, decision.ErrEndedByApprover)
		wantCode(t, <-done, codes.Expired, decision.DetailEndedByApprover)
		term, kill := h.host.eventsOf("got-TERM"), h.host.eventsOf("got-KILL")
		if len(term) != 1 || len(kill) != 1 {
			t.Fatalf("signals %v", h.host.allEvents())
		}
		if gap := kill[0].At.Sub(term[0].At); gap < h.runner.cutGrace-50*time.Millisecond {
			t.Errorf("KILL came %v after TERM, before the grace period", gap)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"sleep"}, nil, false)
		_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 300*time.Millisecond)
		wantCode(t, err, codes.Expired, DetailTimeout)
	})
	t.Run("elevation expiry", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"sleep"}, nil, false)
		g := grantFor(t.Context(), req, func(s *decisiontest.Spec) {
			s.CoveredBy, s.ApprovalID, s.ElevationID = codes.CoveredElevation, "", "elv_x"
			s.NotAfter = time.Now().Add(300 * time.Millisecond)
		})
		res, err := h.runner.Run(g, req, 0)
		wantCode(t, err, codes.Expired, DetailGrantExpired)
		if res == nil || string(res.Stdout) != "started\n" {
			t.Fatalf("a cut run keeps its output: %+v", res)
		}
	})
	t.Run("interactive client gone", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"sleep"}, nil, true)
		ft := newFakeTerm()
		done := make(chan error, 1)
		go func() { _, err := h.runner.RunInteractive(grantFor(t.Context(), req, nil), req, ft); done <- err }()
		ft.waitFor(t, "started")
		ft.close()
		wantCode(t, <-done, codes.Expired, DetailClientGone)
		if len(h.host.eventsOf("got-TERM")) != 1 {
			t.Fatalf("signals %v", h.host.allEvents())
		}
	})
	t.Run("ended before dialling", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"echo", "x"}, nil, false)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := h.runner.Run(grantFor(ctx, req, nil), req, 0)
		wantCode(t, err, codes.Expired, DetailGrantEnded)
		if h.host.loginCount() != 0 {
			t.Fatal("dialled after the grant ended")
		}
	})
	// Review round 1, finding 5: a cut that lands after the command has
	// started but before wait takes over is still a cut, named by its
	// cause, not a lost connection.
	t.Run("cut between start and handoff", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"sleep"}, nil, false)
		g := grantFor(t.Context(), req, nil)
		h.runner.afterStart = func(c *conn) {
			waitEvent(t, h.host, "exec")
			decisiontest.End(g, decision.ErrEndedByApprover)
			waitEvent(t, h.host, "got-TERM")
		}
		_, err := h.runner.Run(g, req, 0)
		wantCode(t, err, codes.Expired, decision.DetailEndedByApprover)
		if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.Detail != decision.DetailEndedByApprover || rec.CertSerial == "" {
			t.Fatalf("run_cut %+v", rec)
		}
	})
	// Review round 2, finding 4: a cut while the exec reply is awaited may
	// follow a command that started, so it is a cut run, not "nothing ran".
	t.Run("cut while the exec reply is awaited", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"stall-reply"}, nil, false)
		g := grantFor(t.Context(), req, nil)
		done := make(chan struct{})
		var res *target.Result
		var err error
		go func() { res, err = h.runner.Run(g, req, 0); close(done) }()
		waitEvent(t, h.host, "exec")
		decisiontest.End(g, decision.ErrEndedByApprover)
		<-done
		wantCode(t, err, codes.Expired, decision.DetailEndedByApprover)
		if res == nil || res.ExitCode != -1 {
			t.Fatalf("result %+v", res)
		}
		if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.ExitCode == nil || *rec.ExitCode != -1 {
			t.Fatalf("run_cut %+v", rec)
		}
	})
	// Review round 1, finding 5: End now before the command is sent is
	// named as such, not as a grant that ended (D17).
	t.Run("ended by the approver before dialling", func(t *testing.T) {
		h := newHarness(t, nil)
		req := build(t, []string{"echo", "x"}, nil, false)
		g := grantFor(t.Context(), req, nil)
		decisiontest.End(g, decision.ErrEndedByApprover)
		_, err := h.runner.Run(g, req, 0)
		wantCode(t, err, codes.Expired, decision.DetailEndedByApprover)
		if rec, ok := h.audit.last(codes.KindDecision); !ok || rec.Detail != decision.DetailEndedByApprover {
			t.Fatalf("refusal record %+v", rec)
		}
		if h.host.loginCount() != 0 {
			t.Fatal("dialled after the approver ended it")
		}
	})
}

func waitEvent(t *testing.T, h *fakeHost, typ string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.eventsOf(typ)) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the host never got %s", typ)
}

// TestSSHDependencyFailures covers docs/07 §6: unreachable host, refused
// authentication, refused session, and an audit log that can't record
// the start each end in unavailable before the command is sent.
func TestSSHDependencyFailures(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		h := newHarness(t, func(c *RunnerConfig, _ *fakeHost) {
			c.Dial = func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: net.ErrClosed}
			}
		})
		req := build(t, []string{"echo", "x"}, nil, false)
		_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
		wantCode(t, err, codes.Unavailable, DetailUnreachable)
	})
	t.Run("auth refused", func(t *testing.T) {
		h := newHarness(t, func(_ *RunnerConfig, host *fakeHost) { host.principal = "nyyrikki:owner@db-2" })
		req := build(t, []string{"echo", "x"}, nil, false)
		_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
		wantCode(t, err, codes.Unavailable, DetailAuthRefused)
	})
	t.Run("wrong CA", func(t *testing.T) {
		h := newHarness(t, func(_ *RunnerConfig, host *fakeHost) { host.userCA = newSigner(t).PublicKey() })
		req := build(t, []string{"echo", "x"}, nil, false)
		_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
		wantCode(t, err, codes.Unavailable, DetailAuthRefused)
	})
	t.Run("session refused", func(t *testing.T) {
		h := newHarness(t, func(_ *RunnerConfig, host *fakeHost) { host.noSession = true })
		req := build(t, []string{"echo", "x"}, nil, false)
		_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
		wantCode(t, err, codes.Unavailable, DetailSessionRefused)
		if len(h.host.eventsOf("exec")) != 0 {
			t.Fatal("the command was sent")
		}
	})
	t.Run("audit down", func(t *testing.T) {
		h := newHarness(t, nil)
		h.audit.fail = func(r audit.Record) bool { return r.Kind == codes.KindRunStarted }
		req := build(t, []string{"echo", "x"}, nil, false)
		_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
		if codes.Of(err) != codes.Unavailable {
			t.Fatalf("err %v", err)
		}
		if h.host.loginCount() != 0 {
			t.Fatal("dialled without a run_started record")
		}
	})
	t.Run("CA unreadable", func(t *testing.T) {
		h := newHarness(t, func(c *RunnerConfig, _ *fakeHost) {
			c.CA = NewCA("/nonexistent/user-ca", nil, []string{"127.0.0.1/32"}, nil)
		})
		req := build(t, []string{"echo", "x"}, nil, false)
		_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
		wantCode(t, err, codes.Unavailable, DetailCAUnreadable)
		if rec, ok := h.audit.last(codes.KindDependencyFailed); !ok || rec.Detail != DetailCAUnreadable {
			t.Fatalf("audit %+v", rec)
		}
	})
}

// TestSSHNeverLeaksKey covers G3: the CA key, the run's certificate and
// its key appear in no audit record, log line, result or error.
func TestSSHNeverLeaksKey(t *testing.T) {
	h := newHarness(t, nil)
	var outputs []string
	for _, args := range [][]string{{"echo", "x"}, {"fail"}, {"noexit"}} {
		req := build(t, args, nil, false)
		res, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
		if res != nil {
			outputs = append(outputs, string(res.Stdout), string(res.Stderr), res.Detail)
		}
		if err != nil {
			outputs = append(outputs, err.Error())
		}
	}
	h2 := newHarness(t, func(_ *RunnerConfig, host *fakeHost) { host.principal = "x" })
	req := build(t, []string{"echo"}, nil, false)
	if _, err := h2.runner.Run(grantFor(t.Context(), req, nil), req, 0); err != nil {
		outputs = append(outputs, err.Error())
	}
	h.host.mu.Lock()
	certs := append([]*ssh.Certificate(nil), h.host.certs...)
	h.host.mu.Unlock()
	everything := strings.Join(append(outputs, h.audit.json(), h.logs.String(), h2.audit.json(), h2.logs.String()), "\n")
	if leaks(everything, h.ca.pem, h2.ca.pem) {
		t.Fatal("CA key material leaked")
	}
	for _, c := range certs {
		for _, b := range [][]byte{c.Marshal(), c.Key.Marshal(), c.Signature.Blob} {
			enc := base64.StdEncoding.EncodeToString(b)
			if strings.Contains(everything, enc[:24]) {
				t.Fatal("certificate or run key leaked")
			}
		}
	}
}
