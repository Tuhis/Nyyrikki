package sshtarget

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// ownHostCA is Nyyrikki's host CA (docs/08 D1): a key file next to the
// user CA's, loaded with it on each use.
type ownHostCA struct {
	signer ssh.Signer
	file   string
}

// withOwnHostCA writes a host-ca key file and makes cfg's CA load it
// with the harness's user CA.
func withOwnHostCA(t *testing.T, cfg *RunnerConfig, userCAFile string) *ownHostCA {
	t.Helper()
	pemBytes, _, err := sshca.GenerateKey("nyyrikki-host-ca")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "host-ca")
	if err := os.WriteFile(file, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := sshca.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CA = NewCA(sshca.New(sshca.Options{Files: sshca.Files{UserCA: userCAFile, HostCA: file}}), []string{"127.0.0.1/32"}, nil)
	return &ownHostCA{signer: s, file: file}
}

// hostCert is the certificate docs/08 D8 describes for target db-1,
// signed by signer, changed by mod.
func hostCert(t *testing.T, key ssh.PublicKey, signer ssh.Signer, mod func(*ssh.Certificate)) *ssh.Certificate {
	t.Helper()
	now := time.Now()
	c := &ssh.Certificate{
		Key: key, CertType: ssh.HostCert, KeyId: HostCertKeyID("db-1"),
		ValidPrincipals: []string{"db-1.example.com"},
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{SessionKillExtension: ""}},
	}
	if mod != nil {
		mod(c)
	}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return c
}

// unpinned leaves db-1 with no pins and no host CAs of its own.
func unpinned(cfg *RunnerConfig) {
	tg := cfg.Targets["db-1"]
	tg.HostKeys, tg.HostCAs = nil, nil
	cfg.Targets["db-1"] = tg
}

// TestHostKeyOwnCA covers docs/08 D9 (G8) for Nyyrikki's own host CA: a
// certificate it signed, naming the host and the target in its key ID,
// valid now, is accepted for a target with only an address; one for
// another target, another host, an expired one, one for a key that
// isn't ed25519, and one whose key or CA is revoked are refused before
// authentication.
func TestHostKeyOwnCA(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaSigner, _ := ssh.NewSignerFromKey(ecdsaKey)
	cases := map[string]struct {
		cert   func(*fakeHost, *ownHostCA) *ssh.Certificate
		mod    func(*RunnerConfig, *fakeHost, *ownHostCA)
		detail string
	}{
		"valid": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, nil)
		}},
		"key ID of another target": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, func(c *ssh.Certificate) { c.KeyId = HostCertKeyID("db-2") })
		}, detail: DetailHostKeyMismatch},
		"key ID not Nyyrikki's": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, func(c *ssh.Certificate) { c.KeyId = "db-1" })
		}, detail: DetailHostKeyMismatch},
		"another host": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"db-2.example.com"} })
		}, detail: DetailHostKeyMismatch},
		"expired": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, func(c *ssh.Certificate) { c.ValidBefore = uint64(time.Now().Add(-time.Minute).Unix()) })
		}, detail: DetailHostKeyMismatch},
		"no principals": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, func(c *ssh.Certificate) { c.ValidPrincipals = nil })
		}, detail: DetailHostKeyMismatch},
		"not ed25519": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			h.hostKey = ecdsaSigner
			return hostCert(t, ecdsaSigner.PublicKey(), o.signer, nil)
		}, detail: DetailHostKeyMismatch},
		"signed by another key": {cert: func(h *fakeHost, _ *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), newSigner(t), nil)
		}, detail: DetailHostKeyMismatch},
		"host key revoked": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, nil)
		}, mod: func(c *RunnerConfig, h *fakeHost, _ *ownHostCA) {
			c.RevokedHostKeys = []ssh.PublicKey{h.hostKey.PublicKey()}
		}, detail: DetailHostKeyRevoked},
		"host-ca revoked": {cert: func(h *fakeHost, o *ownHostCA) *ssh.Certificate {
			return hostCert(t, h.hostKey.PublicKey(), o.signer, nil)
		}, mod: func(c *RunnerConfig, _ *fakeHost, o *ownHostCA) {
			c.RevokedHostKeys = []ssh.PublicKey{o.signer.PublicKey()}
		}, detail: DetailHostKeyRevoked},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(cfg *RunnerConfig, host *fakeHost) {
				o := withOwnHostCA(t, cfg, host.userCAFile)
				unpinned(cfg)
				host.hostCert = c.cert(host, o)
				if c.mod != nil {
					c.mod(cfg, host, o)
				}
			})
			req := build(t, []string{"echo", "x"}, nil, false)
			_, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0)
			_, cerr := h.runner.CheckHost(t.Context(), "db-1")
			if c.detail == "" {
				if err != nil || cerr != nil {
					t.Fatalf("refused a valid certificate: run %v, check %v", err, cerr)
				}
				return
			}
			wantCode(t, err, codes.Unavailable, c.detail)
			wantCode(t, cerr, codes.Unavailable, c.detail)
			if h.host.loginCount() != 0 {
				t.Fatal("authenticated to an unverified host")
			}
		})
	}
}

// TestHostKeyOwnCAWithPins: a pinned target is verified by its pins as
// before docs/08, also when Nyyrikki has a host CA: the host presents
// its plain key, and session_kill is the config value.
func TestHostKeyOwnCAWithPins(t *testing.T) {
	h := newHarness(t, func(cfg *RunnerConfig, host *fakeHost) {
		withOwnHostCA(t, cfg, host.userCAFile)
		tg := cfg.Targets["db-1"]
		tg.SessionKill = true
		cfg.Targets["db-1"] = tg
	})
	facts, err := h.runner.CheckHost(t.Context(), "db-1")
	if err != nil || !facts.SessionKill {
		t.Fatalf("check: %+v %v", facts, err)
	}
	req := build(t, []string{"echo", "x"}, nil, false)
	if _, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0); err != nil {
		t.Fatal(err)
	}
}

// TestHostKeySessionKill covers docs/08 D9 (G8): session_kill is read
// from a certificate of Nyyrikki's own host CA (the extension present
// with an empty value), and only from one: for an organisation's host
// CA, with or without the extension, and for a pin, it is the target's
// config value.
func TestHostKeySessionKill(t *testing.T) {
	orgCA := newSigner(t)
	withExt := func(c *ssh.Certificate) {}
	noExt := func(c *ssh.Certificate) { c.Extensions = nil }
	valued := func(c *ssh.Certificate) { c.Extensions = map[string]string{SessionKillExtension: "<b>yes</b>"} }
	cases := map[string]struct {
		own    bool                   // signed by host-ca, else by orgCA
		cert   func(*ssh.Certificate) // nil: the host is pinned
		config bool
		want   bool
	}{
		"own, extension, config false":      {own: true, cert: withExt, config: false, want: true},
		"own, no extension, config true":    {own: true, cert: noExt, config: true, want: false},
		"own, extension with a value":       {own: true, cert: valued, config: false, want: false},
		"org CA, extension, config false":   {cert: withExt, config: false, want: false},
		"org CA, no extension, config true": {cert: noExt, config: true, want: true},
		"pinned, config true":               {config: true, want: true},
		"pinned, config false":              {config: false, want: false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(cfg *RunnerConfig, host *fakeHost) {
				o := withOwnHostCA(t, cfg, host.userCAFile)
				tg := cfg.Targets["db-1"]
				tg.SessionKill = c.config
				if c.cert != nil {
					tg.HostKeys = nil
					signer := orgCA
					if c.own {
						signer = o.signer
					} else {
						tg.HostCAs = []ssh.PublicKey{orgCA.PublicKey()}
					}
					host.hostCert = hostCert(t, host.hostKey.PublicKey(), signer, c.cert)
				}
				cfg.Targets["db-1"] = tg
			})
			facts, err := h.runner.CheckHost(t.Context(), "db-1")
			if err != nil || facts.SessionKill != c.want {
				t.Fatalf("check: session_kill %v, err %v; want %v", facts.SessionKill, err, c.want)
			}
		})
	}
}

// TestHostCheckNoAuth covers docs/08 D10 (G9): the host check verifies
// the host and reads its facts without authenticating. The in-process
// host records every authentication attempt, of any method; after
// checks that succeed and checks that fail, it has recorded none, no
// login and no session request. A run against the same host does
// authenticate, so the counter counts.
func TestHostCheckNoAuth(t *testing.T) {
	for name, mod := range map[string]func(*RunnerConfig, *fakeHost){
		"pinned": nil,
		"own certificate": func(cfg *RunnerConfig, host *fakeHost) {
			o := withOwnHostCA(t, cfg, host.userCAFile)
			unpinned(cfg)
			host.hostCert = hostCert(t, host.hostKey.PublicKey(), o.signer, nil)
		},
		"mismatch": func(cfg *RunnerConfig, _ *fakeHost) {
			tg := cfg.Targets["db-1"]
			tg.HostKeys = []ssh.PublicKey{newSigner(t).PublicKey()}
			cfg.Targets["db-1"] = tg
		},
		"revoked": func(cfg *RunnerConfig, host *fakeHost) {
			cfg.RevokedHostKeys = []ssh.PublicKey{host.hostKey.PublicKey()}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mod)
			for range 3 {
				_, _ = h.runner.CheckHost(t.Context(), "db-1")
			}
			if n := h.host.authCount(); n != 0 {
				t.Fatalf("the host check made %d authentication attempts", n)
			}
			if h.host.loginCount() != 0 || len(h.host.allEvents()) != 0 {
				t.Fatal("the host check logged in or opened a session")
			}
			if len(h.audit.kinds()) != 0 {
				t.Fatalf("the check wrote %v; the decision point audits it", h.audit.kinds())
			}
			if name != "pinned" && name != "own certificate" {
				return
			}
			req := build(t, []string{"echo", "x"}, nil, false)
			if _, err := h.runner.Run(grantFor(t.Context(), req, nil), req, 0); err != nil {
				t.Fatal(err)
			}
			if h.host.authCount() == 0 {
				t.Fatal("a run authenticated without the host counting it: the counter is broken")
			}
		})
	}
}

// TestHostCheckFailures covers docs/08 D10 (G9) for every way the check
// fails, each failing closed with its detail: an unreachable host, a
// host that never answers within connect_timeout, a target nothing can
// verify (never dialled), an unknown target, and a broken or revoked CA
// key file (docs/08 D1; never dialled).
func TestHostCheckFailures(t *testing.T) {
	dialled := false
	cases := map[string]struct {
		mod    func(*RunnerConfig, *fakeHost)
		target string
		code   codes.Code
		detail string
		noDial bool
	}{
		"unreachable": {mod: func(c *RunnerConfig, _ *fakeHost) {
			c.Dial = func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: net.ErrClosed}
			}
		}, detail: DetailHostUnreachable},
		"refused": {mod: func(c *RunnerConfig, _ *fakeHost) {
			// Nothing listens there any more.
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			tg := c.Targets["db-1"]
			tg.Address = ln.Addr().String()
			ln.Close()
			c.Targets["db-1"] = tg
		}, detail: DetailHostUnreachable},
		"silent host": {mod: func(c *RunnerConfig, _ *fakeHost) {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					t.Cleanup(func() { conn.Close() })
				}
			}()
			tg := c.Targets["db-1"]
			tg.Address = ln.Addr().String()
			c.Targets["db-1"] = tg
			c.ConnectTimeout = 300 * time.Millisecond
		}, detail: DetailHostUnreachable},
		"not pinned": {mod: func(c *RunnerConfig, _ *fakeHost) {
			unpinned(c)
			c.Dial = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, net.ErrClosed }
		}, detail: DetailHostNotPinned, noDial: true},
		"unknown target": {target: "db-9", detail: DetailUnknownTarget, noDial: true},
		"broken host-ca": {mod: func(c *RunnerConfig, host *fakeHost) {
			o := withOwnHostCA(t, c, host.userCAFile)
			os.WriteFile(o.file, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nhalf written"), 0o600)
			c.Dial = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, net.ErrClosed }
		}, detail: sshca.DetailUnreadable, noDial: true},
		"host-ca not ed25519": {mod: func(c *RunnerConfig, host *fakeHost) {
			o := withOwnHostCA(t, c, host.userCAFile)
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			block, _ := ssh.MarshalPrivateKey(k, "")
			os.WriteFile(o.file, pem.EncodeToMemory(block), 0o600)
			c.Dial = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, net.ErrClosed }
		}, detail: sshca.DetailUnreadable, noDial: true},
		"user-ca unreadable": {mod: func(c *RunnerConfig, _ *fakeHost) {
			c.CA = NewCA(userCA("/nonexistent/user-ca"), []string{"127.0.0.1/32"}, nil)
			c.Dial = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, net.ErrClosed }
		}, detail: sshca.DetailUnreadable, noDial: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dialled = false
			h := newHarness(t, c.mod)
			tgt := c.target
			if tgt == "" {
				tgt = "db-1"
			}
			start := time.Now()
			_, err := h.runner.CheckHost(t.Context(), tgt)
			wantCode(t, err, codes.Unavailable, c.detail)
			if c.noDial && dialled {
				t.Fatal("dialled")
			}
			if time.Since(start) > 4*time.Second {
				t.Fatalf("the check took %v", time.Since(start))
			}
			if h.host.authCount() != 0 {
				t.Fatal("authenticated")
			}
		})
	}
}

// TestSSHRunHostChanged covers docs/08 D10 (G9): a run whose approver
// was shown that the host finishes cuts is refused as host_changed when
// the host, verified again at dial time, no longer says so, before
// authentication, and audited. A host that still says so, or a run
// whose approver was shown the warning, runs.
func TestSSHRunHostChanged(t *testing.T) {
	cases := map[string]struct {
		shown, ext bool
		ok         bool
	}{
		"shown true, now false":  {shown: true, ext: false, ok: false},
		"shown true, still true": {shown: true, ext: true, ok: true},
		"shown false, now false": {shown: false, ext: false, ok: true},
		"shown false, now true":  {shown: false, ext: true, ok: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(cfg *RunnerConfig, host *fakeHost) {
				o := withOwnHostCA(t, cfg, host.userCAFile)
				unpinned(cfg)
				host.hostCert = hostCert(t, host.hostKey.PublicKey(), o.signer, func(cert *ssh.Certificate) {
					if !c.ext {
						cert.Extensions = nil
					}
				})
			})
			req := build(t, []string{"echo", "x"}, nil, false)
			g := grantFor(t.Context(), req, func(s *decisiontest.Spec) { s.SessionKillShown = c.shown })
			_, err := h.runner.Run(g, req, 0)
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantCode(t, err, codes.Unavailable, DetailHostChanged)
			if h.host.loginCount() != 0 || h.host.authCount() != 0 || len(h.host.allEvents()) != 0 {
				t.Fatal("authenticated to, or ran on, a changed host")
			}
			if rec, ok := h.audit.last(codes.KindDependencyFailed); !ok || rec.Detail != DetailHostChanged || rec.CertSerial == "" {
				t.Fatalf("audit %+v", rec)
			}
		})
	}
	// Interactive runs are held to the same.
	h := newHarness(t, func(cfg *RunnerConfig, host *fakeHost) {
		o := withOwnHostCA(t, cfg, host.userCAFile)
		unpinned(cfg)
		host.hostCert = hostCert(t, host.hostKey.PublicKey(), o.signer, func(cert *ssh.Certificate) { cert.Extensions = nil })
	})
	req := build(t, nil, nil, true)
	g := grantFor(t.Context(), req, func(s *decisiontest.Spec) { s.SessionKillShown = true })
	_, err := h.runner.RunInteractive(g, req, newFakeTerm())
	wantCode(t, err, codes.Unavailable, DetailHostChanged)
}
