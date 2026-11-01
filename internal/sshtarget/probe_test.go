package sshtarget

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// probeHost is an sshd stand-in with several ny-* accounts: a user
// certificate from its user CA logs in to an account if it names that
// account's principal, and sshd's own source-address check applies, as
// the certificate's critical option asks (docs/07 D4, D5). It records
// every connection, every public-key attempt per account, and every
// channel or global request: the probe must open none (docs/08 D7).
type probeHost struct {
	t        *testing.T
	ln       net.Listener
	hostKey  ssh.Signer
	present  ssh.Signer // what the host presents: its certificate, usually
	userCA   ssh.PublicKey
	accounts map[string]string // account → principal

	mu       sync.Mutex
	conns    int
	attempts map[string]int // publickey attempts with a signature or query, per account
	logins   map[string]int
	channels int
	requests int
}

func newProbeHost(t *testing.T, userCA ssh.PublicKey, target string, humans ...string) *probeHost {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h := &probeHost{t: t, ln: ln, hostKey: hk, present: hk, userCA: userCA, accounts: map[string]string{},
		attempts: map[string]int{}, logins: map[string]int{}}
	for _, hu := range humans {
		h.accounts["ny-"+hu] = Principal(hu, target)
	}
	return h
}

func (h *probeHost) start() {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			h.mu.Lock()
			h.attempts[md.User()]++
			principal, ok := h.accounts[md.User()]
			h.mu.Unlock()
			cert, isCert := key.(*ssh.Certificate)
			if !ok || !isCert {
				return nil, fmt.Errorf("refused")
			}
			chk := &ssh.CertChecker{
				IsUserAuthority:          func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), h.userCA.Marshal()) },
				SupportedCriticalOptions: []string{"source-address"},
			}
			if err := chk.CheckCert(principal, cert); err != nil {
				return nil, err
			}
			// The server enforces source-address from these permissions.
			return &cert.Permissions, nil
		},
		AuthLogCallback: func(md ssh.ConnMetadata, method string, err error) {
			if method == "publickey" && err == nil {
				h.mu.Lock()
				h.logins[md.User()]++
				h.mu.Unlock()
			}
		},
	}
	cfg.AddHostKey(h.present)
	go func() {
		for {
			c, err := h.ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns++
			h.mu.Unlock()
			go func() {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go func() {
					for r := range reqs {
						h.mu.Lock()
						h.requests++
						h.mu.Unlock()
						if r.WantReply {
							r.Reply(false, nil)
						}
					}
				}()
				for nch := range chans {
					h.mu.Lock()
					h.channels++
					h.mu.Unlock()
					nch.Reject(ssh.Prohibited, "no")
				}
			}()
		}
	}()
}

func (h *probeHost) stats() (conns, channels, requests int, attempts map[string]int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := map[string]int{}
	for k, v := range h.attempts {
		a[k] = v
	}
	return h.conns, h.channels, h.requests, a
}

// probeEnv is a runner for db-1 with a user CA and a host-ca, and a host
// with a certificate enrollment would have issued.
type probeEnv struct {
	runner *Runner
	host   *probeHost
	set    *sshca.Set
	issued *ssh.Certificate
	keys   *sshca.Keys
}

func newProbeEnv(t *testing.T, sources []string, humans []string, mod func(*probeEnv, *Target)) *probeEnv {
	t.Helper()
	ca := newTestCA(t)
	hostPEM, _, err := sshca.GenerateKey("nyyrikki-host-ca")
	if err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(t.TempDir(), "host-ca")
	if err := os.WriteFile(hostFile, hostPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := sshca.New(sshca.Options{Files: sshca.Files{UserCA: ca.file, HostCA: hostFile}})
	set, err := keys.Load()
	if err != nil {
		t.Fatal(err)
	}
	h := newProbeHost(t, ca.signer.PublicKey(), "db-1", humans...)
	issued, err := set.SignHostCert(sshca.HostCert{Key: h.hostKey.PublicKey(), Target: "db-1", Host: "db-1.example.com",
		Validity: time.Hour, SessionKill: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(issued, h.hostKey)
	if err != nil {
		t.Fatal(err)
	}
	h.present = cs
	e := &probeEnv{host: h, set: set, issued: issued, keys: keys}
	tg := Target{Name: "db-1", Address: h.ln.Addr().String(), Host: "db-1.example.com"}
	if mod != nil {
		mod(e, &tg)
	}
	h.start()
	r, err := NewRunner(RunnerConfig{
		Targets: map[string]Target{"db-1": tg}, CA: NewCA(keys, sources, nil), ConnectTimeout: 5 * time.Second,
		Limits: Limits{DefaultTimeout: 10 * time.Second, MaxTimeout: time.Minute, MaxInteractive: time.Minute, MaxOutput: 1 << 20},
		Audit:  &recAudit{}, Logger: newTestLogger(&bytes.Buffer{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.runner = r
	return e
}

type probeAudit struct {
	mu      sync.Mutex
	serials []string
	fail    bool
}

func (a *probeAudit) before(_, _, serial string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return codes.New(codes.Unavailable, "audit down")
	}
	a.serials = append(a.serials, serial)
	return nil
}

// TestEnrollProbeOK covers docs/08 D7 (G7): the probe checks the host
// presents the certificate just issued and logs in once as each
// account, opening no channel and sending no request.
func TestEnrollProbeOK(t *testing.T) {
	e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner", "alice"}, nil)
	a := &probeAudit{}
	got, err := e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner", "alice"}, a.before)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (ProbeAccount{"owner", "ny-owner", ProbeOK, a.serials[0]}) || got[1] != (ProbeAccount{"alice", "ny-alice", ProbeOK, a.serials[1]}) {
		t.Fatalf("results %+v", got)
	}
	time.Sleep(50 * time.Millisecond) // let the host's goroutines record
	conns, channels, requests, _ := e.host.stats()
	e.host.mu.Lock()
	logins := map[string]int{"ny-owner": e.host.logins["ny-owner"], "ny-alice": e.host.logins["ny-alice"]}
	e.host.mu.Unlock()
	if conns != 2 || channels != 0 || requests != 0 || logins["ny-owner"] != 1 || logins["ny-alice"] != 1 {
		t.Fatalf("conns %d, channels %d, requests %d, logins %v", conns, channels, requests, logins)
	}
}

// TestEnrollProbeRefused covers docs/08 D7 and M5 (G7): with the wrong
// ssh.source_addresses, the first account is refused, the probe stops
// there, and only one connection, with one login attempt, reached the
// host.
func TestEnrollProbeRefused(t *testing.T) {
	e := newProbeEnv(t, []string{"203.0.113.10/32"}, []string{"owner", "alice", "bob"}, nil)
	a := &probeAudit{}
	got, err := e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner", "alice", "bob"}, a.before)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Status != ProbeRefused || got[1].Status != ProbeNotChecked || got[2].Status != ProbeNotChecked ||
		got[1].CertSerial != "" || len(a.serials) != 1 {
		t.Fatalf("results %+v, audited %v", got, a.serials)
	}
	time.Sleep(50 * time.Millisecond)
	conns, channels, _, attempts := e.host.stats()
	if conns != 1 || channels != 0 || attempts["ny-owner"] != 1 || attempts["ny-alice"] != 0 || attempts["ny-bob"] != 0 {
		t.Fatalf("conns %d, channels %d, attempts %v", conns, channels, attempts)
	}

	// A missing principals file (no such account on the host) is a
	// refusal too, after the accounts before it logged in.
	e = newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, nil)
	got, err = e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner", "alice", "bob"}, (&probeAudit{}).before)
	if err != nil || got[0].Status != ProbeOK || got[1].Status != ProbeRefused || got[2].Status != ProbeNotChecked {
		t.Fatalf("results %+v %v", got, err)
	}
}

// TestEnrollProbeHostRefused: a host that presents something other than
// the certificate just issued is never authenticated to; nor is one that
// can't be reached; and the probe's audit failing stops it before the
// host is dialled.
func TestEnrollProbeHostRefused(t *testing.T) {
	t.Run("another certificate", func(t *testing.T) {
		var other *ssh.Certificate
		e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, func(e *probeEnv, _ *Target) {
			var err error
			other, err = e.set.SignHostCert(sshca.HostCert{Key: e.host.hostKey.PublicKey(), Target: "db-1", Host: "db-1.example.com",
				Validity: time.Hour, Now: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
		})
		// The host presents e.issued; the probe is told another was issued.
		_, err := e.runner.Probe(t.Context(), "db-1", other, []string{"owner"}, (&probeAudit{}).before)
		wantCode(t, err, codes.Unavailable, DetailHostCertMismatch)
		_, _, _, attempts := e.host.stats()
		if attempts["ny-owner"] != 0 {
			t.Fatal("authenticated to a host that failed the check")
		}
	})
	t.Run("plain key", func(t *testing.T) {
		e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, func(e *probeEnv, _ *Target) { e.host.present = e.host.hostKey })
		_, err := e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner"}, (&probeAudit{}).before)
		if codes.Of(err) != codes.Unavailable {
			t.Fatalf("err %v", err)
		}
		if _, _, _, attempts := e.host.stats(); attempts["ny-owner"] != 0 {
			t.Fatal("authenticated")
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, func(e *probeEnv, tg *Target) {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			tg.Address = ln.Addr().String()
			ln.Close()
		})
		_, err := e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner"}, (&probeAudit{}).before)
		wantCode(t, err, codes.Unavailable, DetailHostUnreachable)
	})
	t.Run("audit fails", func(t *testing.T) {
		e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, nil)
		_, err := e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner"}, (&probeAudit{fail: true}).before)
		if codes.Of(err) != codes.Unavailable {
			t.Fatalf("err %v", err)
		}
		if conns, _, _, _ := e.host.stats(); conns != 0 {
			t.Fatal("dialled without an audit record")
		}
	})
	t.Run("host key revoked", func(t *testing.T) {
		e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, nil)
		e.runner.revoked = []ssh.PublicKey{e.host.hostKey.PublicKey()}
		_, err := e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner"}, (&probeAudit{}).before)
		wantCode(t, err, codes.Unavailable, DetailHostKeyRevoked)
	})
	t.Run("pinned target", func(t *testing.T) {
		// A pinned target is checked for its enrolled certificate all the
		// same (docs/08 SE4 keeps runs on the pin).
		e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, func(e *probeEnv, tg *Target) {
			tg.HostKeys = []ssh.PublicKey{e.host.hostKey.PublicKey()}
		})
		got, err := e.runner.Probe(t.Context(), "db-1", e.issued, []string{"owner"}, (&probeAudit{}).before)
		if err != nil || got[0].Status != ProbeOK {
			t.Fatalf("results %+v %v", got, err)
		}
	})
}

// TestEnrollCertVerifies covers docs/08 G7 with SE4's verifier: the
// certificate enrollment issues verifies its target, with the facts it
// states, and no other target, even at the same address.
func TestEnrollCertVerifies(t *testing.T) {
	e := newProbeEnv(t, []string{"127.0.0.1/32"}, []string{"owner"}, nil)
	own := e.set.HostCA.PublicKey()
	now := time.Now
	db1 := newHostVerifier(Target{Name: "db-1", Host: "db-1.example.com"}, own, nil, now)
	facts, err := db1.verify(nil, e.issued)
	if err != nil || !facts.SessionKill {
		t.Fatalf("db-1: %+v %v", facts, err)
	}
	for _, tg := range []Target{{Name: "db-2", Host: "db-1.example.com"}, {Name: "db-1", Host: "db-2.example.com"}} {
		if _, err := newHostVerifier(tg, own, nil, now).verify(nil, e.issued); err == nil {
			t.Fatalf("accepted for %+v", tg)
		}
	}
	// Without the extension, session_kill reads false.
	plain, _ := e.set.SignHostCert(sshca.HostCert{Key: e.host.hostKey.PublicKey(), Target: "db-1", Host: "db-1.example.com", Validity: time.Hour, Now: time.Now()})
	if facts, err := db1.verify(nil, plain); err != nil || facts.SessionKill {
		t.Fatalf("no extension: %+v %v", facts, err)
	}
}
