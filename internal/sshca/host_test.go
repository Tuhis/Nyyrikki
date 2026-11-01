package sshca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestEnrollHostCertFields covers docs/08 D8 (G7): exactly the fields
// D8 names, signed by host-ca, and the extension only when asked for.
func TestEnrollHostCertFields(t *testing.T) {
	dir := t.TempDir()
	user, host := newKey(t, dir, KeyUserCA), newKey(t, dir, KeyHostCA)
	set, err := New(Options{Files: Files{UserCA: user.file, HostCA: host.file}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	hk := hostKey(t)
	for _, kill := range []bool{true, false} {
		c, err := set.SignHostCert(HostCert{Key: hk, Target: "db-1", Host: "db-1.example.com", Validity: 43800 * time.Hour, SessionKill: kill, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if c.CertType != ssh.HostCert || !bytes.Equal(c.Key.Marshal(), hk.Marshal()) ||
			len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != "db-1.example.com" ||
			c.KeyId != "nyyrikki-host:db-1" ||
			c.ValidAfter != uint64(now.Add(-5*time.Minute).Unix()) || c.ValidBefore != uint64(now.Add(43800*time.Hour).Unix()) ||
			len(c.CriticalOptions) != 0 || !bytes.Equal(c.SignatureKey.Marshal(), host.pub.Marshal()) {
			t.Fatalf("certificate %+v", c)
		}
		if v, ok := c.Extensions[SessionKillExtension]; ok != kill || v != "" || len(c.Extensions) != map[bool]int{true: 1, false: 0}[kill] {
			t.Fatalf("session_kill %v: extensions %v", kill, c.Extensions)
		}
		chk := &ssh.CertChecker{IsHostAuthority: func(a ssh.PublicKey, _ string) bool { return bytes.Equal(a.Marshal(), host.pub.Marshal()) },
			Clock: func() time.Time { return now }}
		if err := chk.CheckHostKey("db-1.example.com:22", nil, c); err != nil {
			t.Fatalf("not a valid host certificate: %v", err)
		}
	}
	// Two certificates never share a serial (random, 64 bits).
	a, _ := set.SignHostCert(HostCert{Key: hk, Target: "db-1", Host: "h", Validity: time.Hour, Now: now})
	b, _ := set.SignHostCert(HostCert{Key: hk, Target: "db-1", Host: "h", Validity: time.Hour, Now: now})
	if a.Serial == b.Serial {
		t.Fatal("serial repeated")
	}
}

// TestEnrollHostCertRefused: no host-ca, or a key D8 doesn't enroll,
// signs nothing.
func TestEnrollHostCertRefused(t *testing.T) {
	dir := t.TempDir()
	user, host := newKey(t, dir, KeyUserCA), newKey(t, dir, KeyHostCA)
	noHost, err := New(Options{Files: Files{UserCA: user.file, HostCA: dir + "/absent"}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	req := HostCert{Key: hostKey(t), Target: "db-1", Host: "h", Validity: time.Hour, Now: time.Now()}
	if _, err := noHost.SignHostCert(req); codes.DetailOf(err) != DetailHostCAAbsent {
		t.Fatalf("without host-ca: %v", err)
	}
	if _, err := noHost.EnrollTokenKey(); codes.DetailOf(err) != DetailHostCAAbsent {
		t.Fatalf("token key without host-ca: %v", err)
	}
	set, err := New(Options{Files: Files{UserCA: user.file, HostCA: host.file}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := set.SignHostCert(req)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPub := extraECDSA(t)
	for name, k := range map[string]ssh.PublicKey{"a certificate": cert, "ecdsa": ecdsaPub, "nil": nil} {
		r := req
		r.Key = k
		if _, err := set.SignHostCert(r); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// TestEnrollTokenKeyDerived covers docs/08 D6: the key is derived from
// host-ca alone, so two loads (the server and the exec'd command) agree,
// another host-ca gives another key, and the key isn't the seed.
func TestEnrollTokenKeyDerived(t *testing.T) {
	dir := t.TempDir()
	user, host := newKey(t, dir, KeyUserCA), newKey(t, dir, KeyHostCA)
	load := func(hostFile string) []byte {
		t.Helper()
		s, err := New(Options{Files: Files{UserCA: user.file, HostCA: hostFile}}).Load()
		if err != nil {
			t.Fatal(err)
		}
		k, err := s.EnrollTokenKey()
		if err != nil || len(k) != 32 {
			t.Fatalf("token key: %v", err)
		}
		return k
	}
	a, b := load(host.file), load(host.file)
	if !bytes.Equal(a, b) {
		t.Fatal("two loads derive different keys")
	}
	other := newKey(t, t.TempDir(), KeyHostCA)
	if bytes.Equal(a, load(other.file)) {
		t.Fatal("another host-ca derives the same key")
	}
	seed, err := seedOf(host.pem)
	if err != nil || bytes.Equal(seed, a) {
		t.Fatal("the key is the seed itself")
	}
	// A host-ca that isn't ed25519 is unreadable, as before (D1).
	if err := os.WriteFile(host.file, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Files: Files{UserCA: user.file, HostCA: host.file}}).Load(); codes.DetailOf(err) != DetailUnreadable {
		t.Fatalf("broken host-ca: %v", err)
	}
}

func extraECDSA(t *testing.T) ssh.PublicKey {
	t.Helper()
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, err := ssh.NewPublicKey(&ek.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
