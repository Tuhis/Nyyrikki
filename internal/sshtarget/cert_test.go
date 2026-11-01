package sshtarget

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// TestMintCert covers docs/07 D5 (G3): exactly one principal, the run's
// key ID, a two-minute validity backdated by a minute, source-address,
// and permit-pty only for an interactive run, signed by the CA.
func TestMintCert(t *testing.T) {
	ca := newTestCA(t)
	now := time.Unix(1_800_000_000, 0)
	c := NewCA(userCA(ca.file), []string{"203.0.113.10/32", "2001:db8::/64"}, func() time.Time { return now })
	for _, interactive := range []bool{false, true} {
		m, err := c.Mint("run_01ABC", "owner", "db-1", interactive)
		if err != nil {
			t.Fatal(err)
		}
		cert, ok := m.signer.PublicKey().(*ssh.Certificate)
		if !ok {
			t.Fatal("not a certificate signer")
		}
		if cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "nyyrikki:owner@db-1" {
			t.Errorf("type %d principals %v", cert.CertType, cert.ValidPrincipals)
		}
		if cert.KeyId != "nyyrikki:run_01ABC" || m.KeyID != cert.KeyId || m.Serial != cert.Serial {
			t.Errorf("key id %q, serial %d/%d", cert.KeyId, cert.Serial, m.Serial)
		}
		if cert.ValidAfter != uint64(now.Add(-60*time.Second).Unix()) || cert.ValidBefore != uint64(now.Add(2*time.Minute).Unix()) {
			t.Errorf("validity %d–%d", cert.ValidAfter, cert.ValidBefore)
		}
		if len(cert.CriticalOptions) != 1 || cert.CriticalOptions["source-address"] != "203.0.113.10/32,2001:db8::/64" {
			t.Errorf("critical options %v", cert.CriticalOptions)
		}
		_, pty := cert.Extensions["permit-pty"]
		if pty != interactive || len(cert.Extensions) != map[bool]int{false: 0, true: 1}[interactive] {
			t.Errorf("interactive=%v: extensions %v", interactive, cert.Extensions)
		}
		chk := &ssh.CertChecker{
			IsUserAuthority:          func(a ssh.PublicKey) bool { return string(a.Marshal()) == string(ca.signer.PublicKey().Marshal()) },
			Clock:                    func() time.Time { return now },
			SupportedCriticalOptions: []string{"source-address"},
		}
		if err := chk.CheckCert("nyyrikki:owner@db-1", cert); err != nil {
			t.Errorf("the CA's own check refuses it: %v", err)
		}
		if cert.Key.Type() != ssh.KeyAlgoED25519 {
			t.Errorf("run key type %s", cert.Key.Type())
		}
	}
	a, _ := c.Mint("run_a", "owner", "db-1", false)
	b, _ := c.Mint("run_b", "owner", "db-1", false)
	if a.Serial == b.Serial || string(a.signer.PublicKey().(*ssh.Certificate).Key.Marshal()) == string(b.signer.PublicKey().(*ssh.Certificate).Key.Marshal()) {
		t.Error("two runs share a serial or a key")
	}
}

// TestMintCertFailures covers docs/07 §6 and docs/08 D1, D3: a CA key
// that can't be read, isn't ed25519, or is revoked makes the run
// unavailable, and the error never carries the key.
func TestMintCertFailures(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	garbage := filepath.Join(t.TempDir(), "garbage")
	os.WriteFile(garbage, []byte("not a key"), 0o600)
	// An ECDSA CA key is refused: only ed25519 (docs/07 D6).
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eblock, _ := ssh.MarshalPrivateKey(ek, "")
	ecFile := filepath.Join(t.TempDir(), "ecdsa")
	os.WriteFile(ecFile, pem.EncodeToMemory(eblock), 0o600)
	cases := map[string]struct {
		keys   *sshca.Keys
		detail string
	}{
		"missing file": {userCA(filepath.Join(t.TempDir(), "none")), sshca.DetailUnreadable},
		"garbage":      {userCA(garbage), sshca.DetailUnreadable},
		"ecdsa":        {userCA(ecFile), sshca.DetailUnreadable},
		// A broken optional key stops runs too (docs/08 D1).
		"broken host CA": {sshca.New(sshca.Options{Files: sshca.Files{UserCA: ca.file, HostCA: garbage}}), sshca.DetailUnreadable},
		"revoked":        {sshca.New(sshca.Options{Files: sshca.Files{UserCA: ca.file}, Revoked: []ssh.PublicKey{ca.signer.PublicKey()}}), sshca.DetailUserCARevoked},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewCA(c.keys, []string{"127.0.0.1/32"}, nil).Mint("run_x", "owner", "db-1", false)
			wantCode(t, err, codes.Unavailable, c.detail)
			if leaks(err.Error(), other.pem, ca.pem) {
				t.Fatal("the error carries key material")
			}
		})
	}
	// Read on each use: a rotated file applies to the next run (docs/07 D6).
	c := NewCA(userCA(ca.file), []string{"127.0.0.1/32"}, nil)
	m, err := c.Mint("run_1", "owner", "db-1", false)
	if err != nil || string(m.signer.PublicKey().(*ssh.Certificate).SignatureKey.Marshal()) != string(ca.signer.PublicKey().Marshal()) {
		t.Fatalf("first key: %v", err)
	}
	os.WriteFile(ca.file, other.pem, 0o600)
	m, err = c.Mint("run_2", "owner", "db-1", false)
	if err != nil || string(m.signer.PublicKey().(*ssh.Certificate).SignatureKey.Marshal()) != string(other.signer.PublicKey().Marshal()) {
		t.Fatalf("rotated key: %v", err)
	}
}

// userCA is a loader with only the user CA key file.
func userCA(file string) *sshca.Keys {
	return sshca.New(sshca.Options{Files: sshca.Files{UserCA: file}})
}

// leaks reports whether s holds anything of the PEM files: their marker
// or any line of their base64 body.
func leaks(s string, pems ...[]byte) bool {
	if strings.Contains(s, "PRIVATE KEY") {
		return true
	}
	for _, p := range pems {
		for _, line := range strings.Split(string(p), "\n") {
			if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(s, line[:16]) {
				return true
			}
		}
	}
	return false
}
