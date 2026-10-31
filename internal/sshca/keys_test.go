package sshca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

type key struct {
	file string
	pem  []byte
	pub  ssh.PublicKey
}

func newKey(t *testing.T, dir, name string) key {
	t.Helper()
	b, pub, err := GenerateKey("test")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, name)
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return key{file: f, pem: b, pub: pub}
}

func extraKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, pub, err := GenerateKey("")
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func fps(keys []ssh.PublicKey) string {
	var out []string
	for _, k := range keys {
		out = append(out, ssh.FingerprintSHA256(k))
	}
	return strings.Join(out, ",")
}

type recAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail bool
}

func (a *recAudit) Append(_ context.Context, r audit.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("down")
	}
	a.recs = append(a.recs, r)
	return nil
}

// TestCAKeysTrustedSet covers docs/08 G1: the trusted set is pub(user-ca),
// pub(user-ca-next) when present, then the extra keys, without
// duplicates and minus the revoked ones; the signers are the derived keys
// minus the revoked ones, a subset of the trusted set.
func TestCAKeysTrustedSet(t *testing.T) {
	dir := t.TempDir()
	user, next, host := newKey(t, dir, KeyUserCA), newKey(t, dir, KeyNextUserCA), newKey(t, dir, KeyHostCA)
	e1, e2 := extraKey(t), extraKey(t)

	s, err := New(Options{Files: Files{UserCA: user.file, NextUserCA: next.file, HostCA: host.file}, Extra: []ssh.PublicKey{e1, e2}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fps(s.Trusted()), fps([]ssh.PublicKey{user.pub, next.pub, e1, e2}); got != want {
		t.Fatalf("trusted %s, want %s", got, want)
	}
	if got, want := fps(s.Signers()), fps([]ssh.PublicKey{user.pub, next.pub}); got != want {
		t.Fatalf("signers %s, want %s", got, want)
	}
	if !bytes.Equal(s.HostCA.PublicKey().Marshal(), host.pub.Marshal()) || !bytes.Equal(s.UserCA.PublicKey().Marshal(), user.pub.Marshal()) {
		t.Fatal("wrong signers loaded")
	}

	// Revoked: a staged key and an extra key drop out of both sets.
	s, err = New(Options{Files: Files{UserCA: user.file, NextUserCA: next.file}, Extra: []ssh.PublicKey{e1, e2},
		Revoked: []ssh.PublicKey{next.pub, e1}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fps(s.Trusted()), fps([]ssh.PublicKey{user.pub, e2}); got != want {
		t.Fatalf("trusted with revocations %s, want %s", got, want)
	}
	if got, want := fps(s.Signers()), fps([]ssh.PublicKey{user.pub}); got != want {
		t.Fatalf("signers with revocations %s, want %s", got, want)
	}

	// An extra key equal to a derived one is listed once, in the derived
	// key's place, and never becomes a signer by being extra.
	s, err = New(Options{Files: Files{UserCA: user.file}, Extra: []ssh.PublicKey{e1, user.pub, e1}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fps(s.Trusted()), fps([]ssh.PublicKey{user.pub, e1}); got != want {
		t.Fatalf("trusted with duplicates %s, want %s", got, want)
	}
	if got, want := fps(s.Signers()), fps([]ssh.PublicKey{user.pub}); got != want {
		t.Fatalf("an extra key became a signer: %s", got)
	}
}

// TestCAKeysOptionalAbsent covers G1: a missing optional file, or one not
// configured, removes only that feature.
func TestCAKeysOptionalAbsent(t *testing.T) {
	dir := t.TempDir()
	user := newKey(t, dir, KeyUserCA)
	for name, f := range map[string]Files{
		"missing files":  {UserCA: user.file, NextUserCA: filepath.Join(dir, KeyNextUserCA), HostCA: filepath.Join(dir, KeyHostCA)},
		"not configured": {UserCA: user.file},
	} {
		s, err := New(Options{Files: f}).Load()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.NextUserCA != nil || s.HostCA != nil || fps(s.Trusted()) != fps([]ssh.PublicKey{user.pub}) || fps(s.Signers()) != fps([]ssh.PublicKey{user.pub}) {
			t.Fatalf("%s: %+v", name, s)
		}
	}
}

// TestCAKeysBroken covers G1: user-ca missing, or any key file that
// exists but can't be read or parsed or isn't ed25519, is unavailable
// with ca_key_unreadable; a revoked user-ca is user_ca_revoked. No error
// carries key material.
func TestCAKeysBroken(t *testing.T) {
	dir := t.TempDir()
	user := newKey(t, dir, KeyUserCA)
	garbage := filepath.Join(dir, "garbage")
	os.WriteFile(garbage, []byte("not a key"), 0o600)
	// A half-written rotation: the start of a valid key.
	half := filepath.Join(dir, "half")
	os.WriteFile(half, user.pem[:len(user.pem)/2], 0o600)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eblock, _ := ssh.MarshalPrivateKey(ek, "")
	ecdsaFile := filepath.Join(dir, "ecdsa")
	os.WriteFile(ecdsaFile, pem.EncodeToMemory(eblock), 0o600)
	// An encrypted key can't be used without a passphrase.
	_, priv, _ := newEd25519()
	encBlock, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	encFile := filepath.Join(dir, "encrypted")
	os.WriteFile(encFile, pem.EncodeToMemory(encBlock), 0o600)
	unreadable := filepath.Join(dir, "unreadable")
	os.WriteFile(unreadable, user.pem, 0o000)

	cases := map[string]struct {
		o      Options
		detail string
	}{
		"user-ca missing":         {Options{Files: Files{UserCA: filepath.Join(dir, "none")}}, DetailUnreadable},
		"user-ca not configured":  {Options{}, DetailUnreadable},
		"user-ca garbage":         {Options{Files: Files{UserCA: garbage}}, DetailUnreadable},
		"user-ca half written":    {Options{Files: Files{UserCA: half}}, DetailUnreadable},
		"user-ca ecdsa":           {Options{Files: Files{UserCA: ecdsaFile}}, DetailUnreadable},
		"user-ca encrypted":       {Options{Files: Files{UserCA: encFile}}, DetailUnreadable},
		"user-ca a directory":     {Options{Files: Files{UserCA: dir}}, DetailUnreadable},
		"next garbage":            {Options{Files: Files{UserCA: user.file, NextUserCA: garbage}}, DetailUnreadable},
		"next half written":       {Options{Files: Files{UserCA: user.file, NextUserCA: half}}, DetailUnreadable},
		"next ecdsa":              {Options{Files: Files{UserCA: user.file, NextUserCA: ecdsaFile}}, DetailUnreadable},
		"host-ca garbage":         {Options{Files: Files{UserCA: user.file, HostCA: garbage}}, DetailUnreadable},
		"host-ca ecdsa":           {Options{Files: Files{UserCA: user.file, HostCA: ecdsaFile}}, DetailUnreadable},
		"host-ca a directory":     {Options{Files: Files{UserCA: user.file, HostCA: dir}}, DetailUnreadable},
		"user-ca revoked":         {Options{Files: Files{UserCA: user.file}, Revoked: []ssh.PublicKey{user.pub}}, DetailUserCARevoked},
		"revoked and also extra":  {Options{Files: Files{UserCA: user.file}, Extra: []ssh.PublicKey{user.pub}, Revoked: []ssh.PublicKey{user.pub}}, DetailUserCARevoked},
		"host-ca unreadable mode": {Options{Files: Files{UserCA: user.file, HostCA: unreadable}}, DetailUnreadable},
	}
	if os.Geteuid() == 0 {
		delete(cases, "host-ca unreadable mode") // root reads anything
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := New(c.o).Load()
			if s != nil || codes.Of(err) != codes.Unavailable || codes.DetailOf(err) != c.detail {
				t.Fatalf("set %v, err %v (detail %q), want %s", s, err, codes.DetailOf(err), c.detail)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), string(user.pem[40:60])) {
				t.Fatal("the error carries key material")
			}
		})
	}
}

// TestCAKeysReadOnEachUse covers G1: a Secret change is picked up without
// a restart. The kubelet replaces the files; the next Load sees them.
func TestCAKeysReadOnEachUse(t *testing.T) {
	dir := t.TempDir()
	user := newKey(t, dir, KeyUserCA)
	nextPath := filepath.Join(dir, KeyNextUserCA)
	k := New(Options{Files: Files{UserCA: user.file, NextUserCA: nextPath}})
	s, err := k.Load()
	if err != nil || s.NextUserCA != nil {
		t.Fatalf("before stage: %v", err)
	}
	// Stage.
	next := newKey(t, dir, KeyNextUserCA)
	if s, err = k.Load(); err != nil || fps(s.Signers()) != fps([]ssh.PublicKey{user.pub, next.pub}) {
		t.Fatalf("after stage: %v", err)
	}
	// Promote: user-ca becomes the staged key, user-ca-next goes away.
	os.WriteFile(user.file, next.pem, 0o600)
	os.Remove(nextPath)
	if s, err = k.Load(); err != nil || fps(s.Trusted()) != fps([]ssh.PublicKey{next.pub}) || !bytes.Equal(s.UserCA.PublicKey().Marshal(), next.pub.Marshal()) {
		t.Fatalf("after promote: %v", err)
	}
	// Broken mid-rotation, then repaired.
	os.WriteFile(nextPath, []byte("x"), 0o600)
	if _, err = k.Load(); codes.DetailOf(err) != DetailUnreadable {
		t.Fatalf("broken: %v", err)
	}
	os.Remove(nextPath)
	if _, err = k.Load(); err != nil {
		t.Fatalf("repaired: %v", err)
	}
}

// TestCAKeysWarnDerivedExtra covers docs/08 D14: an extra key equal to a
// derived one is logged and audited, once per change, and again after the
// condition clears and returns; a failed audit write is retried.
func TestCAKeysWarnDerivedExtra(t *testing.T) {
	dir := t.TempDir()
	user := newKey(t, dir, KeyUserCA)
	nextPath := filepath.Join(dir, KeyNextUserCA)
	a := &recAudit{}
	var logs bytes.Buffer
	next := newKey(t, t.TempDir(), "elsewhere")
	k := New(Options{Files: Files{UserCA: user.file, NextUserCA: nextPath}, Extra: []ssh.PublicKey{next.pub},
		Audit: a, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	load := func() {
		t.Helper()
		if _, err := k.Load(); err != nil {
			t.Fatal(err)
		}
	}
	load()
	if len(a.recs) != 0 {
		t.Fatalf("warned without a derived duplicate: %+v", a.recs)
	}
	os.WriteFile(nextPath, next.pem, 0o600) // staged key equals the extra one
	load()
	load()
	if len(a.recs) != 1 || a.recs[0].Kind != codes.KindSSHCAWarning || !strings.Contains(a.recs[0].Detail, ssh.FingerprintSHA256(next.pub)) {
		t.Fatalf("audit %+v", a.recs)
	}
	if !strings.Contains(logs.String(), ssh.FingerprintSHA256(next.pub)) {
		t.Fatalf("not logged: %s", logs.String())
	}
	os.Remove(nextPath)
	load()
	a.fail = true
	os.WriteFile(nextPath, next.pem, 0o600)
	load() // the audit write fails: Load still succeeds, and retries next time
	a.fail = false
	load()
	load()
	if len(a.recs) != 2 {
		t.Fatalf("%d warnings, want 2", len(a.recs))
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") || strings.Contains(a.recs[1].Detail, "PRIVATE") {
		t.Fatal("key material in the warning")
	}
}

func newEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// A staged user-ca-next that is revoked is dropped from Trusted and
// Signers, and warned about once, so the operator sees it before a promote
// makes every run user_ca_revoked (round 1 of #42).
func TestCAKeysWarnRevokedNext(t *testing.T) {
	dir := t.TempDir()
	user := newKey(t, dir, KeyUserCA)
	next := newKey(t, dir, KeyNextUserCA)
	a := &recAudit{}
	var logs bytes.Buffer
	k := New(Options{Files: Files{UserCA: user.file, NextUserCA: next.file}, Revoked: []ssh.PublicKey{next.pub},
		Audit: a, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	for range 2 {
		s, err := k.Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Trusted()) != 1 || len(s.Signers()) != 1 {
			t.Fatalf("revoked next still trusted: %d %d", len(s.Trusted()), len(s.Signers()))
		}
	}
	fp := ssh.FingerprintSHA256(next.pub)
	if len(a.recs) != 1 || a.recs[0].Kind != codes.KindSSHCAWarning || !strings.Contains(a.recs[0].Detail, fp) ||
		!strings.Contains(a.recs[0].Detail, "revoked") {
		t.Fatalf("audit %+v", a.recs)
	}
	if !strings.Contains(logs.String(), fp) {
		t.Fatalf("not logged: %s", logs.String())
	}
}
