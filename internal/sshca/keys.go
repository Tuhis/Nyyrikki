// Package sshca loads Nyyrikki's SSH CA keys (docs/08 D1, D3): the user
// CA that signs run certificates (docs/07 D5), an optional staged next
// user CA, and an optional host CA. Each key file is read on every use,
// so a rotated Secret applies without a restart, and the public keys
// hosts trust are derived from the private keys, never configured
// separately.
package sshca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// Detail values of the loader's failures. Every failure is
// codes.Unavailable: SSH runs and the /hosts/ endpoints stop (docs/08 D1).
const (
	// DetailUnreadable: a key file that must or does exist can't be read,
	// parsed, or isn't ed25519.
	DetailUnreadable = "ca_key_unreadable"
	// DetailUserCARevoked: user-ca is listed in ssh.revoked_user_ca_keys
	// (docs/08 D3).
	DetailUserCARevoked = "user_ca_revoked"
)

// The data keys of the CA Secret, which are also the file names under
// its mount (docs/08 D1).
const (
	KeyUserCA     = "user-ca"
	KeyNextUserCA = "user-ca-next"
	KeyHostCA     = "host-ca"
)

// Files names the three key files. NextUserCA and HostCA may be empty,
// which means the feature is absent, as a missing file does.
type Files struct {
	UserCA     string
	NextUserCA string
	HostCA     string
}

// Options configure Keys.
type Options struct {
	Files Files
	// Extra are ssh.user_ca_public_keys: keys hosts trust for logins in
	// addition to the derived ones (docs/08 D1).
	Extra []ssh.PublicKey
	// Revoked are ssh.revoked_user_ca_keys (docs/08 D3).
	Revoked []ssh.PublicKey
	// Audit and Logger receive the warning of docs/08 D14. Audit may be
	// nil (the ssh-ca command has none).
	Audit  audit.Appender
	Logger *slog.Logger
}

// Keys loads the CA keys on each use.
type Keys struct {
	o Options

	// readFile is os.ReadFile; tests replace it to simulate a rotation
	// landing mid-load.
	readFile func(string) ([]byte, error)

	mu      sync.Mutex
	warned  string // the warnings last written
	writing string // the warnings being written now
}

// New returns a loader. Nothing is read until Load.
func New(o Options) *Keys {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Keys{o: o, readFile: os.ReadFile}
}

// Set is one reading of the key files. It holds private keys: use it for
// one operation and drop it, never keep it.
type Set struct {
	UserCA     ssh.Signer
	NextUserCA ssh.Signer // nil when absent
	HostCA     ssh.Signer // nil when absent
	trusted    []ssh.PublicKey
	signers    []ssh.PublicKey
}

// Trusted is the set of user CA keys hosts trust for logins, in order:
// pub(user-ca), pub(user-ca-next), the extra keys, without duplicates and
// minus the revoked keys (docs/08 D1, D3).
func (s *Set) Trusted() []ssh.PublicKey { return append([]ssh.PublicKey(nil), s.trusted...) }

// Signers is the set of keys that may sign a trust bundle: pub(user-ca)
// and pub(user-ca-next), minus the revoked keys (docs/08 D4). It is
// always a subset of Trusted.
func (s *Set) Signers() []ssh.PublicKey { return append([]ssh.PublicKey(nil), s.signers...) }

// Load reads every key file. Any failure is a *codes.Error with
// codes.Unavailable; nothing in it holds key material.
func (k *Keys) Load() (*Set, error) {
	user, next, host, err := k.readConsistent()
	if err != nil {
		return nil, err
	}
	if contains(k.o.Revoked, user.PublicKey()) {
		return nil, codes.WithDetail(codes.Unavailable, DetailUserCARevoked,
			"the SSH user CA key is listed in ssh.revoked_user_ca_keys")
	}
	s := &Set{UserCA: user, NextUserCA: next, HostCA: host}
	derived := []ssh.PublicKey{user.PublicKey()}
	if next != nil {
		derived = append(derived, next.PublicKey())
	}
	for _, p := range derived {
		if !contains(k.o.Revoked, p) && !contains(s.signers, p) {
			s.signers = append(s.signers, p)
		}
	}
	var warnings []string
	if next != nil && contains(k.o.Revoked, next.PublicKey()) {
		warnings = append(warnings, "the staged user-ca-next is listed in ssh.revoked_user_ca_keys: it is not trusted, and a promote would stop every SSH run (user_ca_revoked); unstage it: "+ssh.FingerprintSHA256(next.PublicKey()))
	}
	var dups []string
	for _, p := range append(append([]ssh.PublicKey(nil), derived...), k.o.Extra...) {
		if contains(k.o.Revoked, p) || contains(s.trusted, p) {
			continue
		}
		s.trusted = append(s.trusted, p)
	}
	for _, p := range k.o.Extra {
		if contains(derived, p) {
			dups = append(dups, ssh.FingerprintSHA256(p))
		}
	}
	if len(dups) > 0 {
		warnings = append(warnings, "ssh.user_ca_public_keys lists a key derived from user-ca or user-ca-next; remove it, or it stays trusted after a promote: "+strings.Join(dups, ","))
	}
	k.warn(warnings)
	return s, nil
}

// readConsistent reads the three key files. The kubelet swaps a mounted
// Secret atomically, but three reads can straddle a swap (a promote
// between them would pair the old user-ca with no user-ca-next), so
// user-ca is parsed from its first read, read again at the end, and the
// whole read retried if the two differ (rounds 1 and 2 of #42). Either
// outcome fails closed; this only keeps one Load from mixing two
// versions.
func (k *Keys) readConsistent() (user, next, host ssh.Signer, err error) {
	for range 3 {
		var raw []byte
		if raw, user, err = k.readKey(k.o.Files.UserCA, false, "the SSH user CA key (user-ca) is unavailable"); err != nil {
			return nil, nil, nil, err
		}
		if _, next, err = k.readKey(k.o.Files.NextUserCA, true, "the staged SSH user CA key (user-ca-next) is unavailable"); err != nil {
			clear(raw)
			return nil, nil, nil, err
		}
		if _, host, err = k.readKey(k.o.Files.HostCA, true, "the SSH host CA key (host-ca) is unavailable"); err != nil {
			clear(raw)
			return nil, nil, nil, err
		}
		after, aerr := k.readFile(k.o.Files.UserCA)
		same := aerr == nil && bytes.Equal(raw, after)
		clear(raw)
		clear(after)
		if same {
			return user, next, host, nil
		}
	}
	return nil, nil, nil, codes.WithDetail(codes.Unavailable, DetailUnreadable, "the SSH CA keys changed while being read")
}

// warn logs and audits the warnings of docs/08 D14 (an extra key equal to
// a derived one) and of a revoked staged key, once per change. The lock
// covers only the comparison: the audit write, which may take seconds,
// happens outside it, so SSH runs don't queue behind a slow audit sink
// (round 1 of #42). While one load writes a set of warnings, others skip
// it rather than writing it again or waiting (round 2 of #42).
func (k *Keys) warn(warnings []string) {
	key := strings.Join(warnings, "\n")
	k.mu.Lock()
	if key == "" {
		k.warned = ""
		k.mu.Unlock()
		return
	}
	if key == k.warned || key == k.writing {
		k.mu.Unlock()
		return
	}
	k.writing = key
	k.mu.Unlock()
	for _, msg := range warnings {
		k.o.Logger.Warn(msg)
		if k.o.Audit != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := k.o.Audit.Append(ctx, audit.Record{Kind: codes.KindSSHCAWarning, Detail: msg})
			cancel()
			if err != nil {
				// A warning, not a decision: retry on the next load.
				k.o.Logger.Error("audit write of the SSH CA warning failed", "err", err)
				k.mu.Lock()
				if k.writing == key {
					k.writing = ""
				}
				k.mu.Unlock()
				return
			}
		}
	}
	k.mu.Lock()
	k.warned = key
	if k.writing == key {
		k.writing = ""
	}
	k.mu.Unlock()
}

// readKey reads and parses one key file, returning the bytes read (the
// caller clears them) with the key. An optional file that doesn't exist
// (or isn't configured) is absent: nil, nil, nil.
func (k *Keys) readKey(path string, optional bool, msg string) ([]byte, ssh.Signer, error) {
	if path == "" && optional {
		return nil, nil, nil
	}
	b, err := k.readFile(path)
	if err != nil {
		clear(b)
		if optional && errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, codes.WithDetail(codes.Unavailable, DetailUnreadable, "%s", msg)
	}
	s, err := ParsePrivateKey(b)
	if err != nil {
		clear(b)
		return nil, nil, codes.WithDetail(codes.Unavailable, DetailUnreadable, "%s", msg)
	}
	if optional {
		clear(b)
		return nil, s, nil
	}
	return b, s, nil
}

// ParsePrivateKey parses an unencrypted ed25519 OpenSSH private key. The
// error never holds the key's bytes.
func ParsePrivateKey(b []byte) (ssh.Signer, error) {
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, errors.New("not an unencrypted OpenSSH private key")
	}
	if s.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("not an ed25519 key")
	}
	return s, nil
}

// GenerateKey makes a fresh ed25519 key and returns it as an OpenSSH
// private key file, with its public key.
func GenerateKey(comment string) ([]byte, ssh.PublicKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, nil, err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(block), s.PublicKey(), nil
}

// AuthorizedKey is p in authorized_keys form, type and base64 only.
func AuthorizedKey(p ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))
}

func contains(set []ssh.PublicKey, p ssh.PublicKey) bool {
	m := p.Marshal()
	for _, q := range set {
		if bytes.Equal(q.Marshal(), m) {
			return true
		}
	}
	return false
}
