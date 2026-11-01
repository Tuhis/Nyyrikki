package sshca

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// SessionKillExtension is the host certificate extension by which a
// certificate from Nyyrikki's own host CA states that the host finishes
// cuts (docs/08 D8, D9). Its value is empty.
const SessionKillExtension = "session-kill@nyyrikki"

// HostCertKeyID is the key ID a host certificate from Nyyrikki's own
// host CA carries for target (docs/08 D8). The verifier accepts such a
// certificate only for that target (D9).
func HostCertKeyID(target string) string { return "nyyrikki-host:" + target }

// hostCertBackdate is how far before now a host certificate is valid
// from (docs/08 D8), for hosts whose clocks run a little behind.
const hostCertBackdate = 5 * time.Minute

// DetailHostCAAbsent: there is no host-ca, so enrollment is off
// (docs/08 D1, D6).
const DetailHostCAAbsent = "host_ca_absent"

// errNoHostCA is the error of every host-ca operation without one.
func errNoHostCA() error {
	return codes.WithDetail(codes.Unavailable, DetailHostCAAbsent, "there is no SSH host CA key (host-ca): enrollment is off")
}

// HostCert is what an enrollment certifies (docs/08 D8).
type HostCert struct {
	// Key is the host's ed25519 public key.
	Key ssh.PublicKey
	// Target names the target in the key ID; Host is the host part of
	// its address, the one principal.
	Target string
	Host   string
	// Validity is ssh.host_cert_validity.
	Validity time.Duration
	// SessionKill adds the session-kill@nyyrikki extension.
	SessionKill bool
	Now         time.Time
}

// SignHostCert signs the host certificate of docs/08 D8 with host-ca:
// type host, the host's ed25519 key, one principal, key ID
// nyyrikki-host:<target>, a random 64-bit serial, valid from now − 5 min
// to now + Validity, and the session-kill@nyyrikki extension (empty
// value) only when SessionKill is set. No other extension and no
// critical option. Any failure is a *codes.Error with codes.Unavailable,
// or codes.InvalidRequest for a key that isn't a plain ed25519 key;
// nothing in it holds key material.
func (s *Set) SignHostCert(h HostCert) (*ssh.Certificate, error) {
	if s.HostCA == nil {
		return nil, errNoHostCA()
	}
	if h.Key == nil || h.Key.Type() != ssh.KeyAlgoED25519 {
		return nil, codes.New(codes.InvalidRequest, "only an ed25519 host key is enrolled")
	}
	if _, isCert := h.Key.(*ssh.Certificate); isCert {
		return nil, codes.New(codes.InvalidRequest, "only an ed25519 host key is enrolled")
	}
	if h.Target == "" || h.Host == "" || h.Validity <= 0 || h.Now.IsZero() {
		return nil, codes.New(codes.Internal, "incomplete host certificate request")
	}
	var sb [8]byte
	if _, err := rand.Read(sb[:]); err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not make a serial")
	}
	ext := map[string]string{}
	if h.SessionKill {
		ext[SessionKillExtension] = ""
	}
	cert := &ssh.Certificate{
		Key:             h.Key,
		Serial:          binary.BigEndian.Uint64(sb[:]),
		CertType:        ssh.HostCert,
		KeyId:           HostCertKeyID(h.Target),
		ValidPrincipals: []string{h.Host},
		ValidAfter:      uint64(h.Now.Add(-hostCertBackdate).Unix()),
		ValidBefore:     uint64(h.Now.Add(h.Validity).Unix()),
		Permissions:     ssh.Permissions{Extensions: ext},
	}
	if err := cert.SignCert(rand.Reader, s.HostCA); err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not sign the host certificate")
	}
	return cert, nil
}

// enrollTokenInfo is the HKDF info of the enrollment token key
// (docs/08 D6).
const enrollTokenInfo = "nyyrikki-enroll-token-v1"

// EnrollTokenKey is the key enrollment tokens are signed with
// (docs/08 D6): HKDF-SHA256 over host-ca's private key, with info
// nyyrikki-enroll-token-v1, so that the server and `nyyrikkid
// enroll-token` agree without sharing state or a new Secret. Without
// host-ca, enrollment is off: a *codes.Error with codes.Unavailable and
// detail host_ca_absent. The caller clears the key after use.
func (s *Set) EnrollTokenKey() ([]byte, error) {
	if s.HostCA == nil || len(s.hostSeed) != ed25519.SeedSize {
		return nil, errNoHostCA()
	}
	k, err := hkdf.Key(sha256.New, s.hostSeed, nil, enrollTokenInfo, 32)
	if err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not derive the enrollment token key")
	}
	return k, nil
}

// seedOf returns the ed25519 seed of an OpenSSH private key file, the
// secret the token key is derived from. The caller clears it.
func seedOf(b []byte) ([]byte, error) {
	k, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, errors.New("not an unencrypted OpenSSH private key")
	}
	var priv ed25519.PrivateKey
	switch v := k.(type) {
	case ed25519.PrivateKey:
		priv = v
	case *ed25519.PrivateKey:
		priv = *v
	default:
		return nil, errors.New("not an ed25519 key")
	}
	return append([]byte(nil), priv.Seed()...), nil
}
