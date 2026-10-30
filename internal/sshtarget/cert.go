package sshtarget

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// Certificate lifetime around now (docs/07 D5): sshd checks it only at
// login, so it covers the handshake, not the run.
const (
	certBackdate = 60 * time.Second
	certLifetime = 2 * time.Minute
)

// Detail values of the CA's failures.
const (
	DetailCAUnreadable = "ca_key_unreadable"
	DetailCAMismatch   = "ca_key_not_listed"
)

// CA signs one certificate per run with the user CA key (docs/07 D5,
// D6). The key file is read on each use, so a rotated Secret applies to
// the next run, and the key is never kept between runs.
type CA struct {
	keyFile string
	// trusted are the marshalled user_ca_public_keys: the key in keyFile
	// must be one of them (docs/07 §5.5).
	trusted [][]byte
	sources string
	now     func() time.Time
}

// NewCA returns a CA. publicKeys are the parsed user_ca_public_keys,
// sources the source addresses the certificate is restricted to.
func NewCA(keyFile string, publicKeys []ssh.PublicKey, sources []string, now func() time.Time) *CA {
	if now == nil {
		now = time.Now
	}
	ca := &CA{keyFile: keyFile, sources: strings.Join(sources, ","), now: now}
	for _, k := range publicKeys {
		ca.trusted = append(ca.trusted, k.Marshal())
	}
	return ca
}

// Cert is one run's credential: a signer over a key pair made in memory
// for the run, and the certificate's serial and key ID for the audit
// record. It lives only as long as the run's dial (docs/07 D5, D10).
type Cert struct {
	signer ssh.Signer
	Serial uint64
	KeyID  string
}

// Principal is the one principal a certificate for human on target
// carries, and the one the host's principals file lists (docs/07 D4).
func Principal(human, target string) string { return "nyyrikki:" + human + "@" + target }

// Mint issues the certificate of docs/07 D5 for one run. Any failure is
// a *codes.Error with codes.Unavailable; nothing in it holds key
// material.
func (ca *CA) Mint(runID, human, target string, interactive bool) (*Cert, error) {
	caSigner, err := ca.load()
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not make the run's key")
	}
	keySigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not make the run's key")
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not make the run's key")
	}
	var sb [8]byte
	if _, err := rand.Read(sb[:]); err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not make a serial")
	}
	now := ca.now()
	ext := map[string]string{}
	if interactive {
		ext["permit-pty"] = ""
	}
	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          binary.BigEndian.Uint64(sb[:]),
		CertType:        ssh.UserCert,
		KeyId:           "nyyrikki:" + runID,
		ValidPrincipals: []string{Principal(human, target)},
		ValidAfter:      uint64(now.Add(-certBackdate).Unix()),
		ValidBefore:     uint64(now.Add(certLifetime).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"source-address": ca.sources},
			Extensions:      ext,
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not sign the run's certificate")
	}
	signer, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		return nil, codes.Wrap(codes.Unavailable, err, "could not sign the run's certificate")
	}
	return &Cert{signer: signer, Serial: cert.Serial, KeyID: cert.KeyId}, nil
}

// load reads the CA key and checks it against user_ca_public_keys
// (docs/07 §5.5). The file's contents never reach an error.
func (ca *CA) load() (ssh.Signer, error) {
	b, err := os.ReadFile(ca.keyFile)
	if err != nil {
		return nil, codes.WithDetail(codes.Unavailable, DetailCAUnreadable, "the SSH user CA key is unavailable")
	}
	s, err := ssh.ParsePrivateKey(b)
	clear(b)
	if err != nil || s.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, codes.WithDetail(codes.Unavailable, DetailCAUnreadable, "the SSH user CA key is unavailable")
	}
	pub := s.PublicKey().Marshal()
	for _, t := range ca.trusted {
		if bytes.Equal(t, pub) {
			return s, nil
		}
	}
	return nil, codes.WithDetail(codes.Unavailable, DetailCAMismatch, "the SSH user CA key is not one of ssh.user_ca_public_keys")
}
