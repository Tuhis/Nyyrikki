package sshtarget

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// Certificate lifetime around now (docs/07 D5): sshd checks it only at
// login, so it covers the handshake, not the run.
const (
	certBackdate = 60 * time.Second
	certLifetime = 2 * time.Minute
)

// CA signs one certificate per run with the user CA key (docs/07 D5,
// D6). The key is read through internal/sshca on each use (docs/08 D1),
// so a rotated Secret applies to the next run, and the key is never kept
// between runs.
type CA struct {
	keys    *sshca.Keys
	sources string
	now     func() time.Time
}

// NewCA returns a CA that signs with the user CA of keys. sources are
// the source addresses the certificate is restricted to.
func NewCA(keys *sshca.Keys, sources []string, now func() time.Time) *CA {
	if now == nil {
		now = time.Now
	}
	return &CA{keys: keys, sources: strings.Join(sources, ","), now: now}
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
	set, err := ca.load()
	if err != nil {
		return nil, err
	}
	return ca.mint(set, runID, human, target, interactive)
}

// mint is Mint with keys already loaded, so that a run reads the key
// files once for its certificate and its host verification.
func (ca *CA) mint(set *sshca.Set, runID, human, target string, interactive bool) (*Cert, error) {
	caSigner := set.UserCA
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

// load reads the CA keys (docs/08 D1): a broken key file or a revoked
// user-ca is a *codes.Error with codes.Unavailable and no key material.
func (ca *CA) load() (*sshca.Set, error) { return ca.keys.Load() }

// hostCA is pub(host-ca) from set, or nil when there is none (docs/08
// D1, D9).
func hostCA(set *sshca.Set) ssh.PublicKey {
	if set.HostCA == nil {
		return nil
	}
	return set.HostCA.PublicKey()
}
