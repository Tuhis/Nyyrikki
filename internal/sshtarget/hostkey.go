package sshtarget

import (
	"bytes"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// errHostKey is what the host-key callback returns; the runner reports
// it as host_key_mismatch.
var errHostKey = errors.New("sshtarget: host key not trusted")

// errHostKeyRevoked is returned for a key listed in revoked_host_keys
// (docs/08 D9); the runner reports it as host_key_revoked.
var errHostKeyRevoked = errors.New("sshtarget: host key revoked")

// hostVerifier checks the host before Nyyrikki authenticates (docs/07
// D8): its key equals a pin, or it is a host certificate signed by one
// of the host CAs, valid now, naming the target's host. Nothing is
// trusted on first use. A key in revoked, presented plainly, as a
// certificate's key or as the key that signed it, is refused before
// anything else (docs/08 D9).
type hostVerifier struct {
	host    string
	pins    [][]byte
	cas     [][]byte
	revoked [][]byte
	now     func() time.Time
	checker *ssh.CertChecker
}

func newHostVerifier(host string, pins, cas, revoked []ssh.PublicKey, now func() time.Time) *hostVerifier {
	v := &hostVerifier{host: host, now: now}
	for _, k := range revoked {
		v.revoked = append(v.revoked, k.Marshal())
	}
	for _, k := range pins {
		v.pins = append(v.pins, k.Marshal())
	}
	for _, k := range cas {
		v.cas = append(v.cas, k.Marshal())
	}
	v.checker = &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool { return v.isCA(auth) },
		Clock:           now,
		HostKeyFallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if v.isPinned(key) {
				return nil
			}
			return errHostKey
		},
	}
	return v
}

func (v *hostVerifier) isCA(k ssh.PublicKey) bool     { return contains(v.cas, k.Marshal()) }
func (v *hostVerifier) isPinned(k ssh.PublicKey) bool { return contains(v.pins, k.Marshal()) }

func contains(set [][]byte, b []byte) bool {
	for _, s := range set {
		if bytes.Equal(s, b) {
			return true
		}
	}
	return false
}

// callback is the ssh.HostKeyCallback. The host name a certificate must
// name is the target's, from config, not what the dialler resolved.
func (v *hostVerifier) callback(_ string, remote net.Addr, key ssh.PublicKey) error {
	if contains(v.revoked, key.Marshal()) {
		return errHostKeyRevoked
	}
	if c, ok := key.(*ssh.Certificate); ok {
		if contains(v.revoked, c.Key.Marshal()) || (c.SignatureKey != nil && contains(v.revoked, c.SignatureKey.Marshal())) {
			return errHostKeyRevoked
		}
		// CertChecker takes a certificate without principals as valid
		// for every host; D8 wants this host named.
		if len(v.cas) == 0 || len(c.ValidPrincipals) == 0 {
			return errHostKey
		}
	}
	// CertChecker takes the host name from addr; give it the configured
	// one, with a port it ignores.
	if err := v.checker.CheckHostKey(net.JoinHostPort(v.host, "22"), remote, key); err != nil {
		return errHostKey
	}
	return nil
}

// algorithms are the host key algorithms to offer: certificate
// algorithms only when host CAs are configured, and the plain ones of
// the pinned key types, so the host presents something that can match.
func (v *hostVerifier) algorithms(pins []ssh.PublicKey) []string {
	var out []string
	if len(v.cas) > 0 {
		out = append(out, ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01,
			ssh.CertAlgoECDSA521v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01)
	}
	seen := map[string]bool{}
	for _, k := range pins {
		algos := []string{k.Type()}
		if k.Type() == ssh.KeyAlgoRSA {
			algos = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
		}
		for _, a := range algos {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}
