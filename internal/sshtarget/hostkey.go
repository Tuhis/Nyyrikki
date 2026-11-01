package sshtarget

import (
	"bytes"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/decision"
)

// errHostKey is what the host-key callback returns; the runner reports
// it as host_key_mismatch.
var errHostKey = errors.New("sshtarget: host key not trusted")

// errHostKeyRevoked is returned for a key listed in revoked_host_keys
// (docs/08 D9); the runner reports it as host_key_revoked.
var errHostKeyRevoked = errors.New("sshtarget: host key revoked")

// SessionKillExtension is the host certificate extension by which a
// certificate from Nyyrikki's own host CA states that the host finishes
// cuts (docs/08 D8, D9). Its value is empty.
const SessionKillExtension = "session-kill@nyyrikki"

// HostCertKeyID is the key ID a host certificate from Nyyrikki's own
// host CA carries for target (docs/08 D8). The verifier accepts such a
// certificate only for that target (D9).
func HostCertKeyID(target string) string { return "nyyrikki-host:" + target }

// hostVerifier checks the host before Nyyrikki authenticates (docs/07
// D8, revised by docs/08 D9): its key equals a pin, or it is a host
// certificate signed by one of the host CAs, or by Nyyrikki's own host
// CA, valid now, naming the target's host. A certificate from the own
// host CA must also carry the target's key ID. Nothing is trusted on
// first use. A key in revoked, presented plainly, as a certificate's key
// or as the key that signed it, is refused before anything else.
type hostVerifier struct {
	target      string
	host        string
	pins        [][]byte
	cas         [][]byte
	own         []byte // pub(host-ca), nil when absent
	revoked     [][]byte
	sessionKill bool // the target's config value (docs/07 §5.5)
	now         func() time.Time
	checker     *ssh.CertChecker
}

// newHostVerifier returns the verifier of target t. ownCA is pub(host-ca)
// as just loaded, or nil when there is none.
func newHostVerifier(t Target, ownCA ssh.PublicKey, revoked []ssh.PublicKey, now func() time.Time) *hostVerifier {
	v := &hostVerifier{target: t.Name, host: t.Host, sessionKill: t.SessionKill, now: now}
	for _, k := range revoked {
		v.revoked = append(v.revoked, k.Marshal())
	}
	for _, k := range t.HostKeys {
		v.pins = append(v.pins, k.Marshal())
	}
	for _, k := range t.HostCAs {
		v.cas = append(v.cas, k.Marshal())
	}
	if ownCA != nil {
		v.own = ownCA.Marshal()
	}
	v.checker = &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool { return v.isCA(auth) || v.isOwn(auth) },
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
func (v *hostVerifier) isOwn(k ssh.PublicKey) bool {
	return v.own != nil && k != nil && bytes.Equal(v.own, k.Marshal())
}

// trustsCerts reports whether host certificates are offered and
// accepted: for a target with host CAs of its own or global ones, and
// for an unpinned target when Nyyrikki has a host CA. A pinned target
// without host CAs is verified by its pins only, as before docs/08, so
// a host that also has a certificate keeps presenting its plain key.
func (v *hostVerifier) trustsCerts() bool {
	return len(v.cas) > 0 || (v.own != nil && len(v.pins) == 0)
}

// anyTrust reports whether anything could verify the host: without it,
// the target is host_not_pinned and never dialled.
func (v *hostVerifier) anyTrust() bool { return len(v.pins) > 0 || v.trustsCerts() }

func contains(set [][]byte, b []byte) bool {
	for _, s := range set {
		if bytes.Equal(s, b) {
			return true
		}
	}
	return false
}

// verify checks a presented host key and returns the facts it shows
// (docs/08 D9): session_kill from the extension of a certificate that
// Nyyrikki's own host CA signed, else from the target's config value.
// The host name a certificate must name is the target's, from config,
// not what the dialler resolved.
func (v *hostVerifier) verify(remote net.Addr, key ssh.PublicKey) (decision.HostFacts, error) {
	if contains(v.revoked, key.Marshal()) {
		return decision.HostFacts{}, errHostKeyRevoked
	}
	c, isCert := key.(*ssh.Certificate)
	own := false
	if isCert {
		if contains(v.revoked, c.Key.Marshal()) || (c.SignatureKey != nil && contains(v.revoked, c.SignatureKey.Marshal())) {
			return decision.HostFacts{}, errHostKeyRevoked
		}
		// CertChecker takes a certificate without principals as valid
		// for every host; D8 wants this host named.
		if !v.trustsCerts() || len(c.ValidPrincipals) == 0 {
			return decision.HostFacts{}, errHostKey
		}
		own = v.isOwn(c.SignatureKey)
		// docs/08 D9: a certificate Nyyrikki issued names its target in
		// its key ID, so one target's certificate never verifies
		// another, even at the same address. D8 enrolls ed25519 only.
		if own && (c.KeyId != HostCertKeyID(v.target) || c.Key.Type() != ssh.KeyAlgoED25519) {
			return decision.HostFacts{}, errHostKey
		}
	}
	// CertChecker takes the host name from addr; give it the configured
	// one, with a port it ignores.
	if err := v.checker.CheckHostKey(net.JoinHostPort(v.host, "22"), remote, key); err != nil {
		return decision.HostFacts{}, errHostKey
	}
	if own {
		val, ok := c.Extensions[SessionKillExtension]
		return decision.HostFacts{SessionKill: ok && val == ""}, nil
	}
	return decision.HostFacts{SessionKill: v.sessionKill}, nil
}

// algorithms are the host key algorithms to offer: certificate
// algorithms only when certificates are trusted, and the plain ones of
// the pinned key types, so the host presents something that can match.
func (v *hostVerifier) algorithms(pins []ssh.PublicKey) []string {
	var out []string
	if v.trustsCerts() {
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
