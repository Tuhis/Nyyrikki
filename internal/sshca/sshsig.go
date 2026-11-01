package sshca

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// TrustNamespace is the SSHSIG namespace of a trust bundle (docs/08 D4).
// A namespaced signature can't be taken for a certificate's or another
// namespace's, so user-ca can sign both (OD3).
const TrustNamespace = "nyyrikki-trust@v1"

// The armor of an SSHSIG signature, as ssh-keygen -Y sign writes it.
const (
	SSHSIGBegin = "-----BEGIN SSH SIGNATURE-----"
	SSHSIGEnd   = "-----END SSH SIGNATURE-----"
)

const (
	sshsigMagic   = "SSHSIG"
	sshsigVersion = 1
	sshsigHash    = "sha512"
	armorColumns  = 70
)

// SignSSHSIG signs message in OpenSSH's SSHSIG format (PROTOCOL.sshsig)
// under namespace, with an ed25519 signer, and returns the armored
// signature, ending in a newline. ssh-keygen -Y verify checks it (docs/08
// M1). It signs whatever it is given: callers pass content they built
// themselves, never bytes from a request (docs/08 §6).
func SignSSHSIG(s ssh.Signer, namespace string, message []byte) ([]byte, error) {
	if s == nil || s.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("sshca: SSHSIG needs an ed25519 key")
	}
	if namespace == "" {
		return nil, errors.New("sshca: SSHSIG needs a namespace")
	}
	h := sha512.Sum512(message)
	// What is signed: the magic preamble, then the namespace, the
	// reserved field, the hash algorithm and the message's hash.
	signed := append([]byte(sshsigMagic), ssh.Marshal(struct {
		Namespace string
		Reserved  string
		Hash      string
		Digest    string
	}{namespace, "", sshsigHash, string(h[:])})...)
	sig, err := s.Sign(rand.Reader, signed)
	if err != nil {
		return nil, err
	}
	if sig.Format != ssh.KeyAlgoED25519 {
		return nil, errors.New("sshca: unexpected signature format")
	}
	blob := append([]byte(sshsigMagic), ssh.Marshal(struct {
		Version   uint32
		PublicKey string
		Namespace string
		Reserved  string
		Hash      string
		Signature string
	}{sshsigVersion, string(s.PublicKey().Marshal()), namespace, "", sshsigHash, string(ssh.Marshal(sig))})...)
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(SSHSIGBegin + "\n")
	for len(enc) > armorColumns {
		b.WriteString(enc[:armorColumns] + "\n")
		enc = enc[armorColumns:]
	}
	b.WriteString(enc + "\n" + SSHSIGEnd + "\n")
	return []byte(b.String()), nil
}
