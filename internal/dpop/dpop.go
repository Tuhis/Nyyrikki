// Package dpop makes and inspects DPoP proofs (RFC 9449). The CLI uses it
// to sign requests with the key of its login (docs/01 §5.4); the server's
// checks are in internal/authn.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// NewKey makes a fresh P-256 key, one per login (docs/01 OD14).
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of pub, base64url
// without padding: the value of cnf.jkt.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	t, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(t), nil
}

// ATH returns the ath claim for an access token.
func ATH(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Claims are a proof's claims.
type Claims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// Proof returns a proof for method and url. accessToken may be empty (token
// requests); nonce may be empty.
func Proof(key *ecdsa.PrivateKey, method, url, accessToken, nonce string, now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	c := Claims{
		JTI:   base64.RawURLEncoding.EncodeToString(jti),
		HTM:   method,
		HTU:   url,
		IAT:   now.Unix(),
		Nonce: nonce,
	}
	if accessToken != "" {
		c.ATH = ATH(accessToken)
	}
	return Sign(key, c, nil)
}

// Sign signs arbitrary proof claims. extraHeaders overrides or adds
// protected headers; tests use it to build malformed proofs.
func Sign(key crypto.Signer, c any, extraHeaders map[jose.HeaderKey]any) (string, error) {
	alg := jose.ES256
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt")
	for k, v := range extraHeaders {
		opts = opts.WithHeader(k, v)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	jws, err := s.Sign(payload)
	if err != nil {
		return "", err
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("dpop: %w", err)
	}
	return out, nil
}
