package hostsetup

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/config"
)

// Enrollment tokens (docs/08 D6): nye1.<base64url(len(target) ‖ target ‖
// expiry ‖ 16 random bytes ‖ HMAC-SHA256)>. The target is prefixed by
// its length, one byte, so no two (target, expiry) pairs share an
// encoding; the expiry is Unix seconds, big-endian, eight bytes. The
// HMAC covers TokenPrefix and every byte before it, under the key
// sshca derives from host-ca.
const (
	TokenPrefix = "nye1."
	// TokenLife is how long a token is valid (docs/08 D6).
	TokenLife = 15 * time.Minute

	tokenRandomLen = 16
	tokenMACLen    = sha256.Size
	// maxTokenLen bounds what is decoded: a 63-character target makes
	// the longest token, 165 characters.
	maxTokenLen = 256
)

// Token is a verified token's content. It holds no secret: the random
// part only identifies the token, so that it is used once.
type Token struct {
	Target  string
	Expires time.Time
	Random  [tokenRandomLen]byte
}

// Issued is when the token was made.
func (t Token) Issued() time.Time { return t.Expires.Add(-TokenLife) }

// SHA256 is the hex SHA-256 of the random part: what the audit records
// instead of the token (docs/08 D6).
func (t Token) SHA256() string {
	h := sha256.Sum256(t.Random[:])
	return hex.EncodeToString(h[:])
}

// Token errors. None holds any part of the token.
var (
	ErrTokenMalformed = errors.New("hostsetup: malformed enrollment token")
	ErrTokenForged    = errors.New("hostsetup: enrollment token not signed by this Nyyrikki")
)

// MintToken makes a token for target, valid TokenLife from now, signed
// with key (sshca.Set.EnrollTokenKey).
func MintToken(key []byte, target string, now time.Time) (string, Token, error) {
	if len(key) == 0 {
		return "", Token{}, errors.New("hostsetup: no token key")
	}
	if !config.IsSlug(target) {
		return "", Token{}, errors.New("hostsetup: not a target name")
	}
	t := Token{Target: target, Expires: now.Add(TokenLife).Truncate(time.Second)}
	if _, err := rand.Read(t.Random[:]); err != nil {
		return "", Token{}, err
	}
	payload := make([]byte, 0, 1+len(target)+8+tokenRandomLen+tokenMACLen)
	payload = append(payload, byte(len(target)))
	payload = append(payload, target...)
	payload = binary.BigEndian.AppendUint64(payload, uint64(t.Expires.Unix()))
	payload = append(payload, t.Random[:]...)
	payload = append(payload, tokenMAC(key, payload)...)
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(payload), t, nil
}

func tokenMAC(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(TokenPrefix))
	m.Write(payload)
	return m.Sum(nil)
}

// ParseToken checks s's form and its HMAC, in constant time, before it
// reads anything from it. It doesn't check the expiry, the target or
// whether the token was used: the caller does, since only it knows the
// time, the path and what was used.
func ParseToken(key []byte, s string) (Token, error) {
	if len(key) == 0 || len(s) > maxTokenLen || !strings.HasPrefix(s, TokenPrefix) {
		return Token{}, ErrTokenMalformed
	}
	// Strict: no padding, no stray bits, so one token has one spelling.
	b, err := base64.RawURLEncoding.Strict().DecodeString(s[len(TokenPrefix):])
	if err != nil || len(b) < 1+1+8+tokenRandomLen+tokenMACLen {
		return Token{}, ErrTokenMalformed
	}
	payload, mac := b[:len(b)-tokenMACLen], b[len(b)-tokenMACLen:]
	if !hmac.Equal(mac, tokenMAC(key, payload)) {
		return Token{}, ErrTokenForged
	}
	n := int(payload[0])
	if len(payload) != 1+n+8+tokenRandomLen {
		return Token{}, ErrTokenMalformed
	}
	t := Token{Target: string(payload[1 : 1+n])}
	if !config.IsSlug(t.Target) {
		return Token{}, ErrTokenMalformed
	}
	exp := binary.BigEndian.Uint64(payload[1+n : 1+n+8])
	if exp > 1<<62 {
		return Token{}, ErrTokenMalformed
	}
	t.Expires = time.Unix(int64(exp), 0)
	copy(t.Random[:], payload[1+n+8:])
	return t, nil
}
