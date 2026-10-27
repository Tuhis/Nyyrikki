package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/dpop"
)

// allowedAlgs is the asymmetric allowlist for tokens and proofs: never
// none, never HS* (docs/01 D9).
var allowedAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

const (
	maxSkew       = 30 * time.Second // exp, nbf (docs/01 D9)
	proofPast     = 60 * time.Second // iat at most this far in the past
	proofFuture   = 30 * time.Second // and this far in the future
	maxReplaySize = 100_000
)

// Human is what the verifier needs from the human registry.
type Human struct {
	ID string
}

// Config configures a Verifier.
type Config struct {
	Issuer      string
	CLIClientID string
	// Audience is the resource identifier tokens must name as aud: the
	// canonical /mcp URL.
	Audience string
	// HumanBySubject looks up the registry (docs/02 D4).
	HumanBySubject func(sub string) (Human, bool)
	// ResourceMetadataURL goes into the 401 challenge (docs/01 D6).
	ResourceMetadataURL string
	// IntrospectionClientID and IntrospectionSecretFile authenticate
	// introspection; the secret is read on each use (docs/02 D2).
	IntrospectionClientID   string
	IntrospectionSecretFile string
	HTTPClient              *http.Client
	Now                     func() time.Time
	Audit                   audit.Appender
	Logger                  *slog.Logger
}

// Verifier checks tokens and proofs and introspects sessions.
type Verifier struct {
	cfg     Config
	iss     *issuer
	start   time.Time
	nonce   string
	replays *replayCache
}

// NewVerifier returns a Verifier. The process start time it records is the
// earliest iat a proof may have (docs/01 D9).
func NewVerifier(cfg Config) *Verifier {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = HTTPClient()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	start := cfg.Now().Truncate(time.Second)
	return &Verifier{
		cfg:     cfg,
		iss:     newIssuer(cfg.Issuer, cfg.HTTPClient, cfg.Now),
		start:   start,
		nonce:   newNonce(),
		replays: newReplayCache(maxReplaySize),
	}
}

// claims are the access-token claims Nyyrikki reads.
type claims struct {
	jwt.Claims
	Typ      string `json:"typ"`
	AZP      string `json:"azp"`
	SID      string `json:"sid"`
	AuthTime int64  `json:"auth_time"`
	CNF      *struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// authError is a token-check failure. Reason goes to the audit log and the
// server log, never to the client beyond the 401.
type authError struct{ reason string }

func (e *authError) Error() string { return "unauthenticated: " + e.reason }

func fail(format string, args ...any) error { return &authError{reason: fmt.Sprintf(format, args...)} }

// Middleware authenticates every request to next. endpointURL is the
// canonical URL of the endpoint it guards (/mcp or /stream), against which
// DPoP proofs are checked (docs/02 D11).
func (v *Verifier) Middleware(endpointURL string, next http.Handler) http.Handler {
	want := normalizeHTU(endpointURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := v.Authenticate(r, want)
		var ne *nonceError
		if errors.As(err, &ne) {
			// A protocol step, not a failure: not audited.
			w.Header().Set("DPoP-Nonce", v.nonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="use the server's DPoP nonce"`)
			http.Error(w, "use_dpop_nonce", http.StatusUnauthorized)
			return
		}
		if err != nil {
			reason := err.Error()
			var ae *authError
			if errors.As(err, &ae) {
				reason = ae.reason
			}
			v.cfg.Logger.Info("authentication failed", "reason", reason, "path", r.URL.Path)
			if v.cfg.Audit != nil {
				// A failed write can't turn into an allow: the request is
				// refused either way.
				_ = v.cfg.Audit.Append(r.Context(), audit.Record{Kind: codes.KindAuthFailed, Code: string(codes.Unauthenticated), Detail: reason})
			}
			w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, v.cfg.ResourceMetadataURL))
			w.Header().Add("WWW-Authenticate", `DPoP algs="ES256 ES384 ES512 RS256 PS256 EdDSA"`)
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// Authenticate runs every check of docs/01 D9 except introspection.
// wantHTU is the normalised canonical URL of the endpoint.
func (v *Verifier) Authenticate(r *http.Request, wantHTU string) (*Principal, error) {
	authz := r.Header.Values("Authorization")
	if len(authz) != 1 {
		return nil, fail("want exactly one Authorization header, got %d", len(authz))
	}
	scheme, token, ok := strings.Cut(authz[0], " ")
	if !ok || token == "" || strings.ContainsAny(token, " \t") {
		return nil, fail("malformed Authorization header")
	}
	scheme = strings.ToLower(scheme)
	if scheme != "bearer" && scheme != "dpop" {
		return nil, fail("unsupported scheme")
	}

	c, err := v.verifyToken(r.Context(), token)
	if err != nil {
		return nil, err
	}

	jkt := ""
	if c.CNF != nil {
		// A token bound by any other method (an mTLS x5t#S256) can't be
		// checked here, and must not pass as unbound.
		if c.CNF.JKT == "" {
			return nil, fail("cnf without jkt")
		}
		jkt = c.CNF.JKT
	}
	// Which DPoP rule applies is decided by the token's claims, never by
	// the scheme the client chose (docs/01 D9).
	if c.AZP == v.cfg.CLIClientID && jkt == "" {
		return nil, fail("CLI token without cnf.jkt")
	}
	if jkt != "" {
		if scheme != "dpop" {
			return nil, fail("DPoP-bound token presented as Bearer")
		}
		if err := v.verifyProof(r, token, jkt, wantHTU); err != nil {
			return nil, err
		}
	} else if scheme == "dpop" {
		return nil, fail("DPoP scheme with a token that isn't DPoP-bound")
	}

	h, ok := v.cfg.HumanBySubject(c.Subject)
	if !ok {
		return nil, fail("subject not in the human registry")
	}
	var key string
	if jkt != "" {
		// CLI (and any DPoP-bound client): one key per login (docs/01 D8).
		key = "dpop\x00" + c.Issuer + "\x00" + c.AZP + "\x00" + jkt
	} else {
		if c.SID == "" {
			return nil, fail("token without sid")
		}
		key = "sid\x00" + c.Issuer + "\x00" + c.AZP + "\x00" + c.SID
	}
	signedIn := time.Unix(c.AuthTime, 0)
	if c.AuthTime == 0 && c.IssuedAt != nil {
		signedIn = c.IssuedAt.Time()
	}
	return &Principal{
		Human:      h.ID,
		Subject:    c.Subject,
		AgentKey:   key,
		ClientID:   c.AZP,
		SignedInAt: signedIn.UTC(),
		JKT:        jkt,
		token:      token,
	}, nil
}

func (v *Verifier) verifyToken(ctx context.Context, token string) (*claims, error) {
	tok, err := jwt.ParseSigned(token, allowedAlgs)
	if err != nil {
		return nil, fail("token: %v", err)
	}
	if len(tok.Headers) != 1 {
		return nil, fail("token: want one signature")
	}
	kid := tok.Headers[0].KeyID
	if kid == "" {
		return nil, fail("token: no kid")
	}
	key, err := v.iss.key(ctx, kid)
	if err != nil {
		return nil, fail("token: key %q: %v", kid, err)
	}
	if string(tok.Headers[0].Algorithm) != key.Algorithm && key.Algorithm != "" {
		return nil, fail("token: alg does not match the key")
	}
	var c claims
	if err := tok.Claims(key.Key, &c); err != nil {
		return nil, fail("token: signature: %v", err)
	}
	if c.Issuer != v.iss.url {
		return nil, fail("token: wrong issuer")
	}
	// aud must be exactly Nyyrikki's resource identifier (docs/01 D9).
	if len(c.Audience) != 1 || c.Audience[0] != v.cfg.Audience {
		return nil, fail("token: wrong audience")
	}
	if c.Expiry == nil {
		return nil, fail("token: no exp")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Time: v.cfg.Now()}, maxSkew); err != nil {
		return nil, fail("token: %v", err)
	}
	// Only access tokens (INV-06): Keycloak marks them "Bearer" or "DPoP";
	// an ID or refresh token carrying the audience is refused.
	if c.Typ != "Bearer" && c.Typ != "DPoP" {
		return nil, fail("token: not an access token")
	}
	if c.Subject == "" || c.AZP == "" {
		return nil, fail("token: missing sub or azp")
	}
	return &c, nil
}

func (v *Verifier) verifyProof(r *http.Request, token, jkt, wantHTU string) error {
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return fail("want exactly one DPoP header, got %d", len(proofs))
	}
	jws, err := jose.ParseSigned(proofs[0], allowedAlgs)
	if err != nil {
		return fail("proof: %v", err)
	}
	if len(jws.Signatures) != 1 {
		return fail("proof: want one signature")
	}
	h := jws.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return fail("proof: typ is not dpop+jwt")
	}
	jwk := h.JSONWebKey
	if jwk == nil || !jwk.IsPublic() || !jwk.Valid() {
		return fail("proof: jwk missing, private or invalid")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return fail("proof: signature: %v", err)
	}
	var c dpop.Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return fail("proof: claims: %v", err)
	}
	if c.HTM != r.Method {
		return fail("proof: htm")
	}
	if wantHTU == "" || normalizeHTU(c.HTU) != wantHTU {
		return fail("proof: htu")
	}
	now := v.cfg.Now()
	iat := time.Unix(c.IAT, 0)
	if iat.Before(now.Add(-proofPast)) || iat.After(now.Add(proofFuture)) {
		return fail("proof: iat outside the window")
	}
	if iat.Before(v.start) {
		return fail("proof: iat before the process started")
	}
	// The server nonce (RFC 9449 §8) is made per process, so a proof made
	// before a restart can't be replayed into the new process's empty
	// replay cache. A missing or stale nonce is answered with the current
	// one, and the client retries.
	if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(v.nonce)) != 1 {
		return &nonceError{}
	}
	if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(dpop.ATH(token))) != 1 {
		return fail("proof: ath")
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return fail("proof: thumbprint: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(tp)), []byte(jkt)) != 1 {
		return fail("proof: key does not match cnf.jkt")
	}
	if c.JTI == "" || len(c.JTI) > 256 {
		return fail("proof: jti")
	}
	// Checked last, so only proofs that are otherwise valid take a slot.
	// Remembered until its iat leaves the window, measured on the same
	// clock as the iat check.
	if err := v.replays.add(c.JTI, now, iat.Add(proofPast+time.Second)); err != nil {
		return fail("proof: %v", err)
	}
	return nil
}

// nonceError asks the client to retry with the server's DPoP nonce.
type nonceError struct{}

func (*nonceError) Error() string { return "unauthenticated: proof without the server's DPoP nonce" }

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Nonce returns the server's current DPoP nonce.
func (v *Verifier) Nonce() string { return v.nonce }

// replayCache remembers proof jtis for the acceptance window. When full,
// it refuses rather than evicts (docs/01 D9).
type replayCache struct {
	mu   sync.Mutex
	max  int
	seen map[string]time.Time
}

func newReplayCache(max int) *replayCache {
	return &replayCache{max: max, seen: map[string]time.Time{}}
}

func (c *replayCache) add(jti string, now, until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[jti]; ok && now.Before(exp) {
		return errors.New("jti replayed")
	}
	if len(c.seen) >= c.max {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.max {
			return errors.New("replay cache full")
		}
	}
	c.seen[jti] = until
	return nil
}
