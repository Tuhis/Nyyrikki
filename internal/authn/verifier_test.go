package authn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/authn/authntest"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/dpop"
)

const mcpURL = "https://nyyrikki.example.com/mcp"

type recAudit struct {
	mu   sync.Mutex
	recs []audit.Record
}

func (r *recAudit) Append(_ context.Context, rec audit.Record) error {
	r.mu.Lock()
	r.recs = append(r.recs, rec)
	r.mu.Unlock()
	return nil
}

type fixture struct {
	as    *authntest.Server
	v     *authn.Verifier
	audit *recAudit
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	as := authntest.New(t)
	as.Audience = mcpURL
	f := &fixture{as: as, audit: &recAudit{}, now: time.Now()}
	as.Now = func() time.Time { return f.now }
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(as.IntrospectionSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.v = authn.NewVerifier(authn.Config{
		Issuer:      as.Issuer(),
		CLIClientID: "nyyrikki-cli",
		Audience:    mcpURL,
		HumanBySubject: func(sub string) (authn.Human, bool) {
			return authn.Human{ID: "owner"}, sub == "owner-sub"
		},
		ResourceMetadataURL:     "https://nyyrikki.example.com/.well-known/oauth-protected-resource/mcp",
		IntrospectionClientID:   as.IntrospectionClient,
		IntrospectionSecretFile: secret,
		HTTPClient:              as.Client(),
		Now:                     func() time.Time { return f.now },
		Audit:                   f.audit,
	})
	return f
}

type req struct {
	scheme string
	token  string
	proofs []string
	method string
	auths  []string // overrides scheme+token when set
}

func (f *fixture) do(t *testing.T, r req) (*authn.Principal, int) {
	t.Helper()
	var got *authn.Principal
	h := f.v.Middleware(mcpURL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = authn.FromContext(r.Context())
	}))
	m := r.method
	if m == "" {
		m = http.MethodPost
	}
	hr := httptest.NewRequest(m, "https://evil.example.com/mcp", nil)
	if r.auths != nil {
		for _, a := range r.auths {
			hr.Header.Add("Authorization", a)
		}
	} else {
		hr.Header.Set("Authorization", r.scheme+" "+r.token)
	}
	for _, p := range r.proofs {
		hr.Header.Add("DPoP", p)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hr)
	return got, w.Code
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jkt(t *testing.T, k *ecdsa.PrivateKey) string {
	j, err := dpop.Thumbprint(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func proof(t *testing.T, nonce string, k *ecdsa.PrivateKey, method, u, tok string, at time.Time) string {
	p, err := dpop.Proof(k, method, u, tok, nonce, at)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBearerMCPTokenAccepted(t *testing.T) {
	f := newFixture(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "claude-code", SID: "s1"})
	p, code := f.do(t, req{scheme: "Bearer", token: tok})
	if code != 200 || p == nil {
		t.Fatalf("code %d", code)
	}
	if p.Human != "owner" || p.ClientID != "claude-code" || !strings.Contains(p.AgentKey, "s1") || p.JKT != "" {
		t.Fatalf("principal %+v", p)
	}
}

func TestDPoPCLITokenAccepted(t *testing.T) {
	f := newFixture(t)
	k := mustKey(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "nyyrikki-cli", SID: "s1", JKT: jkt(t, k)})
	p, code := f.do(t, req{scheme: "DPoP", token: tok, proofs: []string{proof(t, f.v.Nonce(), k, "POST", mcpURL, tok, f.now)}})
	if code != 200 || p == nil {
		t.Fatalf("code %d", code)
	}
	if p.JKT != jkt(t, k) || !strings.Contains(p.AgentKey, p.JKT) {
		t.Fatalf("principal %+v", p)
	}
	// Two logins in one browser session share sid but are two agents
	// (docs/01 OD14).
	k2 := mustKey(t)
	tok2 := f.as.Token(t, authntest.Claims{AZP: "nyyrikki-cli", SID: "s1", JKT: jkt(t, k2)})
	p2, _ := f.do(t, req{scheme: "DPoP", token: tok2, proofs: []string{proof(t, f.v.Nonce(), k2, "POST", mcpURL, tok2, f.now)}})
	if p2 == nil || p2.AgentKey == p.AgentKey {
		t.Fatal("two DPoP logins got the same agent key")
	}
}

func TestTokenRejected(t *testing.T) {
	f := newFixture(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherEC, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	base := authntest.Claims{AZP: "claude-code", SID: "s1"}
	with := func(mod func(c *authntest.Claims)) string {
		c := base
		mod(&c)
		return f.as.Token(t, c)
	}
	cases := map[string]req{
		"wrong issuer":      {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Issuer = "https://evil" })},
		"wrong audience":    {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Audience = []string{"https://other/mcp"} })},
		"extra audience":    {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Audience = []string{mcpURL, "account"} })},
		"expired":           {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Expiry = f.now.Add(-31 * time.Second) })},
		"no exp":            {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.NoExpiry = true })},
		"not yet valid":     {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.NotBefore = f.now.Add(time.Minute) })},
		"unknown subject":   {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Subject = "stranger" })},
		"ID token":          {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Typ = "ID" })},
		"refresh token":     {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Typ = "Refresh" })},
		"no typ":            {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.Typ = "-" })},
		"no sid":            {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.SID = "" })},
		"no azp":            {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.AZP = "" })},
		"CLI without jkt":   {scheme: "Bearer", token: with(func(c *authntest.Claims) { c.AZP = "nyyrikki-cli" })},
		"foreign key":       {scheme: "Bearer", token: f.as.TokenSignedBy(t, base, otherEC, f.as.KID, jose.ES256)},
		"unknown kid":       {scheme: "Bearer", token: f.as.TokenSignedBy(t, base, f.as.Key, "nope", jose.ES256)},
		"HS256":             {scheme: "Bearer", token: f.as.TokenSignedBy(t, base, []byte("0123456789abcdef0123456789abcdef"), f.as.KID, jose.HS256)},
		"RSA under EC kid":  {scheme: "Bearer", token: f.as.TokenSignedBy(t, base, rsaKey, f.as.KID, jose.RS256)},
		"garbage":           {scheme: "Bearer", token: "not.a.jwt"},
		"basic scheme":      {scheme: "Basic", token: with(func(*authntest.Claims) {})},
		"two Authorization": {auths: []string{"Bearer " + with(func(*authntest.Claims) {}), "Bearer x"}},
		"no Authorization":  {auths: []string{}},
		"unbound as DPoP":   {scheme: "DPoP", token: with(func(*authntest.Claims) {})},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(f.audit.recs)
			if p, code := f.do(t, r); code != http.StatusUnauthorized || p != nil {
				t.Fatalf("code %d, principal %v", code, p)
			}
			if len(f.audit.recs) != before+1 || f.audit.recs[before].Kind != codes.KindAuthFailed {
				t.Fatal("rejection not audited")
			}
		})
	}
}

func TestChallenge(t *testing.T) {
	f := newFixture(t)
	h := f.v.Middleware(mcpURL, http.NotFoundHandler())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", mcpURL, nil))
	if w.Code != 401 || !strings.Contains(strings.Join(w.Header().Values("WWW-Authenticate"), "\n"), `resource_metadata="https://nyyrikki.example.com/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("code %d headers %v", w.Code, w.Header())
	}
}

func TestDPoPRejected(t *testing.T) {
	f := newFixture(t)
	k := mustKey(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "nyyrikki-cli", SID: "s1", JKT: jkt(t, k)})
	// Any DPoP-bound token, whatever its azp.
	other := f.as.Token(t, authntest.Claims{AZP: "some-mcp-client", SID: "s1", JKT: jkt(t, k)})
	good := func() string { return proof(t, f.v.Nonce(), k, "POST", mcpURL, tok, f.now) }
	sign := func(c dpop.Claims, hdr map[jose.HeaderKey]any, key *ecdsa.PrivateKey) string {
		p, err := dpop.Sign(key, c, hdr)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	claims := func(mod func(*dpop.Claims)) dpop.Claims {
		c := dpop.Claims{JTI: "j-" + time.Now().String(), HTM: "POST", HTU: mcpURL, IAT: f.now.Unix(), ATH: dpop.ATH(tok), Nonce: f.v.Nonce()}
		mod(&c)
		return c
	}
	replayed := good()
	if _, code := f.do(t, req{scheme: "DPoP", token: tok, proofs: []string{replayed}}); code != 200 {
		t.Fatalf("first use of proof: %d", code)
	}
	cases := map[string]req{
		"no proof":              {scheme: "DPoP", token: tok},
		"bound token as Bearer": {scheme: "Bearer", token: tok, proofs: []string{good()}},
		"other azp as Bearer":   {scheme: "Bearer", token: other},
		"two proofs":            {scheme: "DPoP", token: tok, proofs: []string{good(), good()}},
		"replayed jti":          {scheme: "DPoP", token: tok, proofs: []string{replayed}},
		"wrong htm":             {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(c *dpop.Claims) { c.HTM = "GET" }), nil, k)}},
		"wrong htu":             {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(c *dpop.Claims) { c.HTU = "https://evil.example.com/mcp" }), nil, k)}},
		"stream htu on mcp":     {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(c *dpop.Claims) { c.HTU = "https://nyyrikki.example.com/stream" }), nil, k)}},
		"wrong ath":             {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(c *dpop.Claims) { c.ATH = dpop.ATH("other") }), nil, k)}},
		"old iat":               {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(c *dpop.Claims) { c.IAT = f.now.Add(-61 * time.Second).Unix() }), nil, k)}},
		"future iat":            {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(c *dpop.Claims) { c.IAT = f.now.Add(31 * time.Second).Unix() }), nil, k)}},
		"different key":         {scheme: "DPoP", token: tok, proofs: []string{proof(t, f.v.Nonce(), mustKey(t), "POST", mcpURL, tok, f.now)}},
		"wrong typ":             {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(*dpop.Claims) {}), map[jose.HeaderKey]any{jose.HeaderType: "JWT"}, k)}},
		"private jwk":           {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(*dpop.Claims) {}), map[jose.HeaderKey]any{"jwk": jose.JSONWebKey{Key: k}}, k)}},
		"alg none":              {scheme: "DPoP", token: tok, proofs: []string{unsignedProof(claims(func(*dpop.Claims) {}))}},
		"no jti":                {scheme: "DPoP", token: tok, proofs: []string{sign(claims(func(c *dpop.Claims) { c.JTI = "" }), nil, k)}},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if p, code := f.do(t, r); code != http.StatusUnauthorized || p != nil {
				t.Fatalf("code %d", code)
			}
		})
	}
}

func unsignedProof(c dpop.Claims) string {
	// header {"alg":"none","typ":"dpop+jwt"}
	return "eyJhbGciOiJub25lIiwidHlwIjoiZHBvcCtqd3QifQ." + b64json(c) + "."
}

// TestSlowClockProofAccepted: a proof carrying this process's nonce can't
// predate the process, so a CLI whose clock lags isn't refused after a
// restart (found in review of #10, R1; replaces an iat-before-start check).
func TestSlowClockProofAccepted(t *testing.T) {
	f := newFixture(t)
	k := mustKey(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "nyyrikki-cli", SID: "s1", JKT: jkt(t, k)})
	p := proof(t, f.v.Nonce(), k, "POST", mcpURL, tok, f.now.Add(-10*time.Second))
	if _, code := f.do(t, req{scheme: "DPoP", token: tok, proofs: []string{p}}); code != 200 {
		t.Fatalf("proof from a slow clock refused: %d", code)
	}
}

// TestCancelledCallerDoesNotBlockRefetch: a caller that hangs up during the
// hourly refetch must not leave everyone refused for a minute (R3).
func TestCancelledCallerDoesNotBlockRefetch(t *testing.T) {
	f := newFixture(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "claude-code", SID: "s1", Expiry: f.now.Add(3 * time.Hour)})
	if _, code := f.do(t, req{scheme: "Bearer", token: tok}); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	f.now = f.now.Add(2 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", mcpURL, nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+tok)
	f.v.Middleware(mcpURL, http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), r)
	if _, code := f.do(t, req{scheme: "Bearer", token: tok}); code != 200 {
		t.Fatalf("refused after another caller hung up during the refetch: %d", code)
	}
}

func TestIntrospect(t *testing.T) {
	f := newFixture(t)
	k := mustKey(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "nyyrikki-cli", SID: "s9", JKT: jkt(t, k)})
	p, code := f.do(t, req{scheme: "DPoP", token: tok, proofs: []string{proof(t, f.v.Nonce(), k, "POST", mcpURL, tok, f.now)}})
	if code != 200 {
		t.Fatal(code)
	}
	if err := f.v.Introspect(context.Background(), p); err != nil {
		t.Fatalf("live session: %v", err)
	}
	f.as.Revoke("s9")
	if err := f.v.Introspect(context.Background(), p); codes.Of(err) != codes.SessionInactive {
		t.Fatalf("revoked: %v", err)
	}
	f.as.SetDown(true)
	if err := f.v.Introspect(context.Background(), p); codes.Of(err) != codes.IntrospectionFailed {
		t.Fatalf("down: %v", err)
	}
}

func TestIntrospectMismatch(t *testing.T) {
	f := newFixture(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "claude-code", SID: "s1"})
	// A principal whose client ID differs from what the server reports.
	p := authn.NewPrincipalForTest(authn.Principal{ClientID: "other", Subject: "owner-sub"}, tok)
	if err := f.v.Introspect(context.Background(), p); codes.Of(err) != codes.IntrospectionFailed {
		t.Fatalf("client_id mismatch: %v", err)
	}
	k := mustKey(t)
	p = authn.NewPrincipalForTest(authn.Principal{ClientID: "claude-code", Subject: "owner-sub", JKT: jkt(t, k)}, tok)
	if err := f.v.Introspect(context.Background(), p); codes.Of(err) != codes.IntrospectionFailed {
		t.Fatalf("jkt lost: %v", err)
	}
}

// TestDPoPNonce: a proof without the server's nonce, or with another
// process's (one made before a restart), is answered with use_dpop_nonce and
// the current nonce, and isn't audited as a failure. Replaces a 30 s window
// after start (found in review of #10, N2).
func TestDPoPNonce(t *testing.T) {
	f := newFixture(t)
	k := mustKey(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "nyyrikki-cli", SID: "s1", JKT: jkt(t, k)})
	other := authn.NewVerifier(authn.Config{Issuer: f.as.Issuer()}).Nonce()
	if other == f.v.Nonce() {
		t.Fatal("two processes share a nonce")
	}
	for name, nonce := range map[string]string{"no nonce": "", "previous process": other} {
		before := len(f.audit.recs)
		h := f.v.Middleware(mcpURL, http.NotFoundHandler())
		r := httptest.NewRequest("POST", mcpURL, nil)
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Set("DPoP", proof(t, nonce, k, "POST", mcpURL, tok, f.now))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("DPoP-Nonce") != f.v.Nonce() || !strings.Contains(w.Header().Get("WWW-Authenticate"), "use_dpop_nonce") {
			t.Fatalf("%s: %d %v", name, w.Code, w.Header())
		}
		if len(f.audit.recs) != before {
			t.Errorf("%s: a nonce challenge was audited as a failure", name)
		}
	}
	if _, code := f.do(t, req{scheme: "DPoP", token: tok, proofs: []string{proof(t, f.v.Nonce(), k, "POST", mcpURL, tok, f.now)}}); code != 200 {
		t.Fatalf("proof with the nonce: %d", code)
	}
}

// TestOtherConfirmationMethodRejected: a token bound by a cnf method other
// than jkt (an mTLS x5t#S256) is not treated as unbound (L5).
func TestOtherConfirmationMethodRejected(t *testing.T) {
	f := newFixture(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "claude-code", SID: "s1", CNF: map[string]string{"x5t#S256": "abc"}})
	if _, code := f.do(t, req{scheme: "Bearer", token: tok}); code != 401 {
		t.Fatalf("token bound by another method accepted as Bearer: %d", code)
	}
}

// TestRemovedKeyStopsVerifying: the cached key set has a maximum age, so a
// key removed from the authorization server stops verifying tokens (L6).
func TestRemovedKeyStopsVerifying(t *testing.T) {
	f := newFixture(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "claude-code", SID: "s1", Expiry: f.now.Add(3 * time.Hour)})
	if _, code := f.do(t, req{scheme: "Bearer", token: tok}); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	f.as.RotateKey(t) // same kid, new key: the old one is gone
	f.now = f.now.Add(2 * time.Hour)
	if _, code := f.do(t, req{scheme: "Bearer", token: tok}); code != 401 {
		t.Fatalf("token signed by a removed key still accepted: %d", code)
	}
}

// TestConcurrentRefetchWaits: when the key set is due for its hourly
// refetch, concurrent calls wait for the one fetch in flight instead of
// being refused (found in review of #10, N3).
func TestConcurrentRefetchWaits(t *testing.T) {
	f := newFixture(t)
	tok := f.as.Token(t, authntest.Claims{AZP: "claude-code", SID: "s1", Expiry: f.now.Add(3 * time.Hour)})
	if _, code := f.do(t, req{scheme: "Bearer", token: tok}); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	f.now = f.now.Add(2 * time.Hour)
	var wg sync.WaitGroup
	codes := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, code := f.do(t, req{scheme: "Bearer", token: tok})
			codes <- code
		}()
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Fatalf("a concurrent call was refused during the refetch: %d", c)
		}
	}
}
