// Package authntest is a test authorization server: OIDC discovery, JWKS,
// introspection, the device grant (with DPoP binding), refresh and Dynamic
// Client Registration (docs/01 §5.8). It issues tokens with chosen claims.
package authntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Server is a running test authorization server.
type Server struct {
	*httptest.Server
	Key *ecdsa.PrivateKey
	KID string
	// Audience is put into aud of issued tokens.
	Audience string
	// Subject is the sub of tokens issued through the device grant.
	Subject string
	// DPoPClients lists client IDs whose tokens must be DPoP-bound.
	DPoPClients map[string]bool
	// IntrospectionClient and IntrospectionSecret authenticate
	// introspection.
	IntrospectionClient, IntrospectionSecret string
	// AutoApprove approves every device code as it is created (the human
	// signs in at once).
	AutoApprove bool
	// OfflineAccess makes the server advertise the offline_access scope
	// in its metadata, as Keycloak does when the realm offers it.
	OfflineAccess bool
	// NoOfflineScope lists client IDs that don't have the offline_access
	// client scope: a device request asking for it is answered
	// invalid_scope, as Keycloak answers a scope the client lacks
	// (docs/01 OD18; the e2e test checks Keycloak does).
	NoOfflineScope map[string]bool
	// RequirePKCE makes the device grant require PKCE with S256, as
	// Keycloak does for a client whose PKCE method is set (it sets it on
	// every registered client under a pkce-enforcer client policy).
	RequirePKCE bool
	// Now is the clock for issued tokens.
	Now func() time.Time

	mu       sync.Mutex
	inactive map[string]bool // sid → revoked
	down     bool
	devices  map[string]*device
	refresh  map[string]*session
	clients  map[string]string // DCR client_id → name
	scopes   map[string]string // client_id → scope of its last device request
	nextSID  int
}

type device struct {
	clientID  string
	approved  bool
	challenge string // S256 code challenge, if one was sent
}

type session struct {
	clientID, sid, jkt string
}

// New starts a server. Close it with t.Cleanup (done for you).
func New(t testing.TB) *Server {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Key: k, KID: "k1", Subject: "owner-sub",
		DPoPClients:         map[string]bool{"nyyrikki-cli": true},
		IntrospectionClient: "nyyrikki-introspect", IntrospectionSecret: "s3cret",
		Now:      time.Now,
		inactive: map[string]bool{}, devices: map[string]*device{},
		refresh: map[string]*session{}, clients: map[string]string{}, scopes: map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/introspect", s.introspect)
	mux.HandleFunc("/device", s.deviceAuth)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/register", s.register)
	s.Server = httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)
	return s
}

// RotateKey replaces the signing key, keeping the kid.
func (s *Server) RotateKey(t testing.TB) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.Key = k
	s.mu.Unlock()
}

// Issuer is the issuer URL.
func (s *Server) Issuer() string { return s.URL }

// SetDown makes every endpoint answer 503.
func (s *Server) SetDown(down bool) { s.mu.Lock(); s.down = down; s.mu.Unlock() }

// Revoke makes introspection report sid inactive.
func (s *Server) Revoke(sid string) { s.mu.Lock(); s.inactive[sid] = true; s.mu.Unlock() }

// ApproveDevice approves every pending device code (the human signs in).
func (s *Server) ApproveDevice() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		d.approved = true
	}
}

func (s *Server) isDown(w http.ResponseWriter) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}
	return s.down
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	if s.isDown(w) {
		return
	}
	scopes := []string{"openid", "nyyrikki"}
	if s.OfflineAccess {
		scopes = append(scopes, "offline_access")
	}
	writeJSON(w, map[string]any{
		"scopes_supported":              scopes,
		"issuer":                        s.URL,
		"jwks_uri":                      s.URL + "/jwks",
		"introspection_endpoint":        s.URL + "/introspect",
		"device_authorization_endpoint": s.URL + "/device",
		"token_endpoint":                s.URL + "/token",
		"registration_endpoint":         s.URL + "/register",
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	if s.isDown(w) {
		return
	}
	s.mu.Lock()
	k := s.Key
	s.mu.Unlock()
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: s.KID, Algorithm: "ES256", Use: "sig"}}})
}

// Claims are the claims of a token to issue. Zero fields get defaults in
// Token.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	AZP       string
	SID       string
	JKT       string
	Expiry    time.Time
	NotBefore time.Time
	NoExpiry  bool
	// CNF, if set, replaces the cnf claim (JKT is then ignored).
	CNF map[string]string
	// Typ is the token type claim; empty means "Bearer", or "DPoP" when
	// JKT is set, as Keycloak issues access tokens. "-" leaves it out.
	Typ string
}

// Token signs a token with the given claims, filling defaults for empty
// fields (issuer, subject, audience, an expiry 5 minutes from now).
func (s *Server) Token(t testing.TB, c Claims) string {
	t.Helper()
	s.mu.Lock()
	k := s.Key
	s.mu.Unlock()
	tok, err := s.sign(c, k, s.KID)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TokenSignedBy signs with another key, kid and algorithm (negative tests).
func (s *Server) TokenSignedBy(t testing.TB, c Claims, key any, kid string, alg jose.SignatureAlgorithm) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwt.Signed(sig).Claims(s.claimsMap(c)).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (s *Server) claimsMap(c Claims) map[string]any {
	now := s.Now()
	if c.Issuer == "" {
		c.Issuer = s.URL
	}
	if c.Subject == "" {
		c.Subject = s.Subject
	}
	if c.Audience == nil {
		c.Audience = []string{s.Audience}
	}
	if c.Expiry.IsZero() {
		c.Expiry = now.Add(5 * time.Minute)
	}
	m := map[string]any{
		"iss": c.Issuer, "sub": c.Subject, "aud": c.Audience,
		"iat": now.Unix(), "auth_time": now.Unix(), "azp": c.AZP,
	}
	if !c.NoExpiry {
		m["exp"] = c.Expiry.Unix()
	}
	if !c.NotBefore.IsZero() {
		m["nbf"] = c.NotBefore.Unix()
	}
	if c.SID != "" {
		m["sid"] = c.SID
	}
	switch {
	case c.Typ == "-":
	case c.Typ != "":
		m["typ"] = c.Typ
	case c.JKT != "":
		m["typ"] = "DPoP"
	default:
		m["typ"] = "Bearer"
	}
	if c.JKT != "" {
		m["cnf"] = map[string]string{"jkt": c.JKT}
	}
	if c.CNF != nil {
		m["cnf"] = c.CNF
	}
	return m
}

func (s *Server) sign(c Claims, key crypto.Signer, kid string) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid).WithType("JWT"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(sig).Claims(s.claimsMap(c)).Serialize()
}

func (s *Server) introspect(w http.ResponseWriter, r *http.Request) {
	if s.isDown(w) {
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok || id != s.IntrospectionClient || secret != s.IntrospectionSecret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tok, err := jwt.ParseSigned(r.FormValue("token"), []jose.SignatureAlgorithm{jose.ES256})
	var m map[string]any
	if err == nil {
		s.mu.Lock()
		k := s.Key
		s.mu.Unlock()
		err = tok.Claims(&k.PublicKey, &m)
	}
	if err != nil {
		writeJSON(w, map[string]any{"active": false})
		return
	}
	sid, _ := m["sid"].(string)
	s.mu.Lock()
	revoked := s.inactive[sid]
	s.mu.Unlock()
	if revoked {
		writeJSON(w, map[string]any{"active": false})
		return
	}
	out := map[string]any{"active": true, "client_id": m["azp"], "sub": m["sub"]}
	if cnf, ok := m["cnf"]; ok {
		out["cnf"] = cnf
	}
	writeJSON(w, out)
}

func (s *Server) deviceAuth(w http.ResponseWriter, r *http.Request) {
	if s.isDown(w) {
		return
	}
	challenge, method := r.FormValue("code_challenge"), r.FormValue("code_challenge_method")
	if (s.RequirePKCE || challenge != "") && (challenge == "" || method != "S256") {
		oauthError(w, "invalid_request", "Missing parameter: code_challenge_method")
		return
	}
	if s.NoOfflineScope[r.FormValue("client_id")] && slices.Contains(strings.Fields(r.FormValue("scope")), "offline_access") {
		oauthError(w, "invalid_scope", "Invalid scopes: "+r.FormValue("scope"))
		return
	}
	code := randString()
	s.mu.Lock()
	s.devices[code] = &device{clientID: r.FormValue("client_id"), approved: s.AutoApprove, challenge: challenge}
	s.scopes[r.FormValue("client_id")] = r.FormValue("scope")
	s.mu.Unlock()
	writeJSON(w, map[string]any{
		"device_code": code, "user_code": "ABCD-EFGH",
		"verification_uri": s.URL + "/verify", "verification_uri_complete": s.URL + "/verify?code=ABCD-EFGH",
		"expires_in": 600, "interval": 1,
	})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if s.isDown(w) {
		return
	}
	var req struct {
		ClientName string   `json:"client_name"`
		GrantTypes []string `json:"grant_types"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	id := "dcr-" + randString()[:12]
	s.mu.Lock()
	s.clients[id] = req.ClientName
	s.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"client_id": id, "client_name": req.ClientName, "grant_types": req.GrantTypes, "token_endpoint_auth_method": "none"})
}

// DeviceScope is the scope a client asked for in its last device
// authorization request.
func (s *Server) DeviceScope(clientID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopes[clientID]
}

// Registered returns the DCR client IDs registered so far.
func (s *Server) Registered() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id := range s.clients {
		out = append(out, id)
	}
	return out
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if s.isDown(w) {
		return
	}
	clientID := r.FormValue("client_id")
	jkt := ""
	if proof := r.Header.Get("DPoP"); proof != "" {
		var err error
		if jkt, err = proofThumbprint(proof, r.Method, s.URL+"/token"); err != nil {
			oauthError(w, "invalid_dpop_proof", err.Error())
			return
		}
	}
	if s.DPoPClients[clientID] && jkt == "" {
		oauthError(w, "invalid_dpop_proof", "DPoP required")
		return
	}
	var sess *session
	switch r.FormValue("grant_type") {
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.mu.Lock()
		d := s.devices[r.FormValue("device_code")]
		s.mu.Unlock()
		if d == nil || d.clientID != clientID {
			oauthError(w, "invalid_grant", "unknown device code")
			return
		}
		if !d.approved {
			oauthError(w, "authorization_pending", "")
			return
		}
		if d.challenge != "" {
			sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != d.challenge {
				oauthError(w, "invalid_grant", "PKCE verification failed")
				return
			}
		}
		s.mu.Lock()
		delete(s.devices, r.FormValue("device_code"))
		s.nextSID++
		sess = &session{clientID: clientID, sid: fmt.Sprintf("sid-%d", s.nextSID), jkt: jkt}
		s.mu.Unlock()
	case "refresh_token":
		s.mu.Lock()
		sess = s.refresh[r.FormValue("refresh_token")]
		delete(s.refresh, r.FormValue("refresh_token"))
		s.mu.Unlock()
		if sess == nil || sess.clientID != clientID || sess.jkt != jkt {
			oauthError(w, "invalid_grant", "bad refresh token or key")
			return
		}
	default:
		oauthError(w, "unsupported_grant_type", "")
		return
	}
	at, err := s.sign(Claims{AZP: clientID, SID: sess.sid, JKT: sess.jkt}, s.Key, s.KID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rt := randString()
	s.mu.Lock()
	s.refresh[rt] = sess
	s.mu.Unlock()
	typ := "Bearer"
	if sess.jkt != "" {
		typ = "DPoP"
	}
	writeJSON(w, map[string]any{"access_token": at, "token_type": typ, "expires_in": 300, "refresh_token": rt})
}

func proofThumbprint(proof, method, htu string) (string, error) {
	jws, err := jose.ParseSignedCompact(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return "", err
	}
	jwk := jws.Signatures[0].Protected.JSONWebKey
	if jwk == nil {
		return "", fmt.Errorf("no jwk")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return "", err
	}
	var c struct {
		HTM string `json:"htm"`
		HTU string `json:"htu"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", err
	}
	if c.HTM != method || strings.TrimSuffix(c.HTU, "/") != htu {
		return "", fmt.Errorf("htm/htu mismatch")
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func oauthError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
