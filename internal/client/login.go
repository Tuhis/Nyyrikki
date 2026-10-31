// Package client is the CLI's side of Nyyrikki: signing in, keeping the
// login file, DPoP, and calling the tools on /mcp (docs/02 D12, docs/01
// §5.4, D25). It decides nothing; the server does.
package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/dpop"
)

// Login is the content of a login file. Whoever can read it is that agent
// (SECURITY.md, deployment requirements), so it is written 0600.
type Login struct {
	Server        string    `json:"server"`
	MCPURL        string    `json:"mcp_url"`
	StreamURL     string    `json:"stream_url"`
	Issuer        string    `json:"issuer"`
	ClientID      string    `json:"client_id"`
	TokenEndpoint string    `json:"token_endpoint"`
	CAFile        string    `json:"ca_file,omitempty"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	ExpiresAt     time.Time `json:"expires_at"`
	// DPoPKey is the PKCS#8 key of this login, base64; empty for an
	// `--mcp` login, whose tokens aren't DPoP-bound (docs/01 D25).
	DPoPKey string `json:"dpop_key,omitempty"`
	MCP     bool   `json:"mcp,omitempty"`

	key  *ecdsa.PrivateKey
	path string
	// nonce is Nyyrikki's current DPoP nonce (RFC 9449 §8), learnt from
	// its use_dpop_nonce answer; kept in memory only.
	nonceMu sync.Mutex
	nonce   string
}

// SetNonce records the server's DPoP nonce.
func (l *Login) SetNonce(n string) {
	l.nonceMu.Lock()
	l.nonce = n
	l.nonceMu.Unlock()
}

func (l *Login) currentNonce() string {
	l.nonceMu.Lock()
	defer l.nonceMu.Unlock()
	return l.nonce
}

// DefaultPath returns the default login file path.
func DefaultPath(mcp bool) (string, error) {
	if p := os.Getenv("NYYRIKKI_LOGIN_FILE"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	name := "login.json"
	if mcp {
		name = "mcp-login.json"
	}
	return filepath.Join(dir, "nyyrikki", name), nil
}

// ErrNotSignedIn means there is no usable login file.
var ErrNotSignedIn = errors.New("not signed in: run `nyyrikki login`")

// LoadLogin reads a login file.
func LoadLogin(path string) (*Login, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotSignedIn
	}
	if err != nil {
		return nil, err
	}
	var l Login
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("login file %s: %w", path, err)
	}
	l.path = path
	if l.DPoPKey != "" {
		der, err := base64.StdEncoding.DecodeString(l.DPoPKey)
		if err != nil {
			return nil, err
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("login file: DPoP key is not ECDSA")
		}
		l.key = ek
	}
	return &l, nil
}

// Save writes the login file atomically, mode 0600.
func (l *Login) Save() error {
	if l.key != nil {
		der, err := x509.MarshalPKCS8PrivateKey(l.key)
		if err != nil {
			return err
		}
		l.DPoPKey = base64.StdEncoding.EncodeToString(der)
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(l.path), ".login-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), l.path)
}

// HTTPClient returns the client for Nyyrikki and the authorization server:
// no proxy from the environment, the login's CA file if any.
func HTTPClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// LoginOptions configures a sign-in.
type LoginOptions struct {
	Server   string // Nyyrikki's canonical base URL
	ClientID string // override the CLI client from the server's metadata
	CAFile   string
	MCP      bool // `nyyrikki login --mcp` (docs/01 D25)
	Path     string
	Force    bool
	// ClientName is the DCR client name for --mcp.
	ClientName string
	// Prompt shows the device-code instructions to the human.
	Prompt func(verificationURI, userCode, complete string)
	// Notice tells the human something about the sign-in that isn't an
	// error.
	Notice func(string)
	Now    func() time.Time
}

type resourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
	CLIClientID          string   `json:"nyyrikki_cli_client_id"`
}

type asMetadata struct {
	Issuer                      string   `json:"issuer"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	RegistrationEndpoint        string   `json:"registration_endpoint"`
	ScopesSupported             []string `json:"scopes_supported"`
}

func getJSON(ctx context.Context, hc *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// SignIn runs the device authorization grant (docs/01 §5.4) and writes a
// new login file. It refuses to replace an existing login unless Force.
func SignIn(ctx context.Context, o LoginOptions) (*Login, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if _, err := os.Stat(o.Path); err == nil && !o.Force {
		return nil, fmt.Errorf("%s already holds a login; pass --force to replace it", o.Path)
	}
	base := strings.TrimSuffix(o.Server, "/")
	if u, err := url.Parse(base); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("--server must be Nyyrikki's https URL")
	}
	hc, err := HTTPClient(o.CAFile)
	if err != nil {
		return nil, err
	}
	var rm resourceMetadata
	if err := getJSON(ctx, hc, base+"/.well-known/oauth-protected-resource/mcp", &rm); err != nil {
		return nil, fmt.Errorf("reading Nyyrikki's metadata: %w", err)
	}
	if rm.Resource != base+"/mcp" || len(rm.AuthorizationServers) != 1 {
		return nil, errors.New("the server's metadata doesn't match its URL")
	}
	issuer := rm.AuthorizationServers[0]
	var am asMetadata
	if err := getJSON(ctx, hc, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &am); err != nil {
		return nil, fmt.Errorf("reading the authorization server's metadata: %w", err)
	}
	if am.Issuer != issuer || am.DeviceAuthorizationEndpoint == "" || am.TokenEndpoint == "" {
		return nil, errors.New("the authorization server doesn't offer the device grant")
	}

	l := &Login{Server: base, MCPURL: base + "/mcp", StreamURL: base + "/stream", Issuer: issuer,
		TokenEndpoint: am.TokenEndpoint, CAFile: o.CAFile, MCP: o.MCP, path: o.Path}
	if o.MCP {
		// Each `login --mcp` registers its own client, so each is its own
		// agent (docs/01 OD16).
		if am.RegistrationEndpoint == "" {
			return nil, errors.New("the authorization server doesn't offer Dynamic Client Registration")
		}
		id, err := register(ctx, hc, am.RegistrationEndpoint, o.ClientName)
		if err != nil {
			return nil, fmt.Errorf("registering a client: %w", err)
		}
		l.ClientID = id
	} else {
		l.ClientID = o.ClientID
		if l.ClientID == "" {
			l.ClientID = rm.CLIClientID
		}
		if l.ClientID == "" {
			return nil, errors.New("no CLI client ID; pass --client-id")
		}
		// A fresh key per login makes each login its own agent
		// (docs/01 OD14).
		if l.key, err = dpop.NewKey(); err != nil {
			return nil, err
		}
	}

	// PKCE with S256 (docs/01 D7). Keycloak requires it in the device
	// grant too for a client whose PKCE method is set, as its pkce-enforcer
	// client policy does for every registered client.
	verifier, challenge := pkcePair()
	scope := slices.Clone(rm.ScopesSupported)
	// Both logins may hold an offline session, so a sign-in outlives the
	// browser session: an MCP harness's since docs/01 OD17, the CLI's
	// since OD18. The CLI's stays DPoP-bound to this login's key.
	offline := slices.Contains(am.ScopesSupported, "offline_access")
	if offline {
		scope = append(scope, "offline_access")
	}
	form := url.Values{"client_id": {l.ClientID}, "scope": {strings.Join(scope, " ")},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	var da struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	err = postForm(ctx, hc, am.DeviceAuthorizationEndpoint, form, nil, &da)
	// A realm may offer offline_access without giving it to this client
	// (a CLI client set up before OD18): Keycloak answers invalid_scope.
	// Sign in without it; the login then ends with the browser session.
	var oe *oauthError
	if offline && errors.As(err, &oe) && oe.Code == "invalid_scope" {
		form.Set("scope", strings.Join(rm.ScopesSupported, " "))
		err = postForm(ctx, hc, am.DeviceAuthorizationEndpoint, form, nil, &da)
		if err == nil && o.Notice != nil {
			o.Notice("the authorization server doesn't give this client offline_access, so this login ends with your browser session")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	if o.Prompt != nil {
		o.Prompt(da.VerificationURI, da.UserCode, da.VerificationURIComplete)
	}
	interval := time.Duration(max(da.Interval, 1)) * time.Second
	deadline := o.Now().Add(time.Duration(max(da.ExpiresIn, 60)) * time.Second)
	for {
		if o.Now().After(deadline) {
			return nil, errors.New("the sign-in code expired")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		err := l.tokenRequest(ctx, hc, url.Values{
			"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code":   {da.DeviceCode},
			"client_id":     {l.ClientID},
			"code_verifier": {verifier},
		}, o.Now)
		var oe *oauthError
		if errors.As(err, &oe) && oe.Code == "authorization_pending" {
			continue
		}
		if errors.As(err, &oe) && oe.Code == "slow_down" {
			interval += 5 * time.Second
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	if err := l.Save(); err != nil {
		return nil, err
	}
	return l, nil
}

// pkcePair is a PKCE code verifier and its S256 challenge (RFC 7636).
func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func register(ctx context.Context, hc *http.Client, endpoint, name string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                name,
		"grant_types":                []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"token_endpoint_auth_method": "none",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registration: %s", resp.Status)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.ClientID == "" {
		return "", errors.New("registration: no client_id")
	}
	return out.ClientID, nil
}

type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	nonce       string
}

func (e *oauthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// postForm posts a form; header may add DPoP. A 4xx OAuth error is
// returned as *oauthError.
func postForm(ctx context.Context, hc *http.Client, endpoint string, form url.Values, header http.Header, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		var oe oauthError
		if json.Unmarshal(body, &oe) == nil && oe.Code != "" {
			oe.nonce = resp.Header.Get("DPoP-Nonce")
			return &oe
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: %s", endpoint, resp.Status)
	}
	return json.Unmarshal(body, v)
}

// tokenRequest calls the token endpoint, with a DPoP proof when the login
// has a key, retrying once with a server nonce if asked (RFC 9449 §8).
func (l *Login) tokenRequest(ctx context.Context, hc *http.Client, form url.Values, now func() time.Time) error {
	var tr struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	nonce := ""
	for attempt := 0; ; attempt++ {
		var h http.Header
		if l.key != nil {
			p, err := dpop.Proof(l.key, http.MethodPost, l.TokenEndpoint, "", nonce, now())
			if err != nil {
				return err
			}
			h = http.Header{"Dpop": {p}}
		}
		err := postForm(ctx, hc, l.TokenEndpoint, form, h, &tr)
		var oe *oauthError
		if attempt == 0 && errors.As(err, &oe) && oe.Code == "use_dpop_nonce" && oe.nonce != "" {
			nonce = oe.nonce
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if tr.AccessToken == "" {
		return errors.New("token endpoint returned no access token")
	}
	if l.key != nil && !strings.EqualFold(tr.TokenType, "DPoP") {
		// The CLI client must require DPoP (SECURITY.md); an unbound token
		// would make this login share keys with others.
		return errors.New("the authorization server issued an unbound token; the CLI client must require DPoP")
	}
	l.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		l.RefreshToken = tr.RefreshToken
	}
	l.ExpiresAt = now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return nil
}

// Fresh returns a valid access token, refreshing it (and saving the login
// file) when it expires within 30 s.
func (l *Login) Fresh(ctx context.Context, now func() time.Time) (string, error) {
	if now == nil {
		now = time.Now
	}
	if l.AccessToken != "" && now().Add(30*time.Second).Before(l.ExpiresAt) {
		return l.AccessToken, nil
	}
	if l.RefreshToken == "" {
		return "", ErrNotSignedIn
	}
	hc, err := HTTPClient(l.CAFile)
	if err != nil {
		return "", err
	}
	if err := l.tokenRequest(ctx, hc, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {l.RefreshToken}, "client_id": {l.ClientID},
	}, now); err != nil {
		var oe *oauthError
		if errors.As(err, &oe) && oe.Code == "invalid_grant" {
			return "", fmt.Errorf("%w (%v)", ErrNotSignedIn, err)
		}
		return "", err
	}
	if err := l.Save(); err != nil {
		return "", err
	}
	return l.AccessToken, nil
}

// Header returns the authentication headers for a request to endpointURL
// (the canonical /mcp or /stream URL) with method.
func (l *Login) Header(ctx context.Context, method, endpointURL string, now func() time.Time) (http.Header, error) {
	if now == nil {
		now = time.Now
	}
	tok, err := l.Fresh(ctx, now)
	if err != nil {
		return nil, err
	}
	if l.key == nil {
		return http.Header{"Authorization": {"Bearer " + tok}}, nil
	}
	p, err := dpop.Proof(l.key, method, endpointURL, tok, l.currentNonce(), now())
	if err != nil {
		return nil, err
	}
	return http.Header{"Authorization": {"DPoP " + tok}, "Dpop": {p}}, nil
}
