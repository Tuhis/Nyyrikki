//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Dynamic Client Registration for MCP harnesses (docs/01 M9, D7, D25,
// OD16), set up as docs/setup/keycloak.md says and measured against the
// running Keycloak.

const registrationPolicy = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"

// loopback is where a harness's sign-in redirects: its own machine.
const loopback = "http://127.0.0.1:47613/callback"

// configureDCR is docs/setup/keycloak.md's "Dynamic Client Registration"
// section, through the admin API.
func (e *env) configureDCR(t *testing.T) {
	t.Helper()
	r := "/admin/realms/" + realm
	type scope struct{ ID, Name string }
	var all []scope
	json.Unmarshal(e.admin(t, "GET", r+"/client-scopes", nil), &all)
	id := map[string]string{}
	for _, s := range all {
		id[s.Name] = s.ID
	}
	// What a registered client gets: never `roles` (it adds `account` to
	// aud); `nyyrikki` and `offline_access` as optional (OD17).
	var defs, opts []scope
	json.Unmarshal(e.admin(t, "GET", r+"/default-default-client-scopes", nil), &defs)
	for _, s := range defs {
		if s.Name == "roles" || s.Name == "offline_access" {
			e.admin(t, "DELETE", r+"/default-default-client-scopes/"+s.ID, nil)
		}
	}
	json.Unmarshal(e.admin(t, "GET", r+"/default-optional-client-scopes", nil), &opts)
	optional := map[string]bool{}
	for _, s := range opts {
		if s.Name == "roles" {
			e.admin(t, "DELETE", r+"/default-optional-client-scopes/"+s.ID, nil)
		}
		optional[s.Name] = true
	}
	// A new realm already offers offline_access as optional; adding a
	// scope that is there is a 409.
	for _, n := range []string{"nyyrikki", "offline_access"} {
		if !optional[n] {
			e.admin(t, "PUT", r+"/default-optional-client-scopes/"+id[n], nil)
		}
	}
	// Offline sessions capped (OD17; the owner's deployment uses a year).
	e.admin(t, "PUT", r, map[string]any{"offlineSessionMaxLifespanEnabled": true, "offlineSessionMaxLifespan": 31536000})

	// Anonymous registration: redirect URIs on loopback only, and the
	// nyyrikki scope allowed. Consent Required and Max Clients stay.
	var comps []map[string]any
	json.Unmarshal(e.admin(t, "GET", r+"/components?type="+url.QueryEscape(registrationPolicy), nil), &comps)
	seen := map[string]bool{}
	for _, c := range comps {
		if c["subType"] != "anonymous" {
			continue
		}
		cfg, _ := c["config"].(map[string]any)
		if cfg == nil {
			cfg = map[string]any{}
		}
		switch c["providerId"] {
		case "trusted-hosts":
			cfg["host-sending-registration-request-must-match"] = []string{"false"}
			cfg["client-uris-must-match"] = []string{"true"}
			cfg["trusted-hosts"] = []string{"localhost", "127.0.0.1"}
		case "allowed-client-templates":
			cfg["allowed-client-scopes"] = []string{"nyyrikki", "offline_access"}
		default:
			seen[fmt.Sprint(c["providerId"])] = true
			continue
		}
		seen[fmt.Sprint(c["providerId"])] = true
		c["config"] = cfg
		e.admin(t, "PUT", r+"/components/"+fmt.Sprint(c["id"]), c)
	}
	for _, p := range []string{"trusted-hosts", "allowed-client-templates", "consent-required", "max-clients"} {
		if !seen[p] {
			t.Fatalf("anonymous registration policy %q missing from a new realm", p)
		}
	}

	// PKCE with S256 for every client, registered ones included (docs/01
	// D7: OAuth 2.1 with PKCE). Keycloak then requires PKCE in the device
	// grant too for a client with PKCE set; the CLI sends it.
	e.admin(t, "PUT", r+"/client-policies/profiles", map[string]any{"profiles": []any{map[string]any{
		"name": "nyyrikki-pkce", "description": "PKCE with S256",
		"executors": []any{map[string]any{"executor": "pkce-enforcer", "configuration": map[string]any{"auto-configure": "true"}}},
	}}})
	e.admin(t, "PUT", r+"/client-policies/policies", map[string]any{"policies": []any{map[string]any{
		"name": "nyyrikki-pkce", "description": "PKCE with S256 for every client", "enabled": true,
		"conditions": []any{map[string]any{"condition": "any-client", "configuration": map[string]any{}}},
		"profiles":   []string{"nyyrikki-pkce"},
	}}})
}

// register posts a client registration with no credentials, as a harness
// does, and returns the status and the answer.
func (e *env) register(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := e.httpClient().Post(e.issuer+"/clients-registrations/openid-connect", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &out)
	if resp.StatusCode >= 300 {
		out["_body"] = string(raw)
	}
	return resp.StatusCode, out
}

// harness registers a public MCP client as a harness's own sign-in does.
func (e *env) harness(t *testing.T, name string) string {
	t.Helper()
	code, out := e.register(t, map[string]any{
		"client_name": name, "redirect_uris": []string{loopback},
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none", "scope": "nyyrikki",
	})
	id, _ := out["client_id"].(string)
	if code != http.StatusCreated || id == "" {
		t.Fatalf("registering %s: %d %v", name, code, out)
	}
	return id
}

// adminClient is a client's admin representation.
func (e *env) adminClient(t *testing.T, clientID string) map[string]any {
	t.Helper()
	var cs []map[string]any
	json.Unmarshal(e.admin(t, "GET", "/admin/realms/"+realm+"/clients?clientId="+url.QueryEscape(clientID), nil), &cs)
	if len(cs) != 1 {
		t.Fatalf("client %s: %d matches", clientID, len(cs))
	}
	return cs[0]
}

// redact drops the credentials a registration answer carries, for logging.
func redact(out map[string]any) map[string]any {
	r := map[string]any{}
	for k, v := range out {
		if k != "client_secret" && k != "registration_access_token" {
			r[k] = v
		}
	}
	return r
}

func attr(c map[string]any, k string) string {
	a, _ := c["attributes"].(map[string]any)
	s, _ := a[k].(string)
	return s
}

// browser is the owner's browser: one cookie jar, so a second sign-in
// reuses the first's SSO session, as it would in real life.
type browser struct {
	e  *env
	hc *http.Client
}

func (e *env) newBrowser() *browser {
	jar, _ := cookiejar.New(nil)
	hc := e.httpClient()
	hc.Jar = jar
	// The last hop goes to the harness on loopback: stop there and read
	// the code from the URL, as the harness's listener would.
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host == "127.0.0.1:47613" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &browser{e: e, hc: hc}
}

// authorize runs an authorization request in the browser, signing in and
// consenting as the owner, and returns the redirect back to the harness.
func (b *browser) authorize(t *testing.T, q url.Values) *url.URL {
	t.Helper()
	resp, err := b.hc.Get(b.e.issuer + "/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	formRE := regexp.MustCompile(`(?s)<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>`)
	for step := 0; step < 6; step++ {
		if loc := resp.Header.Get("Location"); resp.StatusCode/100 == 3 && strings.HasPrefix(loc, loopback) {
			resp.Body.Close()
			u, _ := url.Parse(loc)
			return u
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := formRE.FindStringSubmatch(string(body))
		if m == nil {
			t.Fatalf("authorize: no form and no redirect (status %d):\n%.2000s", resp.StatusCode, body)
		}
		ref, _ := url.Parse(html.UnescapeString(m[1]))
		action := resp.Request.URL.ResolveReference(ref).String()
		form := url.Values{}
		if strings.Contains(m[2], `name="username"`) {
			form.Set("username", ownerUser)
			form.Set("password", ownerPassword)
			form.Set("credentialId", "")
		} else {
			form.Set("accept", "Yes") // the consent screen
		}
		if resp, err = b.hc.PostForm(action, form); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("authorize did not finish")
	return nil
}

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// signIn is a harness's whole sign-in: authorization code with PKCE, then
// the token request. It returns the access token.
func (b *browser) signIn(t *testing.T, clientID string) string {
	t.Helper()
	tok, _ := b.signInScope(t, clientID, "nyyrikki")
	return tok
}

// signInScope is signIn asking for scope; it also returns the refresh
// token.
func (b *browser) signInScope(t *testing.T, clientID, scope string) (string, string) {
	t.Helper()
	verifier, challenge := pkce()
	back := b.authorize(t, url.Values{
		"client_id": {clientID}, "redirect_uri": {loopback}, "response_type": {"code"}, "scope": {scope},
		"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	})
	code := back.Query().Get("code")
	if code == "" {
		t.Fatalf("sign-in of %s: no code: %s", clientID, back)
	}
	resp, err := b.e.httpClient().PostForm(b.e.issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {loopback},
		"client_id": {clientID}, "code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&tr)
	if tr.AccessToken == "" {
		t.Fatalf("token for %s: %s", clientID, tr.Error)
	}
	return tr.AccessToken, tr.RefreshToken
}

// mcpSession connects to /mcp with a Bearer token, as a harness does.
func (e *env) mcpSession(t *testing.T, tok string) *mcp.ClientSession {
	t.Helper()
	hc := e.httpClient()
	hc.Transport = &bearer{tok: tok, base: hc.Transport}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e-harness", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: e.canonical + "/mcp", HTTPClient: hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// mcpStatus is the HTTP status /mcp answers a tools/list with tok.
func (e *env) mcpStatus(t *testing.T, tok string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", e.canonical+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := e.httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (e *env) token(t *testing.T, form url.Values, basic ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	resp, err := e.httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tr)
	return resp.StatusCode, tr.AccessToken
}

// checkRegistration measures what an anonymous registration can and can't
// get (docs/01 M9). Anyone who can reach Keycloak can register, so none of
// it may lead to a token Nyyrikki accepts without the owner signing in.
func (e *env) checkRegistration(t *testing.T) {
	// A harness: public, loopback redirect, PKCE set on it.
	a := e.harness(t, "e2e harness")
	c := e.adminClient(t, a)
	t.Logf("M9 registered harness: publicClient=%v consentRequired=%v pkce=%q device=%q",
		c["publicClient"], c["consentRequired"], attr(c, "pkce.code.challenge.method"), attr(c, "oauth2.device.authorization.grant.enabled"))
	if c["publicClient"] != true || c["consentRequired"] != true || attr(c, "pkce.code.challenge.method") != "S256" {
		t.Fatalf("registered harness: publicClient=%v consentRequired=%v pkce=%q",
			c["publicClient"], c["consentRequired"], attr(c, "pkce.code.challenge.method"))
	}

	// A redirect off loopback is refused: a sign-in could hand the code to
	// someone else.
	if code, out := e.register(t, map[string]any{
		"client_name": "elsewhere", "redirect_uris": []string{"https://attacker.example/callback"},
		"token_endpoint_auth_method": "none",
	}); code < 400 {
		t.Fatalf("a non-loopback redirect was registered: %d %v", code, out)
	}

	// The CLI's client ID can't be taken, nor the CLI client changed.
	if code, out := e.register(t, map[string]any{
		"client_id": "nyyrikki-cli", "client_name": "impostor", "redirect_uris": []string{loopback},
		"token_endpoint_auth_method": "none",
	}); code < 300 && out["client_id"] == "nyyrikki-cli" {
		t.Fatalf("a registration took the CLI's client ID: %v", out)
	}
	req, _ := http.NewRequest("PUT", e.issuer+"/clients-registrations/openid-connect/nyyrikki-cli",
		strings.NewReader(`{"client_id":"nyyrikki-cli","dpop_bound_access_tokens":false,"redirect_uris":["`+loopback+`"]}`))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := e.httpClient().Do(req); err != nil {
		t.Fatal(err)
	} else if resp.Body.Close(); resp.StatusCode < 400 {
		t.Fatalf("an anonymous update of the CLI client: %d", resp.StatusCode)
	}
	if cli := e.adminClient(t, "nyyrikki-cli"); attr(cli, "dpop.bound.access.tokens") != "true" || cli["standardFlowEnabled"] == true {
		t.Fatalf("the CLI client changed: dpop=%q standardFlow=%v", attr(cli, "dpop.bound.access.tokens"), cli["standardFlowEnabled"])
	}

	// The password grant would skip the consent screen: no registered
	// client gets a token through it.
	code, out := e.register(t, map[string]any{
		"client_name": "ropc", "grant_types": []string{"password"}, "token_endpoint_auth_method": "none",
	})
	t.Logf("M9 registration asking for the password grant: %d %v", code, redact(out))
	// The setup doc says such a registration succeeds and gets no token:
	// pin both, so a change in Keycloak shows up here.
	id, _ := out["client_id"].(string)
	if code != http.StatusCreated || id == "" {
		t.Fatalf("registration asking for the password grant: %d %v", code, redact(out))
	}
	if st, tok := e.token(t, url.Values{"grant_type": {"password"}, "client_id": {id}, "username": {ownerUser},
		"password": {ownerPassword}, "scope": {"nyyrikki"}}); tok != "" {
		t.Fatalf("a registered client got a token by the password grant (%d)", st)
	}

	// Client credentials give a service account's token, whose sub is no
	// human in the registry: Nyyrikki refuses it for that reason.
	code, out = e.register(t, map[string]any{
		"client_name": "service", "grant_types": []string{"client_credentials"}, "token_endpoint_auth_method": "client_secret_basic",
	})
	t.Logf("M9 registration asking for client credentials: %d %v", code, redact(out))
	// docs/gotchas.md: such a client gets a token carrying Nyyrikki's
	// audience, and only the human registry refuses it. Pin both.
	id, _ = out["client_id"].(string)
	sec, _ := out["client_secret"].(string)
	if code != http.StatusCreated || id == "" || sec == "" {
		t.Fatalf("registration asking for client credentials: %d %v", code, redact(out))
	}
	_, tok := e.token(t, url.Values{"grant_type": {"client_credentials"}, "scope": {"nyyrikki"}}, id, sec)
	if tok == "" || claims(tok)["aud"] != e.canonical+"/mcp" {
		t.Fatalf("client-credentials token: issued=%v aud=%v", tok != "", claims(tok)["aud"])
	}
	t.Logf("M9 client-credentials token: aud=%v sub=%v", claims(tok)["aud"], claims(tok)["sub"])
	// ... refused by the registry, not by chance (docs/gotchas.md): this
	// request must add a record with that reason.
	const reason = `"subject not in the human registry"`
	count := func() int {
		return strings.Count(e.kubectl(t, "-n", namespace, "logs", "deploy/nyyrikki-nyyrikki"), reason)
	}
	before := count()
	if st := e.mcpStatus(t, tok); st != http.StatusUnauthorized {
		t.Fatalf("a service account's token reached /mcp: %d", st)
	}
	for try := 0; count() <= before; try++ {
		if try == 10 {
			t.Fatal("no auth_failed record saying the service account isn't in the human registry")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// checkHarnesses signs two harnesses in from one browser: each gets a
// token for Nyyrikki, PKCE is required, and they are two agents (docs/01
// D8, OD16): one's elevation handle is unknown to the other.
func (e *env) checkHarnesses(t *testing.T, next func() int) {
	b := e.newBrowser()
	a, other := e.harness(t, "harness A"), e.harness(t, "harness B")

	// Without PKCE no code is issued.
	back := b.authorize(t, url.Values{"client_id": {a}, "redirect_uri": {loopback}, "response_type": {"code"},
		"scope": {"nyyrikki"}, "state": {"s"}})
	if back.Query().Get("code") != "" || back.Query().Get("error") == "" {
		t.Fatalf("an authorization request without PKCE: %s", back)
	}

	tokA, tokB := b.signIn(t, a), b.signIn(t, other)
	ca, cb := claims(tokA), claims(tokB)
	t.Logf("M9 two harnesses, one browser: azp %v / %v, same sid: %v", ca["azp"], cb["azp"], ca["sid"] == cb["sid"])
	for _, c := range []map[string]any{ca, cb} {
		if c["aud"] != e.canonical+"/mcp" || c["sid"] == nil || c["sub"] != e.ownerID {
			t.Fatalf("harness token: aud=%v sid=%v sub=%v", c["aud"], c["sid"], c["sub"])
		}
	}
	if ca["azp"] == cb["azp"] {
		t.Fatal("two registrations share a client ID")
	}

	sa, sb := e.mcpSession(t, tokA), e.mcpSession(t, tokB)
	res, err := sa.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_targets", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("list_targets: %v %+v", err, res)
	}
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		r, err := sa.CallTool(context.Background(), &mcp.CallToolParams{Name: "elevate", Arguments: map[string]any{
			"targets": []string{"this-cluster"}, "duration": "5m", "reason": "harness A",
		}})
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	e.tap(t, next(), "Approve")
	r := <-done
	if r == nil || r.IsError {
		t.Fatalf("elevate as harness A: %+v", r)
	}
	var el struct {
		Handle string `json:"handle"`
	}
	raw, _ := json.Marshal(r.StructuredContent)
	json.Unmarshal(raw, &el)
	if !strings.HasPrefix(el.Handle, "nyel_") {
		t.Fatalf("elevate: %s", raw)
	}
	before := len(e.tg.Sent(t))
	r, err = sb.CallTool(context.Background(), &mcp.CallToolParams{Name: "run", Arguments: map[string]any{
		"target": "this-cluster", "args": []string{"get", "pods", "-n", workNS}, "reason": "borrowed", "elevation": el.Handle,
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(r.StructuredContent)
	if !r.IsError || !strings.Contains(string(raw), "handle_unknown") {
		t.Fatalf("harness B with harness A's handle: %s", raw)
	}
	if len(e.tg.Sent(t)) != before {
		t.Fatal("a borrowed handle reached the approver")
	}
}

// checkLoginMCP is `nyyrikki login --mcp` (docs/01 D25): it registers its
// own client, signs in through the device grant, and `mcp-headers` gives
// a harness a Bearer token Nyyrikki accepts.
func (e *env) checkLoginMCP(t *testing.T) {
	c := e.newCLI(t)
	c.login(t, "--mcp")
	r := c.run(t, "", "mcp-headers")
	var h map[string]string
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &h) != nil || !strings.HasPrefix(h["Authorization"], "Bearer ") {
		t.Fatalf("mcp-headers: %+v", r)
	}
	tok := strings.TrimPrefix(h["Authorization"], "Bearer ")
	cl := claims(tok)
	t.Logf("M9 login --mcp token: typ=%v azp=%v aud=%v", cl["typ"], cl["azp"], cl["aud"])
	if cl["azp"] == "nyyrikki-cli" || cl["aud"] != e.canonical+"/mcp" {
		t.Fatalf("login --mcp token: azp=%v aud=%v", cl["azp"], cl["aud"])
	}
	res, err := e.mcpSession(t, tok).CallTool(context.Background(), &mcp.CallToolParams{Name: "list_targets", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("list_targets with login --mcp: %v %+v", err, res)
	}
	// A second login --mcp is another client, so another agent (OD16).
	c2 := e.newCLI(t)
	c2.login(t, "--mcp")
	mcpLogin := func(c *cli) map[string]any {
		b, _ := os.ReadFile(filepath.Join(c.home, ".config", "nyyrikki", "mcp-login.json"))
		var m map[string]any
		json.Unmarshal(b, &m)
		return m
	}
	// It holds an offline session (docs/01 OD17), so it outlives the
	// browser session; the CLI's own login doesn't (M1 above).
	rt, _ := mcpLogin(c)["refresh_token"].(string)
	if typ := claims(rt)["typ"]; typ != "Offline" {
		t.Fatalf("login --mcp refresh token type %v, want Offline", typ)
	}
	if l1, l2 := mcpLogin(c)["client_id"], mcpLogin(c2)["client_id"]; l1 == nil || l1 == l2 {
		t.Fatalf("two login --mcp share a client: %v %v", l1, l2)
	}
}

// refresh trades a public client's refresh token for a new access token
// and refresh token; both are empty if Keycloak refuses.
func (e *env) refresh(t *testing.T, clientID, rt string) (string, string) {
	t.Helper()
	resp, err := e.httpClient().PostForm(e.issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tr)
	return tr.AccessToken, tr.RefreshToken
}

// runVia calls run through a harness's session and returns the result's
// structured content as JSON.
func runVia(t *testing.T, cs *mcp.ClientSession, reason string) (*mcp.CallToolResult, string) {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "run", Arguments: map[string]any{
		"target": "this-cluster", "args": []string{"auth", "whoami", "-o", "jsonpath={.status.userInfo.username}"}, "reason": reason,
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r.StructuredContent)
	return r, string(raw)
}

// offlineHarness registers a harness asking for offline_access, as Claude
// Code does, and signs it in through b; it returns the client ID, an
// access token and the offline refresh token.
func (e *env) offlineHarness(t *testing.T, b *browser, name string) (string, string, string) {
	t.Helper()
	code, out := e.register(t, map[string]any{
		"client_name": name, "redirect_uris": []string{loopback},
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none", "scope": "nyyrikki offline_access",
	})
	id, _ := out["client_id"].(string)
	if code != http.StatusCreated || id == "" {
		t.Fatalf("registering a harness that asks for offline_access: %d %v", code, redact(out))
	}
	at, rt := b.signInScope(t, id, "nyyrikki offline_access")
	if claims(rt)["typ"] != "Offline" {
		t.Fatalf("refresh token type %v, want Offline", claims(rt)["typ"])
	}
	return id, at, rt
}

// checkOffline is an MCP harness holding an offline session (docs/01
// OD17): it stays one agent across refreshes, signing out the owner's
// browser sessions leaves it working, and it ends when its client's access
// is revoked or the owner is signed out (docs/setup/keycloak.md, Revoking
// an agent).
func (e *env) checkOffline(t *testing.T, next func() int) {
	users := "/admin/realms/" + realm + "/users/" + e.ownerID
	// The owner's browser is usually signed in to Keycloak already, so the
	// harness signs in through a browser that has a session of its own.
	b := e.newBrowser()
	b.signIn(t, e.harness(t, "the browser's first harness"))
	id, at, rt := e.offlineHarness(t, b, "offline harness")
	sid := claims(at)["sid"]
	type session struct {
		ID string `json:"id"`
	}
	var online, offline []session
	onlineRaw := e.admin(t, "GET", users+"/sessions", nil)
	offlineRaw := e.admin(t, "GET", users+"/offline-sessions/"+fmt.Sprint(e.adminClient(t, id)["id"]), nil)
	json.Unmarshal(onlineRaw, &online)
	json.Unmarshal(offlineRaw, &offline)
	t.Logf("M9 OD17: after an offline sign-in through a signed-in browser, sid %v; online sessions %s; the harness's offline sessions %s", sid, onlineRaw, offlineRaw)
	isSid := func(s session) bool { return s.ID == sid }
	if !slices.ContainsFunc(offline, isSid) {
		t.Errorf("the harness's sid %v isn't one of its offline sessions: %s", sid, offlineRaw)
	}
	// The browser's session has the same ID, so the sign-out below ends the
	// very session the harness signed in through.
	if !slices.ContainsFunc(online, isSid) {
		t.Errorf("the harness's sid %v isn't the browser's session: %s", sid, onlineRaw)
	}
	at2, rt2 := e.refresh(t, id, rt)
	if at2 == "" || claims(at2)["sid"] != sid || claims(at2)["aud"] != e.canonical+"/mcp" {
		t.Fatalf("offline refresh: issued=%v sid %v -> %v aud=%v", at2 != "", sid, claims(at2)["sid"], claims(at2)["aud"])
	}

	// Nyyrikki takes it: a run reaches the approver and runs.
	ch := make(chan string, 1)
	go func() { _, raw := runVia(t, e.mcpSession(t, at2), "offline harness"); ch <- raw }()
	e.tap(t, next(), "Approve")
	if raw := <-ch; !strings.Contains(raw, ownerK8sUser) {
		t.Fatalf("run as the offline harness: %s", raw)
	}

	// Signing out every browser session of the owner leaves it working:
	// it refreshes, and its next run reaches the approver.
	if len(online) == 0 {
		t.Fatal("the browser had no session to sign out, so this measures nothing")
	}
	for _, ss := range online {
		e.admin(t, "DELETE", "/admin/realms/"+realm+"/sessions/"+ss.ID, nil)
	}
	if rest := e.admin(t, "GET", users+"/sessions", nil); string(rest) != "[]" {
		t.Fatalf("online sessions left after signing them out: %s", rest)
	}
	at3, rt3 := e.refresh(t, id, rt2)
	if at3 == "" {
		t.Fatal("signing out the browser sessions ended the offline harness too")
	}
	ch = make(chan string, 1)
	go func() { _, raw := runVia(t, e.mcpSession(t, at3), "after the browser sessions ended"); ch <- raw }()
	e.tap(t, next(), "Deny")
	if raw := <-ch; !strings.Contains(raw, "denied") {
		t.Fatalf("offline harness after the browser sessions ended: %s", raw)
	}

	// Removing its client's access ends it at once ...
	e.admin(t, "DELETE", users+"/consents/"+url.PathEscape(id), nil)
	if a, _ := e.refresh(t, id, rt3); a != "" {
		t.Fatal("an offline token still refreshes after its client's access was revoked")
	}
	before := len(e.tg.Sent(t))
	r, raw := runVia(t, e.mcpSession(t, at3), "after revoke")
	if !r.IsError || !strings.Contains(raw, "session_inactive") {
		t.Fatalf("offline harness after revoke: %s", raw)
	}

	// ... and so does signing the owner out, for every harness. Sign-out
	// sets a not-before time for the user, which refuses every token issued
	// before it, offline ones included; a token issued in the same second
	// survives, so the test steps past it.
	id2, at4, rt4 := e.offlineHarness(t, e.newBrowser(), "second offline harness")
	time.Sleep(1100 * time.Millisecond)
	e.admin(t, "POST", users+"/logout", nil)
	if a, _ := e.refresh(t, id2, rt4); a != "" {
		t.Fatal("an offline token still refreshes after the owner was signed out")
	}
	r, raw = runVia(t, e.mcpSession(t, at4), "after sign-out")
	if !r.IsError || !strings.Contains(raw, "session_inactive") {
		t.Fatalf("offline harness after the owner was signed out: %s", raw)
	}
	if len(e.tg.Sent(t)) != before {
		t.Fatal("a revoked harness reached the approver")
	}
}
