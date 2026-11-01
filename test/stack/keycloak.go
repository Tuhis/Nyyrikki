//go:build e2e || quickstart

package stack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// RegistrationPolicy is Keycloak's component type for client
// registration policies.
const RegistrationPolicy = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"

// KeycloakBase is Keycloak's base URL.
func (s *Stack) KeycloakBase() string { return strings.TrimSuffix(s.Issuer, "/realms/"+Realm) }

// ConfigureKeycloak waits for Keycloak and sets up the realm as
// docs/setup/keycloak.md describes, through the admin REST API: the
// audience scope, the CLI's client, nyyrikkid's introspection client, the
// owner, and Dynamic Client Registration for MCP harnesses. extraClients
// are created after the CLI's client, as they are given.
func (s *Stack) ConfigureKeycloak(extraClients ...map[string]any) error {
	s.logf("waiting for Keycloak and configuring the realm")
	hc := s.HTTPClient()
	deadline := time.Now().Add(4 * time.Minute)
	for {
		resp, err := hc.Get(s.KeycloakBase() + "/realms/master/.well-known/openid-configuration")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		if time.Now().After(deadline) {
			out, _ := exec.Command("docker", "logs", "--tail", "50", s.KeycloakContainer()).CombinedOutput()
			return fmt.Errorf("keycloak did not start: %v\n%s", err, out)
		}
		time.Sleep(2 * time.Second)
	}
	if _, err := s.Admin("POST", "/admin/realms", map[string]any{
		"realm": Realm, "enabled": true, "accessTokenLifespan": 300,
	}); err != nil {
		return err
	}
	r := "/admin/realms/" + Realm
	if _, err := s.Admin("POST", r+"/client-scopes", map[string]any{
		"name": "nyyrikki", "protocol": "openid-connect",
		"attributes": map[string]string{"include.in.token.scope": "true", "display.on.consent.screen": "false"},
		"protocolMappers": []any{map[string]any{
			"name": "nyyrikki audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{
				"included.custom.audience": s.Canonical + "/mcp",
				"access.token.claim":       "true", "id.token.claim": "false", "introspection.token.claim": "true",
			},
		}},
	}); err != nil {
		return err
	}
	cli := DeviceClient(CLIClientID, true)
	// The CLI may hold an offline session (docs/01 OD18).
	cli["optionalClientScopes"] = []string{"nyyrikki", "offline_access"}
	clients := append([]map[string]any{cli}, extraClients...)
	// Named after Nyyrikki's audience: Keycloak introspects a token only
	// for a client in its aud (docs/setup/keycloak.md).
	clients = append(clients, map[string]any{
		"clientId": s.Canonical + "/mcp", "publicClient": false, "secret": s.IntrospectionSecret,
		"standardFlowEnabled": false, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false,
	})
	for _, c := range clients {
		if _, err := s.Admin("POST", r+"/clients", c); err != nil {
			return err
		}
	}
	if _, err := s.Admin("POST", r+"/users", map[string]any{
		"username": OwnerUser, "enabled": true, "email": OwnerK8sUser, "emailVerified": true,
		"firstName": "Owner", "lastName": "Nyyrikki",
		"credentials": []any{map[string]any{"type": "password", "value": s.OwnerPassword, "temporary": false}},
	}); err != nil {
		return err
	}
	var users []struct {
		ID string `json:"id"`
	}
	b, err := s.Admin("GET", r+"/users?username="+OwnerUser+"&exact=true", nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &users); err != nil || len(users) != 1 {
		return fmt.Errorf("owner user not found: %v", err)
	}
	s.OwnerID = users[0].ID
	return s.configureDCR()
}

// DeviceClient is a public client for the device grant, DPoP-bound or not.
func DeviceClient(id string, dpop bool) map[string]any {
	return map[string]any{
		"clientId": id, "publicClient": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
		"implicitFlowEnabled": false, "consentRequired": false,
		"attributes": map[string]string{
			"oauth2.device.authorization.grant.enabled": "true",
			"dpop.bound.access.tokens":                  fmt.Sprint(dpop),
		},
		// No "roles": its audience-resolve mapper adds "account" to aud,
		// and Nyyrikki accepts only its own audience (docs/01 D9).
		"defaultClientScopes":  []string{"basic", "profile", "email", "web-origins", "acr"},
		"optionalClientScopes": []string{"nyyrikki"},
	}
}

// configureDCR is docs/setup/keycloak.md's "Dynamic Client Registration"
// section, through the admin API.
func (s *Stack) configureDCR() error {
	r := "/admin/realms/" + Realm
	type scope struct{ ID, Name string }
	var all []scope
	if err := s.adminJSON("GET", r+"/client-scopes", &all); err != nil {
		return err
	}
	id := map[string]string{}
	for _, sc := range all {
		id[sc.Name] = sc.ID
	}
	// What a registered client gets: never `roles` (it adds `account` to
	// aud); `nyyrikki` and `offline_access` as optional (OD17).
	var defs, opts []scope
	if err := s.adminJSON("GET", r+"/default-default-client-scopes", &defs); err != nil {
		return err
	}
	for _, sc := range defs {
		if sc.Name == "roles" || sc.Name == "offline_access" {
			if _, err := s.Admin("DELETE", r+"/default-default-client-scopes/"+sc.ID, nil); err != nil {
				return err
			}
		}
	}
	if err := s.adminJSON("GET", r+"/default-optional-client-scopes", &opts); err != nil {
		return err
	}
	optional := map[string]bool{}
	for _, sc := range opts {
		if sc.Name == "roles" {
			if _, err := s.Admin("DELETE", r+"/default-optional-client-scopes/"+sc.ID, nil); err != nil {
				return err
			}
		}
		optional[sc.Name] = true
	}
	// A new realm already offers offline_access as optional; adding a
	// scope that is there is a 409.
	for _, n := range []string{"nyyrikki", "offline_access"} {
		if !optional[n] {
			if _, err := s.Admin("PUT", r+"/default-optional-client-scopes/"+id[n], nil); err != nil {
				return err
			}
		}
	}
	// Offline sessions capped (OD17; the owner's deployment uses a year).
	if _, err := s.Admin("PUT", r, map[string]any{"offlineSessionMaxLifespanEnabled": true, "offlineSessionMaxLifespan": 31536000}); err != nil {
		return err
	}

	// Anonymous registration: redirect URIs on loopback only, and the
	// nyyrikki scope allowed. Consent Required and Max Clients stay.
	var comps []map[string]any
	if err := s.adminJSON("GET", r+"/components?type="+url.QueryEscape(RegistrationPolicy), &comps); err != nil {
		return err
	}
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
		if _, err := s.Admin("PUT", r+"/components/"+fmt.Sprint(c["id"]), c); err != nil {
			return err
		}
	}
	for _, p := range []string{"trusted-hosts", "allowed-client-templates", "consent-required", "max-clients"} {
		if !seen[p] {
			return fmt.Errorf("anonymous registration policy %q missing from a new realm", p)
		}
	}

	// PKCE with S256 for every client, registered ones included (docs/01
	// D7: OAuth 2.1 with PKCE). Keycloak then requires PKCE in the device
	// grant too for a client with PKCE set; the CLI sends it.
	if _, err := s.Admin("PUT", r+"/client-policies/profiles", map[string]any{"profiles": []any{map[string]any{
		"name": "nyyrikki-pkce", "description": "PKCE with S256",
		"executors": []any{map[string]any{"executor": "pkce-enforcer", "configuration": map[string]any{"auto-configure": "true"}}},
	}}}); err != nil {
		return err
	}
	_, err := s.Admin("PUT", r+"/client-policies/policies", map[string]any{"policies": []any{map[string]any{
		"name": "nyyrikki-pkce", "description": "PKCE with S256 for every client", "enabled": true,
		"conditions": []any{map[string]any{"condition": "any-client", "configuration": map[string]any{}}},
		"profiles":   []string{"nyyrikki-pkce"},
	}}})
	return err
}

// AdminLogin signs in to the master realm as admin.
func (s *Stack) AdminLogin() (string, error) {
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {s.KeycloakAdminPassword}}
	resp, err := s.HTTPClient().PostForm(s.KeycloakBase()+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("admin login: %s: %v", resp.Status, err)
	}
	return tr.AccessToken, nil
}

// Admin calls Keycloak's admin REST API and returns the answer.
func (s *Stack) Admin(method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.KeycloakBase()+path, rd)
	if err != nil {
		return nil, err
	}
	// Admin tokens from the master realm live a minute: sign in per call.
	tok, err := s.AdminLogin()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("keycloak %s %s: %s %s", method, path, resp.Status, out)
	}
	return out, nil
}

func (s *Stack) adminJSON(method, path string, v any) error {
	b, err := s.Admin(method, path, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.Join(fmt.Errorf("keycloak %s %s", method, path), err)
	}
	return nil
}
