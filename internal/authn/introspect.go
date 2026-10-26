package authn

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

type introspection struct {
	Active   bool   `json:"active"`
	ClientID string `json:"client_id"`
	Sub      string `json:"sub"`
	CNF      *struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// Introspect asks the authorization server whether p's session is live
// (docs/01 OD13, D9). Any failure is an error, and an error is a deny.
func (v *Verifier) Introspect(ctx context.Context, p *Principal) error {
	if p == nil || p.token == "" {
		return codes.New(codes.IntrospectionFailed, "no token to introspect")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m, err := v.iss.metadata(ctx)
	if err != nil {
		return codes.Wrap(codes.IntrospectionFailed, err, "authorization server unavailable")
	}
	secret, err := os.ReadFile(v.cfg.IntrospectionSecretFile)
	if err != nil {
		return codes.Wrap(codes.IntrospectionFailed, err, "introspection credential unavailable")
	}
	form := url.Values{"token": {p.token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return codes.Wrap(codes.IntrospectionFailed, err, "introspection request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(v.cfg.IntrospectionClientID), url.QueryEscape(string(bytes.TrimSpace(secret))))
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return codes.Wrap(codes.IntrospectionFailed, err, "authorization server unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return codes.New(codes.IntrospectionFailed, "introspection answered %d", resp.StatusCode)
	}
	var in introspection
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&in); err != nil {
		return codes.Wrap(codes.IntrospectionFailed, err, "unparseable introspection answer")
	}
	if !in.Active {
		return codes.New(codes.SessionInactive, "the session is no longer active; sign in again")
	}
	if in.ClientID != p.ClientID {
		return codes.New(codes.IntrospectionFailed, "introspection client_id differs from the token's")
	}
	if in.Sub != "" && in.Sub != p.Subject {
		return codes.New(codes.IntrospectionFailed, "introspection sub differs from the token's")
	}
	if in.CNF != nil && in.CNF.JKT != "" && subtle.ConstantTimeCompare([]byte(in.CNF.JKT), []byte(p.JKT)) != 1 {
		return codes.New(codes.IntrospectionFailed, "introspection cnf.jkt differs from the token's")
	}
	if p.JKT != "" && (in.CNF == nil || in.CNF.JKT == "") {
		// A bound token must still be reported as bound.
		return codes.New(codes.IntrospectionFailed, "introspection lost the token's binding")
	}
	return nil
}
