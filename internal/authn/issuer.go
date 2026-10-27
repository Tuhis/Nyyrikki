package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// HTTPClient returns the client Nyyrikki uses for the authorization
// server: no proxy from the environment (docs/gotchas.md), short timeouts.
func HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// discovery is the part of the issuer's metadata Nyyrikki uses.
type discovery struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// issuer fetches and caches the authorization server's metadata and keys.
type issuer struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu          sync.Mutex
	fetchMu     sync.Mutex // serialises refetches
	meta        *discovery
	keys        *jose.JSONWebKeySet
	lastFetch   time.Time
	lastAttempt time.Time
}

func newIssuer(issuerURL string, client *http.Client, now func() time.Time) *issuer {
	return &issuer{url: strings.TrimSuffix(issuerURL, "/"), client: client, now: now}
}

func (i *issuer) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func (i *issuer) metadata(ctx context.Context) (*discovery, error) {
	i.mu.Lock()
	m := i.meta
	i.mu.Unlock()
	if m != nil {
		return m, nil
	}
	var d discovery
	if err := i.getJSON(ctx, i.url+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	// The metadata must name the configured issuer exactly (RFC 8414 §3.3).
	if d.Issuer != i.url {
		return nil, fmt.Errorf("issuer metadata names %q", d.Issuer)
	}
	for _, s := range []string{d.JWKSURI, d.IntrospectionEndpoint} {
		if u, err := url.Parse(s); err != nil || u.Scheme != "https" && !isLoopback(u) {
			return nil, fmt.Errorf("issuer metadata has a non-https endpoint %q", s)
		}
	}
	i.mu.Lock()
	i.meta = &d
	i.mu.Unlock()
	return &d, nil
}

func isLoopback(u *url.URL) bool {
	h := u.Hostname()
	ip := net.ParseIP(h)
	return u.Scheme == "http" && (h == "localhost" || ip != nil && ip.IsLoopback())
}

var errNoKey = errors.New("no matching key")

// maxKeyAge bounds how long a fetched key set is trusted: a key removed
// from the authorization server stops verifying within it.
const maxKeyAge = time.Hour

// key returns the verification key with the given kid. The key set is
// refetched when it is older than maxKeyAge, or when the kid is unknown,
// and attempts (failed ones included) are made at most once a minute
// (docs/02 D2).
func (i *issuer) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	if k := i.freshKey(kid); k != nil {
		return k, nil
	}
	// One refetch at a time: concurrent callers wait for the one in
	// flight and then use what it fetched, instead of being refused.
	i.fetchMu.Lock()
	defer i.fetchMu.Unlock()
	if k := i.freshKey(kid); k != nil {
		return k, nil
	}
	i.mu.Lock()
	fresh := !i.lastFetch.IsZero() && i.now().Sub(i.lastFetch) < maxKeyAge
	recent := !i.lastAttempt.IsZero() && i.now().Sub(i.lastAttempt) < time.Minute
	if !recent {
		i.lastAttempt = i.now()
	}
	i.mu.Unlock()
	if recent {
		if fresh {
			return nil, errNoKey
		}
		return nil, errors.New("key set expired and refetch rate-limited")
	}
	m, err := i.metadata(ctx)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := i.getJSON(ctx, m.JWKSURI, &set); err != nil {
		return nil, err
	}
	i.mu.Lock()
	i.keys, i.lastFetch = &set, i.now()
	i.mu.Unlock()
	if k := i.cached(kid); k != nil {
		return k, nil
	}
	return nil, errNoKey
}

// freshKey returns the key with kid from a key set younger than maxKeyAge.
func (i *issuer) freshKey(kid string) *jose.JSONWebKey {
	i.mu.Lock()
	fresh := !i.lastFetch.IsZero() && i.now().Sub(i.lastFetch) < maxKeyAge
	i.mu.Unlock()
	if !fresh {
		return nil
	}
	return i.cached(kid)
}

func (i *issuer) cached(kid string) *jose.JSONWebKey {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.keys == nil {
		return nil
	}
	for _, k := range i.keys.Key(kid) {
		if k.Use == "" || k.Use == "sig" {
			if k.IsPublic() {
				kk := k
				return &kk
			}
		}
	}
	return nil
}
