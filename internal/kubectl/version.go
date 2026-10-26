package kubectl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// Version check (docs/04 D11).
const (
	minMinor        = 35 // Kubernetes 1.35: WebSocket exec needs create on pods/exec (docs/04 M6)
	versionCacheTTL = 10 * time.Minute
	versionTimeout  = 10 * time.Second
)

// CheckTarget refuses a target that is unknown, unreachable or older than
// Kubernetes 1.35 (docs/04 D11). It reads /version with Nyyrikki's own
// credential, without impersonation, and remembers a good answer for 10
// minutes. Every failure is codes.Unavailable (codes.TargetNotAllowed for
// an unknown target) and is not cached.
func (r *Runner) CheckTarget(ctx context.Context, name string) error {
	t, ok := r.targets[name]
	if !ok {
		return codes.WithDetail(codes.TargetNotAllowed, DetailUnknownTarget, "unknown target")
	}
	r.versionMu.Lock()
	at, ok := r.verified[name]
	r.versionMu.Unlock()
	if ok && r.now().Sub(at) < versionCacheTTL {
		return nil
	}

	major, minor, err := fetchVersion(ctx, t)
	if err != nil {
		r.log.Warn("target version check failed", "target", name, "err", err)
		return &codes.Error{Code: codes.Unavailable, Detail: DetailTargetUnreachable, Message: "target " + name + " is unreachable", Err: err}
	}
	if major < 1 || (major == 1 && minor < minMinor) {
		return codes.WithDetail(codes.Unavailable, DetailTargetVersion, "target %s runs Kubernetes %d.%d; at least 1.%d is required", name, major, minor, minMinor)
	}
	r.versionMu.Lock()
	r.verified[name] = r.now()
	r.versionMu.Unlock()
	return nil
}

// fetchVersion reads the target's /version. The transport ignores
// HTTP(S)_PROXY (docs/gotchas.md) and follows no redirects; the token is
// re-read from its file on every check, so rotation needs no restart. No
// error carries the token.
func fetchVersion(ctx context.Context, t Target) (major, minor int, err error) {
	caPEM, err := os.ReadFile(t.CAFile)
	if err != nil {
		return 0, 0, errors.New("reading the CA file failed")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return 0, 0, errors.New("the CA file holds no certificate")
	}
	tok, err := os.ReadFile(t.TokenFile)
	if err != nil {
		return 0, 0, errors.New("reading the token file failed")
	}
	token := strings.TrimSpace(string(tok))
	if token == "" {
		return 0, 0, errors.New("the token file is empty")
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       versionTimeout,
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(t.Server, "/")+"/version", nil)
	if err != nil {
		return 0, 0, errors.New("building the version request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) {
			// url.Error repeats the URL, which is config, not a secret;
			// keep only the cause.
			return 0, 0, ue.Unwrap()
		}
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, errors.New("/version answered " + resp.Status)
	}
	var v struct {
		Major string `json:"major"`
		Minor string `json:"minor"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&v); err != nil {
		return 0, 0, errors.New("/version answered something unparseable")
	}
	if major, err = leadingInt(v.Major); err != nil {
		return 0, 0, errors.New("/version has no major version")
	}
	if minor, err = leadingInt(v.Minor); err != nil {
		return 0, 0, errors.New("/version has no minor version")
	}
	return major, minor, nil
}

// leadingInt parses the leading digits of s; managed clusters report
// minors like "35+".
func leadingInt(s string) (int, error) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 || end > 6 {
		return 0, errors.New("no number")
	}
	return strconv.Atoi(s[:end])
}
