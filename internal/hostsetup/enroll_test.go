package hostsetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
	"github.com/Tuhis/Nyyrikki/internal/sshtarget"
)

// fakeDecision stands in for the decision point: it counts the prompts
// it would have sent and answers with err, after running issue when err
// is nil (approved).
type fakeDecision struct {
	mu    sync.Mutex
	asked []decision.EnrollRequest
	err   error
	// block, if set, holds the call until it is closed or the caller
	// goes away.
	block chan struct{}
	// beforeIssue, if set, runs on the call's goroutine just before the
	// certificate is issued.
	beforeIssue func()
}

func (f *fakeDecision) DecideEnroll(ctx context.Context, r decision.EnrollRequest, issue func(context.Context, string) error) error {
	f.mu.Lock()
	f.asked = append(f.asked, r)
	err, block := f.err, f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return codes.New(codes.Withdrawn, "gone")
		}
	}
	if err != nil {
		return err
	}
	if f.beforeIssue != nil {
		f.beforeIssue()
	}
	return issue(ctx, "apr_test")
}

func (f *fakeDecision) prompts() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.asked) }

type fakeProber struct {
	mu      sync.Mutex
	calls   int
	results []sshtarget.ProbeAccount
	err     error
	cert    *ssh.Certificate
}

func (f *fakeProber) Probe(_ context.Context, _ string, c *ssh.Certificate, humans []string, before func(string, string, string) error) ([]sshtarget.ProbeAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.cert = c
	for _, h := range humans {
		if err := before(h, config.SSHAccount(h), "42"); err != nil {
			return nil, err
		}
	}
	return f.results, f.err
}

// enrollEnv is the enrollment handlers against fakes, with a real
// host-ca, so tokens are minted as the command mints them.
type enrollEnv struct {
	cfg    *config.Config
	keys   *sshca.Keys
	files  sshca.Files
	dec    *fakeDecision
	prober *fakeProber
	audit  *recAudit
	logs   *bytes.Buffer
	mux    *http.ServeMux
	now    time.Time
	e      *Enroll
}

func newEnrollEnv(t *testing.T) *enrollEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig(t)
	user, _ := keyFile(t, dir, "user-ca")
	host, _ := keyFile(t, dir, "host-ca")
	env := &enrollEnv{cfg: cfg, files: sshca.Files{UserCA: user, HostCA: host}, dec: &fakeDecision{}, prober: &fakeProber{},
		audit: &recAudit{}, logs: &bytes.Buffer{}, mux: http.NewServeMux(), now: time.Unix(1_800_000_000, 0)}
	env.keys = keysFor(t, cfg, env.files)
	e, err := NewEnroll(EnrollConfig{Config: cfg, Keys: env.keys, Decision: env.dec, Prober: env.prober, Audit: env.audit,
		Logger: slog.New(slog.NewTextHandler(env.logs, nil)), Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatal(err)
	}
	env.e = e
	e.Register(env.mux)
	return env
}

func (env *enrollEnv) mint(t *testing.T, target string, at time.Time) string {
	t.Helper()
	set, err := env.keys.Load()
	if err != nil {
		t.Fatal(err)
	}
	key, err := set.EnrollTokenKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := MintToken(key, target, at)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return k
}

func enrollBody(k ssh.PublicKey, kill bool) string {
	return fmt.Sprintf("HOST_KEY=%s\nSESSION_KILL=%v\nEND=2\n", sshca.AuthorizedKey(k), kill)
}

func (env *enrollEnv) post(t *testing.T, path, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	r.RemoteAddr = "198.51.100.7:40000"
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)
	return w
}

// noToken fails if tok, or its base64 payload, appears in any audit
// record or log line (docs/08 D6, G6).
func (env *enrollEnv) noToken(t *testing.T, toks ...string) {
	t.Helper()
	env.audit.mu.Lock()
	recs := fmt.Sprintf("%+v", env.audit.recs)
	env.audit.mu.Unlock()
	for _, tok := range toks {
		payload := strings.TrimPrefix(tok, TokenPrefix)
		for _, s := range []string{recs, env.logs.String()} {
			if strings.Contains(s, payload) || strings.Contains(s, payload[:20]) {
				t.Fatalf("a token reached the audit or the log:\n%s", s)
			}
		}
	}
}

func (env *enrollEnv) lastDetail() string {
	env.audit.mu.Lock()
	defer env.audit.mu.Unlock()
	if len(env.audit.recs) == 0 {
		return ""
	}
	return env.audit.recs[len(env.audit.recs)-1].Detail
}

// TestEnrollTokenOnce covers docs/08 G6: a valid token is accepted once,
// starts one enrollment, is answered with the host certificate, and a
// replay is refused with no prompt.
func TestEnrollTokenOnce(t *testing.T) {
	env := newEnrollEnv(t)
	tok := env.mint(t, "db-1", env.now)
	hk := newHostKey(t)
	w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(hk, true))
	if w.Code != 200 || env.dec.prompts() != 1 {
		t.Fatalf("status %d %q, prompts %d", w.Code, w.Body.String(), env.dec.prompts())
	}
	got := env.dec.asked[0]
	if got.Target != "db-1" || got.HostKey != "ED25519 "+ssh.FingerprintSHA256(hk) || !got.SessionKill ||
		got.ClientAddr != "198.51.100.7" || !got.TokenIssued.Equal(env.now) || got.TokenSHA256 == "" {
		t.Fatalf("asked %+v", got)
	}
	cert := parseCertResponse(t, w.Body.String())
	if !bytes.Equal(cert.Key.Marshal(), hk.Marshal()) || cert.KeyId != "nyyrikki-host:db-1" {
		t.Fatalf("certificate %+v", cert)
	}
	// Replayed: refused at once, nobody asked.
	for range 2 {
		w = env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(newHostKey(t), false))
		if w.Code != http.StatusUnauthorized || env.dec.prompts() != 1 || env.lastDetail() != detailTokenUsed {
			t.Fatalf("replay: %d, prompts %d, detail %q", w.Code, env.dec.prompts(), env.lastDetail())
		}
	}
	env.noToken(t, tok)
}

func parseCertResponse(t *testing.T, body string) *ssh.Certificate {
	t.Helper()
	lines := strings.Split(body, "\n")
	if len(lines) != 3 || lines[1] != "END=1" || lines[2] != "" {
		t.Fatalf("response %q", body)
	}
	line, ok := strings.CutPrefix(lines[0], "HOST_CERT=")
	if !ok {
		t.Fatalf("response %q", body)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	return c
}

// TestEnrollTokenRefused covers docs/08 G6: an expired token, one for
// another target, a forged, truncated or otherwise mangled one, and a
// missing or differently-schemed header are each refused with 401 and no
// prompt; none of them reaches the audit or the log.
func TestEnrollTokenRefused(t *testing.T) {
	env := newEnrollEnv(t)
	good := env.mint(t, "db-1", env.now)
	expired := env.mint(t, "db-1", env.now.Add(-TokenLife))
	justExpired := env.mint(t, "db-1", env.now.Add(-TokenLife).Add(500*time.Millisecond))
	// A token for another target, signed by this Nyyrikki.
	cfg2 := *env.cfg
	cfg2.Targets = append(append([]config.Target(nil), env.cfg.Targets...), config.Target{Name: "db-2", Humans: []string{"owner"}, SSH: &config.SSHTarget{Address: "db-2.example.com:22"}})
	env.cfg.Targets = cfg2.Targets
	other := env.mint(t, "db-2", env.now)
	// A token signed with another host-ca.
	foreignKey := make([]byte, 32)
	rand.Read(foreignKey)
	forged, _, _ := MintToken(foreignKey, "db-1", env.now)
	// The payload of a good token with one byte of the target changed.
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(good, TokenPrefix))
	raw[2] ^= 1
	tampered := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	padded := good + "=="
	body := enrollBody(newHostKey(t), true)

	for name, c := range map[string]struct{ auth, detail string }{
		"expired":        {AuthScheme + " " + expired, detailTokenExpired},
		"at expiry":      {AuthScheme + " " + justExpired, detailTokenExpired},
		"other target":   {AuthScheme + " " + other, detailTokenInvalid},
		"forged":         {AuthScheme + " " + forged, detailTokenInvalid},
		"tampered":       {AuthScheme + " " + tampered, detailTokenInvalid},
		"truncated":      {AuthScheme + " " + good[:len(good)-1], detailTokenInvalid},
		"truncated more": {AuthScheme + " " + good[:len(good)-10], detailTokenInvalid},
		"padded":         {AuthScheme + " " + padded, detailTokenInvalid},
		"no prefix":      {AuthScheme + " " + strings.TrimPrefix(good, TokenPrefix), detailTokenInvalid},
		"bearer":         {"Bearer " + good, detailTokenInvalid},
		"no header":      {"", detailTokenInvalid},
		"empty":          {AuthScheme + " ", detailTokenInvalid},
		"huge":           {AuthScheme + " " + TokenPrefix + strings.Repeat("A", 4000), detailTokenInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			w := env.post(t, "/hosts/db-1/enroll", c.auth, body)
			if w.Code != http.StatusUnauthorized || env.dec.prompts() != 0 || env.lastDetail() != c.detail {
				t.Fatalf("status %d, prompts %d, detail %q", w.Code, env.dec.prompts(), env.lastDetail())
			}
			if w.Header().Get("WWW-Authenticate") != AuthScheme {
				t.Errorf("WWW-Authenticate %q", w.Header().Get("WWW-Authenticate"))
			}
			// The check refuses the same tokens.
			if w := env.post(t, "/hosts/db-1/enroll/check", c.auth, ""); w.Code != http.StatusUnauthorized {
				t.Fatalf("check: %d", w.Code)
			}
		})
	}
	// The token for db-2 is good for db-2: proof the refusal above was
	// the target, not the token.
	if w := env.post(t, "/hosts/db-2/enroll", AuthScheme+" "+other, body); w.Code != 200 {
		t.Fatalf("db-2's token on db-2: %d %s", w.Code, w.Body.String())
	}
	// Two Authorization headers: refused.
	r := httptest.NewRequest(http.MethodPost, "/hosts/db-1/enroll", strings.NewReader(body))
	r.Header.Add("Authorization", AuthScheme+" "+good)
	r.Header.Add("Authorization", AuthScheme+" "+good)
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("two headers: %d", w.Code)
	}
	if env.dec.prompts() != 1 {
		t.Fatalf("%d prompts", env.dec.prompts())
	}
	env.noToken(t, good, expired, other, forged, tampered)
}

// TestEnrollBodyRefused covers docs/08 D7: a malformed body is 400 at
// once, with no prompt, and doesn't use the token up.
func TestEnrollBodyRefused(t *testing.T) {
	env := newEnrollEnv(t)
	tok := env.mint(t, "db-1", env.now)
	hk := newHostKey(t)
	key := sshca.AuthorizedKey(hk)
	for name, b := range map[string]string{
		"empty":            "",
		"no newline":       "HOST_KEY=" + key + "\nSESSION_KILL=true\nEND=2",
		"crlf":             "HOST_KEY=" + key + "\r\nSESSION_KILL=true\r\nEND=2\r\n",
		"wrong count":      "HOST_KEY=" + key + "\nSESSION_KILL=true\nEND=3\n",
		"no END":           "HOST_KEY=" + key + "\nSESSION_KILL=true\n",
		"swapped":          "SESSION_KILL=true\nHOST_KEY=" + key + "\nEND=2\n",
		"extra line":       "HOST_KEY=" + key + "\nSESSION_KILL=true\nSUDO=true\nEND=3\n",
		"two keys":         "HOST_KEY=" + key + "\nHOST_KEY=" + key + "\nEND=2\n",
		"kill yes":         "HOST_KEY=" + key + "\nSESSION_KILL=yes\nEND=2\n",
		"kill TRUE":        "HOST_KEY=" + key + "\nSESSION_KILL=TRUE\nEND=2\n",
		"key comment":      "HOST_KEY=" + key + " root@db-1\nSESSION_KILL=true\nEND=2\n",
		"key options":      "HOST_KEY=from=\"x\" " + key + "\nSESSION_KILL=true\nEND=2\n",
		"key two spaces":   "HOST_KEY=" + strings.Replace(key, " ", "  ", 1) + "\nSESSION_KILL=true\nEND=2\n",
		"rsa key":          "HOST_KEY=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7\nSESSION_KILL=true\nEND=2\n",
		"not a key":        "HOST_KEY=ssh-ed25519 AAAA\nSESSION_KILL=true\nEND=2\n",
		"non-ascii":        "HOST_KEY=" + key + "\nSESSION_KILL=true\u200b\nEND=2\n",
		"nul":              "HOST_KEY=" + key + "\x00\nSESSION_KILL=true\nEND=2\n",
		"over 4 KiB":       "HOST_KEY=" + key + "\nSESSION_KILL=true\nEND=2\n" + strings.Repeat("#", 5000),
		"trailing garbage": "HOST_KEY=" + key + "\nSESSION_KILL=true\nEND=2\nx\n",
	} {
		t.Run(name, func(t *testing.T) {
			w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, b)
			if w.Code != http.StatusBadRequest || env.dec.prompts() != 0 || env.lastDetail() != detailBadBody {
				t.Fatalf("status %d, prompts %d, detail %q", w.Code, env.dec.prompts(), env.lastDetail())
			}
		})
	}
	// A certificate as the host key.
	set, _ := env.keys.Load()
	c, err := set.SignHostCert(sshca.HostCert{Key: hk, Target: "db-1", Host: "h", Validity: time.Hour, Now: env.now})
	if err != nil {
		t.Fatal(err)
	}
	certBody := "HOST_KEY=" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))) + "\nSESSION_KILL=true\nEND=2\n"
	if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, certBody); w.Code != http.StatusBadRequest {
		t.Fatalf("a certificate as the host key: %d", w.Code)
	}
	// The token still works.
	if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(hk, false)); w.Code != 200 {
		t.Fatalf("after malformed bodies: %d %s", w.Code, w.Body.String())
	}
}

// TestEnrollRefusedPaths: query strings, unknown, Kubernetes and
// malformed targets answer as setup.sh does, before the token is read.
func TestEnrollRefusedPaths(t *testing.T) {
	env := newEnrollEnv(t)
	tok := env.mint(t, "db-1", env.now)
	body := enrollBody(newHostKey(t), true)
	for path, want := range map[string]int{
		"/hosts/db-1/enroll?x=1":       http.StatusBadRequest,
		"/hosts/ghost/enroll":          http.StatusNotFound,
		"/hosts/prod-k8s/enroll":       http.StatusNotFound,
		"/hosts/DB-1/enroll":           http.StatusNotFound,
		"/hosts/db-1/enroll/check?x":   http.StatusBadRequest,
		"/hosts/ghost/enroll/check":    http.StatusNotFound,
		"/hosts/prod-k8s/enroll/check": http.StatusNotFound,
	} {
		if w := env.post(t, path, AuthScheme+" "+tok, body); w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
	// GET is not an enrollment.
	r := httptest.NewRequest(http.MethodGet, "/hosts/db-1/enroll", nil)
	r.Header.Set("Authorization", AuthScheme+" "+tok)
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
	if env.dec.prompts() != 0 {
		t.Fatal("prompted")
	}
}

// TestEnrollRefusedOutcomes covers docs/08 G7 at the endpoint: deny,
// expiry, a call gone, and an unavailable approver answer without a
// certificate, and use the token up.
func TestEnrollRefusedOutcomes(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
	}{
		"denied":      {codes.New(codes.Denied, "no"), http.StatusForbidden},
		"expired":     {codes.New(codes.Expired, "late"), http.StatusForbidden},
		"unavailable": {codes.New(codes.Unavailable, "telegram down"), http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnrollEnv(t)
			env.dec.err = c.err
			tok := env.mint(t, "db-1", env.now)
			w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(newHostKey(t), true))
			if w.Code != c.status || strings.Contains(w.Body.String(), "CERT") {
				t.Fatalf("status %d body %q", w.Code, w.Body.String())
			}
			for _, r := range env.audit.recs {
				if r.Kind == codes.KindHostCertIssued {
					t.Fatal("a certificate was issued")
				}
			}
			// Used up: neither a second enrollment nor a check.
			if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(newHostKey(t), true)); w.Code != http.StatusUnauthorized || env.dec.prompts() != 1 {
				t.Fatalf("second enrollment: %d", w.Code)
			}
			if w := env.post(t, "/hosts/db-1/enroll/check", AuthScheme+" "+tok, ""); w.Code != http.StatusUnauthorized || env.prober.calls != 0 {
				t.Fatalf("check after %s: %d", name, w.Code)
			}
		})
	}
}

// TestEnrollFailClosed: a broken or missing host-ca refuses with 503
// before any prompt; a failed audit write of the issued certificate
// returns none.
func TestEnrollFailClosed(t *testing.T) {
	env := newEnrollEnv(t)
	tok := env.mint(t, "db-1", env.now)
	body := enrollBody(newHostKey(t), true)
	hostCA, _ := os.ReadFile(env.files.HostCA)

	os.WriteFile(env.files.HostCA, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n"), 0o600)
	if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, body); w.Code != http.StatusServiceUnavailable ||
		!strings.Contains(w.Body.String(), sshca.DetailUnreadable) || env.dec.prompts() != 0 {
		t.Fatalf("broken host-ca: %d %q", w.Code, w.Body.String())
	}
	os.Remove(env.files.HostCA)
	if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, body); w.Code != http.StatusServiceUnavailable ||
		!strings.Contains(w.Body.String(), sshca.DetailHostCAAbsent) || env.dec.prompts() != 0 {
		t.Fatalf("no host-ca: %d %q", w.Code, w.Body.String())
	}
	// A new host-ca: the old token is no longer this Nyyrikki's.
	keyFile(t, filepath.Dir(env.files.HostCA), "host-ca")
	if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, body); w.Code != http.StatusUnauthorized {
		t.Fatalf("token of a replaced host-ca: %d", w.Code)
	}
	os.WriteFile(env.files.HostCA, hostCA, 0o600)

	// The audit of the certificate fails: no certificate.
	env.audit.failKind = codes.KindHostCertIssued
	w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, body)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "CERT") {
		t.Fatalf("audit failing: %d %q", w.Code, w.Body.String())
	}
}

// TestEnrollCheckOnce covers docs/08 D7: the check needs an approved
// enrollment, runs once, answers per account with the hint after a
// refusal, audits the run certificate before the host is dialled, and
// uses the token up.
func TestEnrollCheckOnce(t *testing.T) {
	env := newEnrollEnv(t)
	tok := env.mint(t, "db-1", env.now)
	auth := AuthScheme + " " + tok
	// Before the enrollment: refused.
	if w := env.post(t, "/hosts/db-1/enroll/check", auth, ""); w.Code != http.StatusUnauthorized || env.prober.calls != 0 {
		t.Fatalf("check before enrollment: %d", w.Code)
	}
	w := env.post(t, "/hosts/db-1/enroll", auth, enrollBody(newHostKey(t), true))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	issued := parseCertResponse(t, w.Body.String())
	// A body: refused, and the token is kept for the real check.
	if w := env.post(t, "/hosts/db-1/enroll/check", auth, "x"); w.Code != http.StatusBadRequest || env.prober.calls != 0 {
		t.Fatalf("check with a body: %d", w.Code)
	}
	env.prober.results = []sshtarget.ProbeAccount{{Human: "owner", Account: "ny-owner", Status: sshtarget.ProbeRefused, CertSerial: "42"},
		{Human: "alice", Account: "ny-alice", Status: sshtarget.ProbeNotChecked}}
	w = env.post(t, "/hosts/db-1/enroll/check", auth, "")
	want := "REFUSED=ny-owner\nNOT_CHECKED=ny-alice\nHINT=the host refused Nyyrikki's login as ny-owner; check that ssh.source_addresses (203.0.113.10/32) holds the address Nyyrikki connects from, and that /etc/ssh/nyyrikki/principals/ny-owner exists; the accounts after it were not tried, so the host's PerSourcePenalties are tripped once at most\nEND=3\n"
	if w.Code != 200 || w.Body.String() != want {
		t.Fatalf("check: %d\n%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(env.prober.cert.Marshal(), issued.Marshal()) {
		t.Fatal("the check probed another certificate than the one issued")
	}
	var pre, done int
	for _, r := range env.audit.recs {
		if r.Kind == codes.KindHostEnrollChecked && r.Detail == "probe_started" && r.CertSerial == "42" && r.RunAs.User == "ny-owner" {
			pre++
		}
		if r.Kind == codes.KindHostEnrollChecked && r.Detail == "ny-owner=refused ny-alice=not_checked" {
			done++
		}
	}
	if pre != 1 || done != 1 {
		t.Fatalf("check audit: %+v", env.audit.recs)
	}
	// Used up.
	if w := env.post(t, "/hosts/db-1/enroll/check", auth, ""); w.Code != http.StatusUnauthorized || env.prober.calls != 1 {
		t.Fatalf("second check: %d", w.Code)
	}
	env.noToken(t, tok)
}

// TestEnrollCheckFailClosed: the audit of the probe's certificate
// failing stops the probe; a host that fails the check answers 503 with
// the detail.
func TestEnrollCheckFailClosed(t *testing.T) {
	for name, c := range map[string]struct {
		auditFails bool
		probeErr   error
		detail     string
	}{
		"audit":       {auditFails: true, detail: "unavailable"},
		"unreachable": {probeErr: codes.WithDetail(codes.Unavailable, sshtarget.DetailHostUnreachable, "x"), detail: sshtarget.DetailHostUnreachable},
		"wrong cert":  {probeErr: codes.WithDetail(codes.Unavailable, sshtarget.DetailHostCertMismatch, "x"), detail: sshtarget.DetailHostCertMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnrollEnv(t)
			tok := env.mint(t, "db-1", env.now)
			auth := AuthScheme + " " + tok
			if w := env.post(t, "/hosts/db-1/enroll", auth, enrollBody(newHostKey(t), true)); w.Code != 200 {
				t.Fatal(w.Code)
			}
			env.prober.err = c.probeErr
			env.prober.results = []sshtarget.ProbeAccount{{Human: "owner", Account: "ny-owner", Status: sshtarget.ProbeOK}}
			if c.auditFails {
				env.audit.failKind = codes.KindHostEnrollChecked
			}
			w := env.post(t, "/hosts/db-1/enroll/check", auth, "")
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), c.detail) || strings.Contains(w.Body.String(), "OK=") {
				t.Fatalf("status %d %q", w.Code, w.Body.String())
			}
		})
	}
}

// TestEnrollCallerGone: the host's call going away while it waits is
// withdrawn, with no certificate.
func TestEnrollCallerGone(t *testing.T) {
	env := newEnrollEnv(t)
	env.dec.block = make(chan struct{})
	tok := env.mint(t, "db-1", env.now)
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodPost, "/hosts/db-1/enroll", strings.NewReader(enrollBody(newHostKey(t), true))).WithContext(ctx)
	r.Header.Set("Authorization", AuthScheme+" "+tok)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { env.mux.ServeHTTP(w, r); close(done) }()
	for env.dec.prompts() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "CERT") {
		t.Fatalf("status %d %q", w.Code, w.Body.String())
	}
}

// slowBody runs fn when it is first read, as a client sending its body
// slowly lets time pass between the token check and the claim.
type slowBody struct {
	r  io.Reader
	fn func()
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.fn != nil {
		b.fn()
		b.fn = nil
	}
	return b.r.Read(p)
}

// A token whose expiry passes while its body is read can't start a second
// enrollment, or a first one: the claim refuses an expired token instead
// of sweeping the earlier use away (round 1 of #47).
func TestEnrollTokenExpiresDuringBody(t *testing.T) {
	env := newEnrollEnv(t)
	tok := env.mint(t, "db-1", env.now)
	if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(newHostKey(t), false)); w.Code != 200 {
		t.Fatalf("first enrollment: %d %s", w.Code, w.Body.String())
	}
	fresh := env.mint(t, "db-1", env.now) // never used
	for _, tc := range []struct{ name, tok string }{{"replayed", tok}, {"first use", fresh}} {
		start := env.now
		r := httptest.NewRequest(http.MethodPost, "/hosts/db-1/enroll", &slowBody{
			r: strings.NewReader(enrollBody(newHostKey(t), false)), fn: func() { env.now = start.Add(TokenLife + time.Hour) }})
		r.Header.Set("Authorization", AuthScheme+" "+tc.tok)
		r.RemoteAddr = "198.51.100.7:40000"
		w := httptest.NewRecorder()
		env.mux.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || env.dec.prompts() != 1 || env.lastDetail() != detailTokenExpired {
			t.Fatalf("%s: %d %q, prompts %d, detail %q", tc.name, w.Code, w.Body.String(), env.dec.prompts(), env.lastDetail())
		}
		env.now = start
	}
}

// A host key listed in ssh.revoked_host_keys is refused before anyone is
// asked, since the verifier would refuse it on every run anyway; the token
// isn't used up (round 1 of #47).
func TestEnrollRevokedHostKey(t *testing.T) {
	env := newEnrollEnv(t)
	hk := newHostKey(t)
	env.cfg.SSH.RevokedHostKeys = []string{sshca.AuthorizedKey(hk)}
	tok := env.mint(t, "db-1", env.now)
	w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(hk, false))
	if w.Code != http.StatusBadRequest || env.dec.prompts() != 0 || env.lastDetail() != "host_key_revoked" {
		t.Fatalf("revoked key: %d %q, prompts %d, detail %q", w.Code, w.Body.String(), env.dec.prompts(), env.lastDetail())
	}
	if w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(newHostKey(t), false)); w.Code != 200 || env.dec.prompts() != 1 {
		t.Fatalf("the token was used up: %d %q", w.Code, w.Body.String())
	}
}

// The body's read deadline must not outlive the body: on HTTP/1.1 net/http
// keeps reading the connection in the background to notice a client that
// goes away, and a deadline left in place cancels the request mid-approval
// (round 2 of #47).
func TestEnrollSlowApprovalHTTP1(t *testing.T) {
	old := enrollBodyTimeout
	enrollBodyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { enrollBodyTimeout = old })
	env := newEnrollEnv(t)
	env.dec.block = make(chan struct{})
	srv := httptest.NewUnstartedServer(env.mux)
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Transport.(*http.Transport).ForceAttemptHTTP2 = false

	tok := env.mint(t, "db-1", env.now)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/hosts/db-1/enroll", strings.NewReader(enrollBody(newHostKey(t), false)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", AuthScheme+" "+tok)
	type result struct {
		code  int
		proto string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		done <- result{code: resp.StatusCode, proto: resp.Proto}
	}()
	time.Sleep(4 * enrollBodyTimeout) // the approver takes longer than the body deadline
	close(env.dec.block)
	r := <-done
	if r.err != nil || r.code != 200 || r.proto != "HTTP/1.1" {
		t.Fatalf("slow approval over HTTP/1.1: %+v, detail %q", r, env.lastDetail())
	}
}

// A token that expires while the approver decides still gets its
// certificate (it was approved and is audited), but the check afterwards
// is refused as expired and dials nothing (round 2 of #47).
func TestEnrollTokenExpiresDuringApproval(t *testing.T) {
	env := newEnrollEnv(t)
	tok := env.mint(t, "db-1", env.now)
	start := env.now
	env.dec.beforeIssue = func() { env.now = start.Add(TokenLife + time.Minute) }
	w := env.post(t, "/hosts/db-1/enroll", AuthScheme+" "+tok, enrollBody(newHostKey(t), false))
	if w.Code != 200 {
		t.Fatalf("enroll: %d %q", w.Code, w.Body.String())
	}
	parseCertResponse(t, w.Body.String())
	w = env.post(t, "/hosts/db-1/enroll/check", AuthScheme+" "+tok, "")
	if w.Code != http.StatusUnauthorized || env.lastDetail() != detailTokenExpired || env.prober.calls != 0 {
		t.Fatalf("check: %d %q, detail %q, probes %d", w.Code, w.Body.String(), env.lastDetail(), env.prober.calls)
	}
}
