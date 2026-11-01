package hostsetup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

const body = "#!/bin/sh\nmain() { exit 0; }\n" + MainLine + "\n"

type recAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail bool
	// failKind, if set, fails only writes of that kind.
	failKind string
}

func (a *recAudit) Append(_ context.Context, r audit.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail || (a.failKind != "" && r.Kind == a.failKind) {
		return errors.New("down")
	}
	a.recs = append(a.recs, r)
	return nil
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	b, err := os.ReadFile("../config/testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// keyFile writes a fresh CA key to dir/name and returns its path and
// its public key's data line value.
func keyFile(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	b, pub, err := sshca.GenerateKey("c")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, sshca.AuthorizedKey(pub)
}

// testKeys is a loader with a fresh user-ca, and that key's line.
func testKeys(t *testing.T, c *config.Config) (*sshca.Keys, string) {
	t.Helper()
	f, line := keyFile(t, t.TempDir(), "user-ca")
	return keysFor(t, c, sshca.Files{UserCA: f}), line
}

func keysFor(t *testing.T, c *config.Config, f sshca.Files) *sshca.Keys {
	t.Helper()
	o := sshca.Options{Files: f}
	for _, k := range c.SSH.UserCAPublicKeys {
		pk, err := config.ParseUserCAKey(k)
		if err != nil {
			t.Fatal(err)
		}
		o.Extra = append(o.Extra, pk)
	}
	for _, k := range c.SSH.RevokedUserCAKeys {
		pk, err := config.ParseUserCAKey(k)
		if err != nil {
			t.Fatal(err)
		}
		o.Revoked = append(o.Revoked, pk)
	}
	return sshca.New(o)
}

func get(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, target, nil)
	h.ServeHTTP(w, r)
	return w
}

// TestHostSetupEndpoint covers docs/07 D16 (G13): no token, the body as
// built in, then data lines holding only config values, END counting
// them, and the terminator; each fetch audited.
func TestHostSetupEndpoint(t *testing.T) {
	a := &recAudit{}
	cfg := testConfig(t)
	keys, derived := testKeys(t, cfg)
	h, err := New(cfg, []byte(body), keys, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := get(t, h, http.MethodGet, "/hosts/db-1/setup.sh")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	got := w.Body.String()
	if !strings.HasPrefix(got, body) {
		t.Fatal("the body is not the script as built in")
	}
	// docs/08 D1: the derived key first, then the extra configured one.
	want := "TARGET=db-1\nHUMAN=owner\n" +
		"CA_KEY=" + derived + "\n" +
		"CA_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y\n" +
		"SOURCE=203.0.113.10/32\nSUDO=true\nEND=6\n" + Terminator + "\n"
	if data := strings.TrimPrefix(got, body); data != want {
		t.Fatalf("data lines:\n%s\nwant:\n%s", data, want)
	}
	if strings.Contains(got, "nyyrikki-user-ca") {
		t.Error("the CA key's comment reached the script")
	}
	if len(a.recs) != 1 || a.recs[0].Kind != codes.KindHostSetupServed || a.recs[0].Targets[0] != "db-1" || !strings.HasPrefix(a.recs[0].Detail, "client ") {
		t.Fatalf("audit %+v", a.recs)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("cacheable")
	}
}

// TestHostSetupEndpointRefusals covers G13: only GET, no query string,
// and the same 404 for an unknown, a Kubernetes and a malformed target.
func TestHostSetupEndpointRefusals(t *testing.T) {
	a := &recAudit{}
	cfg := testConfig(t)
	keys, _ := testKeys(t, cfg)
	h, _ := New(cfg, []byte(body), keys, a, nil)
	for _, m := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, "PROPFIND"} {
		if w := get(t, h, m, "/hosts/db-1/setup.sh"); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", m, w.Code)
		}
	}
	for _, q := range []string{"/hosts/db-1/setup.sh?", "/hosts/db-1/setup.sh?sudo=false", "/hosts/db-1/setup.sh?x"} {
		if w := get(t, h, http.MethodGet, q); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	var bodies []string
	for _, p := range []string{"/hosts/ghost/setup.sh", "/hosts/prod-k8s/setup.sh", "/hosts/DB-1/setup.sh",
		"/hosts/db-1/../db-1/setup.sh", "/hosts/db-1/setup.sh/", "/hosts/db-1/setup", "/hosts//setup.sh", "/hosts/db-1%2fx/setup.sh"} {
		w := get(t, h, http.MethodGet, p)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
		bodies = append(bodies, w.Body.String())
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Error("404 bodies differ, telling target names apart")
		}
	}
	if len(a.recs) != 0 {
		t.Errorf("a refused fetch was audited as served: %+v", a.recs)
	}
	// No audit record, no script.
	a.fail = true
	if w := get(t, h, http.MethodGet, "/hosts/db-1/setup.sh"); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "main") {
		t.Errorf("served without an audit record: %d", w.Code)
	}
}

// TestCheckBody covers G13: the body ends with the one main line, has no
// other, and never holds the terminator.
func TestCheckBody(t *testing.T) {
	if err := CheckBody([]byte(body)); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{
		"no main line":     "#!/bin/sh\n",
		"not last":         "#!/bin/sh\n" + MainLine + "\necho after\n",
		"two main lines":   "#!/bin/sh\nmain x <<NYYRIKKI_VALUES_END\n" + MainLine + "\n",
		"terminator":       "#!/bin/sh\n" + Terminator + "\n" + MainLine + "\n",
		"no final newline": "#!/bin/sh\n" + MainLine,
	} {
		if CheckBody([]byte(b)) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestHostSetupEndpointCAKeys covers docs/08 D1 and D3 at the setup
// endpoint: CA_KEY lines are the trusted set, derived from the key files
// on each fetch; a broken key file, required or optional, or a revoked
// user-ca answers 503 with the detail, serves no script and audits no
// fetch.
func TestHostSetupEndpointCAKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t)
	user, userLine := keyFile(t, dir, "user-ca")
	next, nextLine := keyFile(t, dir, "user-ca-next")
	host := filepath.Join(dir, "host-ca")
	extra := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y"
	caLines := func(w *httptest.ResponseRecorder) []string {
		var out []string
		for _, l := range strings.Split(w.Body.String(), "\n") {
			if v, ok := strings.CutPrefix(l, "CA_KEY="); ok {
				out = append(out, v)
			}
		}
		return out
	}
	serve := func(c *config.Config, f sshca.Files) (*httptest.ResponseRecorder, *recAudit) {
		a := &recAudit{}
		h, err := New(c, []byte(body), keysFor(t, c, f), a, nil)
		if err != nil {
			t.Fatal(err)
		}
		return get(t, h, http.MethodGet, "/hosts/db-1/setup.sh"), a
	}

	// A staged key is trusted next to user-ca; an extra key equal to a
	// derived one is served once.
	dup := *cfg
	dup.SSH.UserCAPublicKeys = []string{nextLine, extra}
	w, _ := serve(&dup, sshca.Files{UserCA: user, NextUserCA: next, HostCA: host})
	if got := caLines(w); w.Code != 200 || strings.Join(got, "|") != strings.Join([]string{userLine, nextLine, extra}, "|") {
		t.Fatalf("status %d, CA_KEY %v", w.Code, got)
	}
	// Revoked keys are dropped: the staged one and an extra one.
	rev := *cfg
	rev.SSH.RevokedUserCAKeys = []string{nextLine, extra}
	w, _ = serve(&rev, sshca.Files{UserCA: user, NextUserCA: next})
	if got := caLines(w); w.Code != 200 || strings.Join(got, "|") != userLine {
		t.Fatalf("revoked keys served: %d %v", w.Code, got)
	}
	// Read on each fetch: a staged key appearing is served at once.
	keys := keysFor(t, cfg, sshca.Files{UserCA: user, NextUserCA: filepath.Join(dir, "later")})
	h, _ := New(cfg, []byte(body), keys, &recAudit{}, nil)
	if n := len(caLines(get(t, h, http.MethodGet, "/hosts/db-1/setup.sh"))); n != 2 {
		t.Fatalf("%d CA_KEY lines before the stage", n)
	}
	b, _ := os.ReadFile(next)
	os.WriteFile(filepath.Join(dir, "later"), b, 0o600)
	if n := len(caLines(get(t, h, http.MethodGet, "/hosts/db-1/setup.sh"))); n != 3 {
		t.Fatalf("%d CA_KEY lines after the stage", n)
	}

	garbage := filepath.Join(dir, "garbage")
	os.WriteFile(garbage, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n"), 0o600)
	revUser := *cfg
	revUser.SSH.RevokedUserCAKeys = []string{userLine}
	for name, c := range map[string]struct {
		cfg    *config.Config
		files  sshca.Files
		detail string
	}{
		"missing user-ca":    {cfg, sshca.Files{UserCA: filepath.Join(dir, "none")}, sshca.DetailUnreadable},
		"broken user-ca":     {cfg, sshca.Files{UserCA: garbage}, sshca.DetailUnreadable},
		"broken next":        {cfg, sshca.Files{UserCA: user, NextUserCA: garbage}, sshca.DetailUnreadable},
		"broken host-ca":     {cfg, sshca.Files{UserCA: user, HostCA: garbage}, sshca.DetailUnreadable},
		"unreadable host-ca": {cfg, sshca.Files{UserCA: user, HostCA: dir}, sshca.DetailUnreadable},
		"revoked user-ca":    {&revUser, sshca.Files{UserCA: user, NextUserCA: next}, sshca.DetailUserCARevoked},
	} {
		t.Run(name, func(t *testing.T) {
			w, a := serve(c.cfg, c.files)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), c.detail) || strings.Contains(w.Body.String(), "main") {
				t.Fatalf("status %d body %q", w.Code, w.Body.String())
			}
			if len(a.recs) != 0 {
				t.Fatalf("audited as served: %+v", a.recs)
			}
		})
	}
}
