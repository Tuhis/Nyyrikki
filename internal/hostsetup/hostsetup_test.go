package hostsetup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
)

const body = "#!/bin/sh\nmain() { exit 0; }\n" + MainLine + "\n"

type recAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail bool
}

func (a *recAudit) Append(_ context.Context, r audit.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
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
	h, err := New(testConfig(t), []byte(body), a, nil)
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
	want := "TARGET=db-1\nHUMAN=owner\n" +
		"CA_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y\n" +
		"SOURCE=203.0.113.10/32\nSUDO=true\nEND=5\n" + Terminator + "\n"
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
	h, _ := New(testConfig(t), []byte(body), a, nil)
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
