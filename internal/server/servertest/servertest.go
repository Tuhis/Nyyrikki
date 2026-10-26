// Package servertest runs an in-process nyyrikkid against a test
// authorization server, a fake Telegram Bot API and a fake apiserver
// (docs/01 §5.8, integration layer).
//
// Packages using it must dispatch "kubectl-child" in TestMain, because the
// runner re-executes the test binary:
//
//	func TestMain(m *testing.M) { servertest.Main(m) }
package servertest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/authn/authntest"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/kubectl"
	"github.com/Tuhis/Nyyrikki/internal/server"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"

	_ "modernc.org/sqlite"
)

// ApproverID is the human's Telegram user ID.
const ApproverID = 4242

// Main runs the tests, or a kubectl child when re-executed by the runner.
func Main(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "kubectl-child" {
		os.Exit(kubectl.ChildMain(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// Env is a running nyyrikkid with its fakes.
type Env struct {
	AS       *authntest.Server
	Telegram *telegramtest.Fake
	API      *FakeAPIServer
	Config   *config.Config
	Audit    *SyncBuffer
	// CAFile trusts nyyrikkid's certificate.
	CAFile string
	// Client trusts nyyrikkid's certificate.
	Client   *http.Client
	Dir      string
	MainAddr string
	cancel   context.CancelFunc
	done     chan error
}

// SyncBuffer is a goroutine-safe buffer for the audit stream.
type SyncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *SyncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *SyncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Records returns the audit records written so far.
func (s *SyncBuffer) Records() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// Option changes the config before start.
type Option func(*config.Config)

// Start runs nyyrikkid until the test ends.
func Start(t *testing.T, opts ...Option) *Env {
	t.Helper()
	dir := t.TempDir()
	e := &Env{AS: authntest.New(t), Telegram: telegramtest.New(t), API: NewFakeAPIServer(t), Audit: &SyncBuffer{}, Dir: dir}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	e.MainAddr = addr
	canonical := "https://" + addr
	e.AS.Audience = canonical + "/mcp"

	certFile, keyFile, pool := selfSigned(t, dir)
	// The CLI's CA file must trust both nyyrikkid and the authorization
	// server.
	certPEM, _ := os.ReadFile(certFile)
	asPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.AS.Certificate().Raw})
	e.CAFile = write(t, dir, "ca-bundle.pem", string(certPEM)+string(asPEM))
	e.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	secret := write(t, dir, "introspection-secret", e.AS.IntrospectionSecret)
	apiCA := write(t, dir, "api-ca.crt", e.API.CAPEM())
	apiToken := write(t, dir, "api-token", FakeSAToken)

	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := config.Defaults()
	c.Server = config.Server{
		CanonicalURL: canonical, Listen: addr, HealthListen: "127.0.0.1:0",
		TLSCertFile: certFile, TLSKeyFile: keyFile,
		StateDir: filepath.Join(dir, "state"), RuntimeDir: filepath.Join(dir, "run"),
	}
	c.Auth = config.Auth{Issuer: e.AS.Issuer(), CLIClientID: "nyyrikki-cli", Scope: "nyyrikki",
		IntrospectionClientID: e.AS.IntrospectionClient, IntrospectionSecretFile: secret}
	c.Approval.Timeout = config.Duration(20 * time.Second)
	c.Humans = []config.Human{{ID: "owner", Subject: e.AS.Subject,
		Kubernetes: config.KubeIdent{User: "owner@example.com", Groups: []string{"admins"}}, TelegramUserID: ApproverID}}
	c.Targets = []config.Target{
		{Name: "prod", Description: "fake cluster", Humans: []string{"owner"},
			Kubernetes: config.KubeTarget{Server: e.API.URL, CAFile: apiCA, TokenFile: apiToken}},
		{Name: "lab", Humans: []string{"owner"},
			Kubernetes: config.KubeTarget{Server: e.API.URL, CAFile: apiCA, TokenFile: apiToken}},
		{Name: "claude-only", Humans: []string{"owner"}, Clients: []string{"claude-code"},
			Kubernetes: config.KubeTarget{Server: e.API.URL, CAFile: apiCA, TokenFile: apiToken}},
	}
	c.Telegram = config.Telegram{APIURL: e.Telegram.URL(), BotTokenFile: e.Telegram.TokenFile(t)}
	for _, o := range opts {
		o(c)
	}
	e.Config = c

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		e.done <- server.Run(ctx, c, server.Options{
			Version: "test", AuditOut: e.Audit, Executable: exe,
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			AuthHTTPClient: e.AS.Client(),
			Ready:          func(net.Addr, net.Addr) { close(ready) },
		})
	}()
	select {
	case <-ready:
	case err := <-e.done:
		t.Fatalf("nyyrikkid did not start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("nyyrikkid did not start")
	}
	t.Cleanup(e.Stop)
	// The bot is healthy once it has polled.
	e.Telegram.Wait(t, "first getUpdates", func() bool { return e.Telegram.Calls("getUpdates") > 0 })
	return e
}

// Stop stops nyyrikkid.
func (e *Env) Stop() {
	e.cancel()
	select {
	case <-e.done:
	case <-time.After(10 * time.Second):
	}
}

// Stopped reports whether nyyrikkid has exited.
func (e *Env) Stopped() bool {
	select {
	case err := <-e.done:
		e.done <- err
		return true
	default:
		return false
	}
}

// URL returns nyyrikkid's canonical URL.
func (e *Env) URL() string { return e.Config.Server.CanonicalURL }

// Approve waits for the n-th prompt (1-based) and taps button on it as the
// approver.
func (e *Env) Tap(t *testing.T, n int, button string) telegramtest.Message {
	t.Helper()
	msgs := e.Telegram.WaitSent(t, n)
	m := msgs[n-1]
	// The bot stores a prompt's button keys right after sendMessage
	// returns; a tap before that is rejected (fail closed). Wait for it.
	e.Telegram.Wait(t, "prompt stored", func() bool { return e.promptStored(m.MessageID) })
	cur, _ := e.Telegram.Message(m.ChatID, m.MessageID)
	a := e.Telegram.WaitAnswer(t, e.Telegram.Tap(t, cur, button, ApproverID))
	t.Logf("tap %q on prompt %d answered %+v", button, n, a)
	if a.Text == "No longer valid" {
		for _, r := range e.Audit.Records() {
			if r["kind"] == "callback_rejected" {
				t.Logf("rejected: %v", r["detail"])
			}
		}
	}
	return cur
}

func (e *Env) promptStored(msgID int64) bool {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.Config.Server.StateDir, "nyyrikki.db")+"?mode=ro")
	if err != nil {
		return false
	}
	defer db.Close()
	var n int
	err = db.QueryRow("SELECT COUNT(*) FROM telegram_prompts WHERE message_id = ?", msgID).Scan(&n)
	return err == nil && n > 0
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func selfSigned(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nyyrikki-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	certFile = write(t, dir, "tls.crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	keyFile = write(t, dir, "tls.key", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})))
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return
}

// FakeSAToken is the token the fake apiserver expects from Nyyrikki.
const FakeSAToken = "fake-sa-token-0123456789"

// FakeAPIServer is a minimal Kubernetes API server: /version, discovery for
// pods, and pod get/list/delete. It records the identity each request
// impersonated.
type FakeAPIServer struct {
	*httptest.Server
	mu       sync.Mutex
	Requests []APIRequest
	Version  string // minor version, default "35"
	deleted  map[string]bool
}

// APIRequest is one request the fake apiserver saw.
type APIRequest struct {
	Method, Path string
	User         string
	Groups       []string
	Bearer       string
}

// NewFakeAPIServer starts one.
func NewFakeAPIServer(t *testing.T) *FakeAPIServer {
	f := &FakeAPIServer{Version: "35", deleted: map[string]bool{}}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// CAPEM is the server's certificate as PEM.
func (f *FakeAPIServer) CAPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw}))
}

// Seen returns the impersonated requests other than /version.
func (f *FakeAPIServer) Seen() []APIRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []APIRequest
	for _, r := range f.Requests {
		if r.Path != "/version" {
			out = append(out, r)
		}
	}
	return out
}

func (f *FakeAPIServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.Requests = append(f.Requests, APIRequest{Method: r.Method, Path: r.URL.Path,
		User: r.Header.Get("Impersonate-User"), Groups: r.Header.Values("Impersonate-Group"),
		Bearer: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
	minor := f.Version
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/shop/pods/")
	gone := f.deleted[name]
	if r.Method == http.MethodDelete {
		f.deleted[name] = true
	}
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+FakeSAToken {
		http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":401}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	pod := func(name string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": name, "namespace": "shop", "uid": "u-" + name, "creationTimestamp": "2026-10-26T00:00:00Z"}}
	}
	switch {
	case r.URL.Path == "/version":
		fmt.Fprintf(w, `{"major":"1","minor":%q,"gitVersion":"v1.%s.0"}`, minor, minor)
	case r.URL.Path == "/api":
		fmt.Fprint(w, `{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"127.0.0.1"}]}`)
	case r.URL.Path == "/apis":
		fmt.Fprint(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[]}`)
	case r.URL.Path == "/api/v1":
		fmt.Fprint(w, `{"kind":"APIResourceList","groupVersion":"v1","resources":[{"name":"pods","singularName":"pod","namespaced":true,"kind":"Pod","verbs":["get","list","delete"],"shortNames":["po"]}]}`)
	case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/shop/pods/") && gone:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404,"details":{"name":%q,"kind":"pods"}}`, name)
	case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/shop/pods/"):
		_ = json.NewEncoder(w).Encode(pod(name))
	case r.URL.Path == "/api/v1/namespaces/shop/pods":
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{},
			"items": []any{pod("api-7f"), pod("web-1")}})
	default:
		http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":404}`, http.StatusNotFound)
	}
}
