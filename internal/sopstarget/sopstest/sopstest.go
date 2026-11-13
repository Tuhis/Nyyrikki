// Package sopstest is a fake Google for tests of the SOPS target
// (docs/10 SO4): Cloud KMS's decrypt and encrypt over REST, a service
// account token endpoint and a federation token endpoint. It must only
// be imported from _test.go files.
package sopstest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/getsops/sops/v3"
	sopsaes "github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/keyservice"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

// Key names the tests use.
const (
	KeyProd  = "projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod"
	KeyOther = "projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/other"
	// KeyForeign is a key the fake serves that no test target lists.
	KeyForeign = "projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/foreign"
)

// Call is one request the fake Cloud KMS received.
type Call struct {
	Op     string // "decrypt" or "encrypt"
	Key    string
	Reason string // X-Goog-Request-Reason
	Token  string // the bearer token
}

// Fake is a fake Cloud KMS and its token endpoints.
type Fake struct {
	srv    *httptest.Server
	secret []byte

	mu     sync.Mutex
	calls  []Call
	tokens int
	// status makes calls for a key fail with an HTTP status.
	status map[string]int
	// tokenStatus makes token exchanges fail with an HTTP status.
	tokenStatus int
	// hold, when set, blocks every KMS call until it is closed or the
	// request ends.
	hold chan struct{}
	// entered receives once per held call.
	entered chan struct{}
	// other counts requests that are neither a KMS method nor a token
	// exchange.
	other int
}

var kmsPath = regexp.MustCompile(`^/v1/(projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/:]+):(decrypt|encrypt)$`)

// New starts the fake. It stops when the test ends.
func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{secret: make([]byte, 32), status: map[string]int{}, entered: make(chan struct{}, 64)}
	if _, err := rand.Read(f.secret); err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// Close stops the fake now, as an outage.
func (f *Fake) Close() { f.srv.Close() }

// OtherRequests is how many requests were neither a KMS method nor a
// token exchange.
func (f *Fake) OtherRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.other
}

// Base64 is b in standard base64, as a file holds a wrapped key.
func Base64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// URL is the fake's base URL.
func (f *Fake) URL() string { return f.srv.URL }

// ClientOptions point a Cloud KMS client at the fake.
func (f *Fake) ClientOptions() []option.ClientOption {
	return []option.ClientOption{option.WithEndpoint(f.srv.URL)}
}

// Calls returns the KMS calls received so far.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// TokenExchanges is how many tokens were issued.
func (f *Fake) TokenExchanges() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens
}

// FailKey makes every call for key answer with status (0 to stop).
func (f *Fake) FailKey(key string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[key] = status
}

// FailTokens makes every token exchange answer with status (0 to stop).
func (f *Fake) FailTokens(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenStatus = status
}

// Hold makes every KMS call block until the returned function is
// called. Entered reports each call that is now blocked.
func (f *Fake) Hold() (release func()) {
	ch := make(chan struct{})
	f.mu.Lock()
	f.hold = ch
	f.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// Entered receives once for each call that reached a Hold.
func (f *Fake) Entered() <-chan struct{} { return f.entered }

func (f *Fake) aead(key string) cipher.AEAD {
	sum := sha256.Sum256(append(append([]byte{}, f.secret...), key...))
	b, _ := aes.NewCipher(sum[:])
	g, _ := cipher.NewGCM(b)
	return g
}

// Wrap encrypts plaintext under key, as the fake's encrypt does.
func (f *Fake) Wrap(key string, plaintext []byte) []byte {
	g := f.aead(key)
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	return g.Seal(nonce, nonce, plaintext, nil)
}

func (f *Fake) unwrap(key string, ct []byte) ([]byte, bool) {
	g := f.aead(key)
	if len(ct) < g.NonceSize() {
		return nil, false
	}
	pt, err := g.Open(nil, ct[:g.NonceSize()], ct[g.NonceSize():], nil)
	return pt, err == nil
}

func apiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "message": msg, "status": http.StatusText(status)}})
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/token", stsPath:
		f.token(w, r)
		return
	}
	m := kmsPath.FindStringSubmatch(r.URL.Path)
	if m == nil || r.Method != http.MethodPost {
		f.mu.Lock()
		f.other++
		f.mu.Unlock()
		apiError(w, http.StatusNotFound, "no such method")
		return
	}
	key, op := m[1], m[2]
	f.mu.Lock()
	f.calls = append(f.calls, Call{Op: op, Key: key, Reason: r.Header.Get("X-Goog-Request-Reason"),
		Token: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
	status, hold := f.status[key], f.hold
	f.mu.Unlock()
	if hold != nil {
		f.entered <- struct{}{}
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
	}
	if status != 0 {
		// The message stands in for what Google would say; no test may
		// find it in a result, a log or the audit record.
		apiError(w, status, "GOOGLE-ERROR-TEXT for "+key)
		return
	}
	var body struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(b, &body); err != nil {
		apiError(w, http.StatusBadRequest, "bad body")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if op == "encrypt" {
		pt, err := base64.StdEncoding.DecodeString(body.Plaintext)
		if err != nil {
			apiError(w, http.StatusBadRequest, "bad plaintext")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"name": key + "/cryptoKeyVersions/1", "ciphertext": base64.StdEncoding.EncodeToString(f.Wrap(key, pt))})
		return
	}
	ct, err := base64.StdEncoding.DecodeString(body.Ciphertext)
	if err != nil {
		apiError(w, http.StatusBadRequest, "bad ciphertext")
		return
	}
	pt, ok := f.unwrap(key, ct)
	if !ok {
		apiError(w, http.StatusBadRequest, "Decryption failed: the ciphertext is invalid. GOOGLE-ERROR-TEXT")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	status := f.tokenStatus
	if status == 0 {
		f.tokens++
	}
	n := f.tokens
	f.mu.Unlock()
	if status != 0 {
		apiError(w, status, "GOOGLE-TOKEN-ERROR-TEXT")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{"access_token": fmt.Sprintf("fake-access-token-%d", n), "token_type": "Bearer", "expires_in": 3600}
	if r.URL.Path == stsPath {
		out["issued_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
	}
	_ = json.NewEncoder(w).Encode(out)
}

// stsPath is the path of Google's token exchange.
const stsPath = "/v1/token"

// TokenHTTPClient is an HTTP client that sends a request for one of
// Google's token endpoints to the fake, and fails any other. The
// credential files name Google's real endpoints, the only ones a
// credential file may name.
func (f *Fake) TokenHTTPClient() *http.Client {
	return &http.Client{Transport: tokenTransport{f}}
}

type tokenTransport struct{ f *Fake }

func (t tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	switch r.URL.Host {
	case "oauth2.googleapis.com", "sts.googleapis.com":
	default:
		return nil, fmt.Errorf("sopstest: a token request for %s", r.URL.Host)
	}
	to, err := url.Parse(t.f.srv.URL)
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host, r.Host = to.Scheme, to.Host, to.Host
	return http.DefaultTransport.RoundTrip(r)
}

// ServiceAccountFile writes a service account key whose tokens come from
// the fake, and returns its path.
func (f *Fake) ServiceAccountFile(t testing.TB, dir string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "acme", "private_key_id": "k1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "nyyrikki-sops@acme.iam.gserviceaccount.com", "client_id": "1",
		"token_uri": "https://oauth2.googleapis.com/token",
	})
	return writeFile(t, dir, "sa.json", b)
}

// ExternalAccountFile writes a Workload Identity Federation
// configuration whose subject token is read from a file and exchanged
// at the fake, and returns its path.
func (f *Fake) ExternalAccountFile(t testing.TB, dir string) string {
	t.Helper()
	sub := writeFile(t, dir, "subject-token", []byte("projected-service-account-token"))
	b, _ := json.Marshal(map[string]any{
		"type":               "external_account",
		"audience":           "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/c",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_url":          "https://sts.googleapis.com" + stsPath,
		"credential_source":  map[string]any{"file": sub},
	})
	return writeFile(t, dir, "wif.json", b)
}

func writeFile(t testing.TB, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// keyService wraps data keys with the fake's own function, without a
// call, so that a fixture leaves no trace in Calls.
type keyService struct{ f *Fake }

func (k keyService) Encrypt(_ context.Context, req *keyservice.EncryptRequest, _ ...grpc.CallOption) (*keyservice.EncryptResponse, error) {
	ct := k.f.Wrap(req.GetKey().GetGcpKmsKey().GetResourceId(), req.GetPlaintext())
	return &keyservice.EncryptResponse{Ciphertext: []byte(Base64(ct))}, nil
}

func (k keyService) Decrypt(context.Context, *keyservice.DecryptRequest, ...grpc.CallOption) (*keyservice.DecryptResponse, error) {
	return nil, errors.New("sopstest: fixtures are only encrypted")
}

// EncryptYAML encrypts plain YAML with the SOPS library under key, which
// the fake can unwrap, and returns the encrypted file. meta, if set,
// changes the file's metadata first (its rules, its keys).
func (f *Fake) EncryptYAML(t testing.TB, plain, key string, meta func(*sops.Metadata)) []byte {
	t.Helper()
	return f.Encrypt(t, "yaml", plain, key, meta)
}

// Encrypt is EncryptYAML for a file of type typ: yaml, json or dotenv.
func (f *Fake) Encrypt(t testing.TB, typ, plain, key string, meta func(*sops.Metadata)) []byte {
	t.Helper()
	format, ok := map[string]formats.Format{"yaml": formats.Yaml, "json": formats.Json, "dotenv": formats.Dotenv}[typ]
	if !ok {
		t.Fatalf("sopstest: no file type %q", typ)
	}
	st := common.StoreForFormat(format, sopsconfig.NewStoresConfig())
	branches, err := st.LoadPlainFile([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	tree := sops.Tree{Branches: branches, Metadata: sops.Metadata{
		KeyGroups: []sops.KeyGroup{{gcpkms.NewMasterKeyFromResourceID(key)}}, Version: "3.13.3"}}
	if meta != nil {
		meta(&tree.Metadata)
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyService{f}})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := common.EncryptTree(common.EncryptTreeOpts{DataKey: dataKey, Tree: &tree, Cipher: sopsaes.NewCipher()}); err != nil {
		t.Fatal(err)
	}
	out, err := st.EmitEncryptedFile(tree)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// EncryptYAMLRegex is EncryptYAML with SOPS's encrypted_regex rule, for
// callers that don't import the SOPS library.
func (f *Fake) EncryptYAMLRegex(t testing.TB, plain, key, encryptedRegex string) []byte {
	t.Helper()
	return f.EncryptYAML(t, plain, key, func(m *sops.Metadata) { m.EncryptedRegex = encryptedRegex })
}
