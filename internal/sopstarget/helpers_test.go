package sopstarget

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsops/sops/v3"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
	"github.com/Tuhis/Nyyrikki/internal/sopstarget/sopstest"
)

// The plaintext most tests work on: a Secret manifest, as Flux keeps
// them, whose data is encrypted and whose identity stays in cleartext.
const secretYAML = `apiVersion: v1
kind: Secret
metadata:
    name: db-creds
    namespace: shop
stringData:
    password: hunter2
    user: app
`

const secretRegex = "^(data|stringData)$"

var testKeys = []string{sopstest.KeyProd, sopstest.KeyOther}

var (
	sopsOnce sync.Once
	sopsDir  string
	sopsBin  string
	sopsErr  error
)

// TestMain removes the sops program the tests built.
func TestMain(m *testing.M) {
	code := m.Run()
	if sopsDir != "" {
		os.RemoveAll(sopsDir)
	}
	os.Exit(code)
}

// sopsProgram builds the sops program this module pins as a tool
// (go.mod), once per test binary: the same version as the library
// (docs/10 G3).
func sopsProgram(t testing.TB) string {
	t.Helper()
	sopsOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nyyrikki-sops-")
		if err != nil {
			sopsErr = err
			return
		}
		sopsDir = dir
		sopsBin = filepath.Join(dir, "sops")
		out, err := exec.Command("go", "build", "-o", sopsBin, "github.com/getsops/sops/v3/cmd/sops").CombinedOutput()
		if err != nil {
			sopsErr = &buildError{string(out)}
		}
	})
	if sopsErr != nil {
		t.Fatalf("building the pinned sops program: %v", sopsErr)
	}
	return sopsBin
}

type buildError struct{ out string }

func (e *buildError) Error() string { return e.out }

// sopsCLI runs the real sops program against the fake Cloud KMS, on a
// file holding content, and returns its stdout.
func sopsCLI(t testing.TB, f *sopstest.Fake, name string, content []byte, args ...string) ([]byte, error) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sopsProgram(t), append(args, file)...)
	cmd.Dir = dir
	cmd.Env = []string{
		"HOME=" + dir, "PATH=" + os.Getenv("PATH"),
		"SOPS_GCP_KMS_ENDPOINT=" + f.URL(), "SOPS_GCP_KMS_CLIENT_TYPE=rest",
		"GOOGLE_OAUTH_ACCESS_TOKEN=the-sops-program",
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, &buildError{stderr.String()}
	}
	return stdout.Bytes(), nil
}

// encrypted is secretYAML encrypted by the real sops program with
// KeyProd, data and stringData only.
func encrypted(t testing.TB, f *sopstest.Fake) []byte {
	t.Helper()
	return mustSops(t, f, "secret.yaml", []byte(secretYAML), "encrypt", "--gcp-kms", sopstest.KeyProd, "--encrypted-regex", secretRegex)
}

func mustSops(t testing.TB, f *sopstest.Fake, name string, content []byte, args ...string) []byte {
	t.Helper()
	out, err := sopsCLI(t, f, name, content, args...)
	if err != nil {
		t.Fatalf("sops %v: %v", args, err)
	}
	return out
}

// memAudit keeps audit records in memory.
type memAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail bool
}

func (m *memAudit) Append(_ context.Context, r audit.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return io.ErrClosedPipe
	}
	m.recs = append(m.recs, r)
	return nil
}

func (m *memAudit) kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.recs {
		out = append(out, r.Kind)
	}
	return out
}

func (m *memAudit) last(kind string) *audit.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.recs) - 1; i >= 0; i-- {
		if m.recs[i].Kind == kind {
			r := m.recs[i]
			return &r
		}
	}
	return nil
}

func (m *memAudit) text() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(m.recs)
	return string(b)
}

// env is a runner with one target, "secrets", on the fake.
type env struct {
	fake   *sopstest.Fake
	runner *Runner
	audit  *memAudit
	log    *bytes.Buffer
	creds  string
}

const testTarget = "secrets"

func newEnv(t *testing.T) *env {
	t.Helper()
	f := sopstest.New(t)
	return newEnvWith(t, f, f.ServiceAccountFile(t, t.TempDir()))
}

func newEnvWith(t *testing.T, f *sopstest.Fake, credsFile string) *env {
	t.Helper()
	e := &env{fake: f, audit: &memAudit{}, log: &bytes.Buffer{}, creds: credsFile}
	r, err := NewRunner(RunnerConfig{
		Targets:       map[string]Target{testTarget: {Name: testTarget, CredentialsFile: credsFile, Keys: testKeys}},
		Limits:        Limits{DefaultTimeout: 10 * time.Second, MaxTimeout: 20 * time.Second, MaxOutput: 1 << 20},
		Audit:         e.audit,
		Logger:        slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ClientOptions: f.ClientOptions(),
		Getenv:        func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.runner = r
	return e
}

func mustParse(t testing.TB, stdin []byte, args ...string) *Request {
	t.Helper()
	r, err := Parse(args, stdin, false, testKeys)
	if err != nil {
		t.Fatalf("Parse(%q): %v", args, err)
	}
	return r
}

// grantFor is a one-off Grant that covers req on the test target.
func grantFor(ctx context.Context, req *Request) *decision.Grant {
	return decisiontest.Grant(ctx, decisiontest.Spec{
		RunID: "run_01TEST", Target: testTarget,
		Digest:    req.Digest(testTarget, ""),
		CoveredBy: codes.CoveredOneOff, ApprovalID: "apr_01TEST",
		Human: "owner", AgentKey: "agent-key", ClientID: "nyyrikki-cli",
	})
}

func (e *env) run(t *testing.T, req *Request) ([]byte, error) {
	t.Helper()
	res, err := e.runner.Run(grantFor(context.Background(), req), req, 0)
	if err != nil {
		if res != nil {
			t.Fatalf("a failed run returned a result: %q", res.Stdout)
		}
		return nil, err
	}
	return res.Stdout, nil
}

// common flags of a request on secret.yaml.
func yamlFlags(extra ...string) []string {
	return append([]string{"--input-type", "yaml", "--filename-override", "clusters/prod/shop/db-creds.enc.yaml"}, extra...)
}

func wantCode(t *testing.T, err error, code codes.Code, detail string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; want %s/%s", code, detail)
	}
	if codes.Of(err) != code || codes.DetailOf(err) != detail {
		t.Fatalf("got %s/%s (%v); want %s/%s", codes.Of(err), codes.DetailOf(err), err, code, detail)
	}
}

// noLibraryText fails if s holds text of the SOPS library's or of the
// fake Google's (docs/10 D9, G4).
func noLibraryText(t *testing.T, what, s string) {
	t.Helper()
	for _, bad := range []string{"GOOGLE-", "MAC mismatch", "File has", "computed ", "Could not decrypt", "cipher:", "Recovery failed", "hunter2", "fake-access-token"} {
		if strings.Contains(s, bad) {
			t.Fatalf("%s holds %q:\n%s", what, bad, s)
		}
	}
}

// libEncrypt encrypts plain YAML with the SOPS library under KeyProd,
// with the metadata meta sets: for fixtures the sops program can't make.
func libEncrypt(t testing.TB, f *sopstest.Fake, plain string, meta func(*sops.Metadata)) []byte {
	t.Helper()
	return f.EncryptYAML(t, plain, sopstest.KeyProd, meta)
}
