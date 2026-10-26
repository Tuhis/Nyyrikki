package kubectl

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
)

const testToken = "nyyrikki-sa-token-value-0123456789"

// seen is one request the fake apiserver received.
type seen struct {
	Path, Method, Auth, User string
	Groups                   []string
	Body                     string
}

// fakeAPIServer serves /version and a few raw paths over TLS and records
// every request with its credential and impersonation headers.
type fakeAPIServer struct {
	*httptest.Server
	mu      sync.Mutex
	reqs    []seen
	major   string
	minor   string
	version int // status for /version
	caFile  string
	tokFile string
}

func newFakeAPIServer(t *testing.T) *fakeAPIServer {
	t.Helper()
	f := &fakeAPIServer{major: "1", minor: "35", version: http.StatusOK}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	dir := t.TempDir()
	f.caFile = filepath.Join(dir, "ca.crt")
	f.tokFile = filepath.Join(dir, "token")
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw})
	if err := os.WriteFile(f.caFile, pemCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.tokFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeAPIServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, seen{
		Path: r.URL.Path, Method: r.Method, Auth: r.Header.Get("Authorization"),
		User: r.Header.Get("Impersonate-User"), Groups: r.Header.Values("Impersonate-Group"),
		Body: string(body),
	})
	major, minor, status := f.major, f.minor, f.version
	f.mu.Unlock()
	switch r.URL.Path {
	case "/version":
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"major":%q,"minor":%q,"gitVersion":"v%s.%s.0"}`, major, minor, major, minor)
	case "/raw/hello":
		io.WriteString(w, "hello from the target\n")
	case "/raw/big":
		io.WriteString(w, strings.Repeat("x", 4096))
	case "/raw/slow":
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(time.Minute):
		}
	case "/raw/post":
		io.WriteString(w, "posted\n")
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAPIServer) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

// childRequests are the requests that came from kubectl, not from the
// version check (which carries no impersonation).
func (f *fakeAPIServer) childRequests() []seen {
	var out []seen
	for _, r := range f.requests() {
		if r.User != "" || len(r.Groups) > 0 || r.Path != "/version" {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAPIServer) target(name string) Target {
	return Target{Name: name, Server: f.URL, CAFile: f.caFile, TokenFile: f.tokFile}
}

// recAudit records audit records and can be made to fail.
type recAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail func(audit.Record) bool
}

func (a *recAudit) Append(_ context.Context, r audit.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil && a.fail(r) {
		return errors.New("audit sink down")
	}
	a.recs = append(a.recs, r)
	return nil
}

func (a *recAudit) kinds() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var k []string
	for _, r := range a.recs {
		k = append(k, r.Kind)
	}
	return k
}

func (a *recAudit) last(kind string) (audit.Record, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.recs) - 1; i >= 0; i-- {
		if a.recs[i].Kind == kind {
			return a.recs[i], true
		}
	}
	return audit.Record{}, false
}

type harness struct {
	t       *testing.T
	api     *fakeAPIServer
	runner  *Runner
	audit   *recAudit
	runtime string
}

func newHarness(t *testing.T, exe string, mod func(*RunnerConfig)) *harness {
	t.Helper()
	h := &harness{t: t, api: newFakeAPIServer(t), audit: &recAudit{}, runtime: t.TempDir()}
	if exe == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		exe = self
	}
	cfg := RunnerConfig{
		RuntimeDir: h.runtime,
		Executable: exe,
		Targets:    map[string]Target{"lab": h.api.target("lab")},
		Audit:      h.audit,
	}
	if mod != nil {
		mod(&cfg)
	}
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.runner = r
	return h
}

var testIdentity = approval.Identity{User: "owner@example.com", Groups: []string{"admins", "devs"}}

func parse(t *testing.T, args []string, stdin []byte, interactive bool) *request.Canonical {
	t.Helper()
	c, err := request.Parse(args, stdin, interactive)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func grantFor(ctx context.Context, target string, c *request.Canonical, mod func(*decisiontest.Spec)) *decision.Grant {
	s := decisiontest.Spec{
		RunID:       "run_test",
		Target:      target,
		RunAs:       testIdentity,
		Digest:      request.Digest(target, c),
		CoveredBy:   codes.CoveredOneOff,
		ApprovalID:  "apr_test",
		Interactive: c.Interactive(),
		Human:       "owner",
		AgentKey:    "agent-key",
		ClientID:    "nyyrikki-cli",
	}
	if mod != nil {
		mod(&s)
	}
	return decisiontest.Grant(ctx, s)
}

func (h *harness) assertRuntimeEmpty() {
	h.t.Helper()
	entries, err := os.ReadDir(h.runtime)
	if err != nil {
		h.t.Fatal(err)
	}
	if len(entries) != 0 {
		h.t.Fatalf("runtime dir not cleaned up: %v", entries)
	}
}

func wantCode(t *testing.T, err error, code codes.Code, detail string) {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want %s/%s", code, detail)
	}
	if codes.Of(err) != code || (detail != "" && codes.DetailOf(err) != detail) {
		t.Fatalf("err = %v (code %s, detail %q), want %s/%s", err, codes.Of(err), codes.DetailOf(err), code, detail)
	}
}

func TestRunRawGet(t *testing.T) {
	h := newHarness(t, "", nil)
	c := parse(t, []string{"get", "--raw", "/raw/hello"}, nil, false)
	g := grantFor(t.Context(), "lab", c, nil)
	res, err := h.runner.Run(g, c, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "hello from the target\n" {
		t.Fatalf("result = %d %q %q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if g.Context().Err() == nil {
		t.Error("grant not released")
	}
	if got := h.audit.kinds(); !slices.Equal(got, []string{codes.KindRunStarted, codes.KindRunFinished}) {
		t.Errorf("audit kinds = %v", got)
	}
	fin, _ := h.audit.last(codes.KindRunFinished)
	if fin.ExitCode == nil || *fin.ExitCode != 0 || fin.StdoutBytes != int64(len(res.Stdout)) ||
		fin.Human != "owner" || fin.Agent != "agent-key" || fin.ClientID != "nyyrikki-cli" ||
		fin.RunID != "run_test" || fin.ApprovalID != "apr_test" || fin.CoveredBy != codes.CoveredOneOff ||
		!slices.Equal(fin.Targets, []string{"lab"}) || fin.RunAs == nil || fin.RunAs.User != testIdentity.User ||
		fin.Request == nil || !slices.Equal(fin.Request.Argv, c.Argv()) {
		t.Errorf("run_finished record = %+v", fin)
	}
	h.assertRuntimeEmpty()
}

// TestKubeconfigImpersonation covers docs/04 G6 (unit): the target sees
// the grant's human through impersonation, with Nyyrikki's token, and the
// version check carries no impersonation.
func TestKubeconfigImpersonation(t *testing.T) {
	h := newHarness(t, "", nil)
	c := parse(t, []string{"get", "--raw", "/raw/hello"}, nil, false)
	if _, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 0); err != nil {
		t.Fatal(err)
	}
	reqs := h.api.requests()
	if len(reqs) < 2 || reqs[0].Path != "/version" || reqs[0].User != "" || reqs[0].Auth != "Bearer "+testToken {
		t.Fatalf("version check = %+v", reqs)
	}
	child := h.api.childRequests()
	if len(child) == 0 {
		t.Fatal("kubectl made no request")
	}
	for _, r := range child {
		if r.User != testIdentity.User || !slices.Equal(r.Groups, testIdentity.Groups) || r.Auth != "Bearer "+testToken {
			t.Errorf("child request %s: user %q groups %q auth %q", r.Path, r.User, r.Groups, r.Auth)
		}
	}
	// An --as in the request never gets this far.
	if _, err := request.Parse([]string{"get", "--raw", "/raw/hello", "--as", "system:admin"}, nil, false); err == nil {
		t.Fatal("--as accepted")
	}
	// A grant without a user doesn't run as Nyyrikki's own account.
	c2 := parse(t, []string{"get", "--raw", "/raw/hello"}, nil, false)
	g := grantFor(t.Context(), "lab", c2, func(s *decisiontest.Spec) { s.RunAs = approval.Identity{} })
	_, err := h.runner.Run(g, c2, 0)
	wantCode(t, err, codes.Internal, DetailNoIdentity)
}

// TestChildEnvironment and TestKubeconfigHasNoSecret cover docs/04 G4.
func TestChildEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	t.Setenv("KUBECONFIG", "/etc/should-not-leak")
	h := newHarness(t, modeExecutable(t, modeEnvDump), nil)
	c := parse(t, []string{"get", "pods", "-n", "shop"}, nil, false)
	res, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout)
	var env []string
	var dir string
	for _, line := range strings.Split(out, "\n") {
		if e, ok := strings.CutPrefix(line, "ENV "); ok {
			env = append(env, e)
			if v, ok := strings.CutPrefix(e, "HOME="); ok {
				dir = v
			}
		}
	}
	if dir == "" || filepath.Dir(dir) != h.runtime {
		t.Fatalf("HOME = %q, want a directory under %s", dir, h.runtime)
	}
	want := []string{
		"HOME=" + dir,
		"KUBECACHEDIR=" + filepath.Join(dir, "cache"),
		"KUBECONFIG=" + filepath.Join(dir, "kubeconfig"),
		"KUBERC=off",
		"LANG=C.UTF-8",
		"PATH=",
	}
	if !slices.Equal(env, want) {
		t.Fatalf("child environment =\n%q\nwant\n%q", env, want)
	}
	for _, line := range []string{"KUBECONFIG_MODE 600", "RUNDIR_MODE 700", "ARGS " + ChildArg + " " + strings.Join(c.Argv(), " ")} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
	h.assertRuntimeEmpty()
}

func TestKubeconfigHasNoSecret(t *testing.T) {
	h := newHarness(t, modeExecutable(t, modeEnvDump), nil)
	c := parse(t, []string{"version"}, nil, false)
	res, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, kc, ok := strings.Cut(string(res.Stdout), "---\n")
	if !ok {
		t.Fatalf("no kubeconfig in output: %s", res.Stdout)
	}
	if strings.Contains(kc, testToken) {
		t.Fatalf("kubeconfig contains the token:\n%s", kc)
	}
	for _, want := range []string{
		"tokenFile: " + h.api.tokFile,
		"certificate-authority: " + h.api.caFile,
		"server: " + h.api.URL,
		"as: " + testIdentity.User,
		"- admins", "- devs",
		"current-context: target",
	} {
		if !strings.Contains(kc, want) {
			t.Errorf("kubeconfig lacks %q:\n%s", want, kc)
		}
	}
	if strings.Contains(kc, "token:") || strings.Contains(kc, "client-key") {
		t.Errorf("kubeconfig has an inline credential:\n%s", kc)
	}
}

func TestInClusterTarget(t *testing.T) {
	api := newFakeAPIServer(t)
	u, _ := url.Parse(api.URL)
	t.Setenv("KUBERNETES_SERVICE_HOST", u.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", u.Port())
	sa := t.TempDir()
	for name, src := range map[string]string{"ca.crt": api.caFile, "token": api.tokFile} {
		b, _ := os.ReadFile(src)
		os.WriteFile(filepath.Join(sa, name), b, 0o600)
	}
	runtime := t.TempDir()
	r, err := NewRunner(RunnerConfig{
		RuntimeDir: runtime, Executable: modeExecutable(t, modeEnvDump),
		Targets:           map[string]Target{"prod": {Name: "prod", InCluster: true}},
		Audit:             &recAudit{},
		ServiceAccountDir: sa,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, []string{"version"}, nil, false)
	res, err := r.Run(grantFor(t.Context(), "prod", c, nil), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server: " + api.URL, "tokenFile: " + filepath.Join(sa, "token"), "certificate-authority: " + filepath.Join(sa, "ca.crt")} {
		if !strings.Contains(string(res.Stdout), want) {
			t.Errorf("kubeconfig lacks %q:\n%s", want, res.Stdout)
		}
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := NewRunner(RunnerConfig{RuntimeDir: runtime, Executable: "x", Targets: map[string]Target{"prod": {Name: "prod", InCluster: true}}, Audit: &recAudit{}}); err == nil {
		t.Error("in-cluster target accepted without KUBERNETES_SERVICE_HOST")
	}
}

// TestRunDigestMismatch covers docs/04 G3.
func TestRunDigestMismatch(t *testing.T) {
	h := newHarness(t, "", nil)
	approved := parse(t, []string{"get", "--raw", "/raw/hello"}, nil, false)
	sent := parse(t, []string{"delete", "pod", "x"}, nil, false)
	g := grantFor(t.Context(), "lab", approved, nil)
	res, err := h.runner.Run(g, sent, 0)
	wantCode(t, err, codes.Internal, DetailDigestMismatch)
	if res != nil {
		t.Error("result for a refused run")
	}
	// Same argv, other target.
	g2 := grantFor(t.Context(), "lab", approved, func(s *decisiontest.Spec) { s.Digest = request.Digest("prod", approved) })
	_, err = h.runner.Run(g2, approved, 0)
	wantCode(t, err, codes.Internal, DetailDigestMismatch)
	// Same request, interactive bit differs.
	it := parse(t, []string{"exec", "-it", "web", "--", "sh"}, nil, true)
	g3 := grantFor(t.Context(), "lab", it, func(s *decisiontest.Spec) { s.Interactive = false })
	_, err = h.runner.Run(g3, it, 0)
	wantCode(t, err, codes.Internal, DetailInteractiveMismatch)
	// An interactive request never runs through Run.
	_, err = h.runner.Run(grantFor(t.Context(), "lab", it, nil), it, 0)
	wantCode(t, err, codes.Internal, DetailInteractiveMismatch)

	if n := len(h.api.requests()); n != 0 {
		t.Errorf("target saw %d requests for refused runs", n)
	}
	if slices.Contains(h.audit.kinds(), codes.KindRunStarted) {
		t.Error("run_started recorded for a refused run")
	}
	if g.Context().Err() == nil || g2.Context().Err() == nil {
		t.Error("refused grant not released")
	}
	h.assertRuntimeEmpty()
}

// TestVersionCheck covers docs/04 G7 and D11.
func TestVersionCheck(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	clock := func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	h := newHarness(t, "", func(c *RunnerConfig) { c.Now = clock })
	ctx := t.Context()
	versionCalls := func() int {
		n := 0
		for _, r := range h.api.requests() {
			if r.Path == "/version" {
				n++
			}
		}
		return n
	}
	set := func(major, minor string) {
		h.api.mu.Lock()
		h.api.major, h.api.minor = major, minor
		h.api.mu.Unlock()
	}

	set("1", "34")
	wantCode(t, h.runner.CheckTarget(ctx, "lab"), codes.Unavailable, DetailTargetVersion)
	set("0", "99")
	wantCode(t, h.runner.CheckTarget(ctx, "lab"), codes.Unavailable, DetailTargetVersion)
	set("1", "")
	wantCode(t, h.runner.CheckTarget(ctx, "lab"), codes.Unavailable, DetailTargetUnreachable)
	set("1", "35+")
	if err := h.runner.CheckTarget(ctx, "lab"); err != nil {
		t.Fatalf("1.35+: %v", err)
	}
	calls := versionCalls()
	// Cached for 10 minutes, even if the target changed meanwhile.
	set("1", "20")
	nowMu.Lock()
	now = now.Add(9 * time.Minute)
	nowMu.Unlock()
	if err := h.runner.CheckTarget(ctx, "lab"); err != nil || versionCalls() != calls {
		t.Fatalf("cached check: err %v, calls %d → %d", err, calls, versionCalls())
	}
	nowMu.Lock()
	now = now.Add(2 * time.Minute)
	nowMu.Unlock()
	wantCode(t, h.runner.CheckTarget(ctx, "lab"), codes.Unavailable, DetailTargetVersion)
	set("2", "0")
	if err := h.runner.CheckTarget(ctx, "lab"); err != nil {
		t.Fatalf("2.0: %v", err)
	}

	// A refused target never runs.
	set("1", "34")
	nowMu.Lock()
	now = now.Add(time.Hour)
	nowMu.Unlock()
	c := parse(t, []string{"get", "--raw", "/raw/hello"}, nil, false)
	_, err := h.runner.Run(grantFor(ctx, "lab", c, nil), c, 0)
	wantCode(t, err, codes.Unavailable, DetailTargetVersion)
	if len(h.api.childRequests()) != 0 {
		t.Error("kubectl ran against a refused target")
	}
	if rec, ok := h.audit.last(codes.KindDependencyFailed); !ok || rec.Detail != DetailTargetVersion || rec.Decision != codes.Deny {
		t.Errorf("dependency_failed record = %+v", rec)
	}

	// Non-200, unknown and unreachable targets.
	h.api.mu.Lock()
	h.api.version = http.StatusForbidden
	h.api.mu.Unlock()
	wantCode(t, h.runner.CheckTarget(ctx, "lab"), codes.Unavailable, DetailTargetUnreachable)
	wantCode(t, h.runner.CheckTarget(ctx, "nope"), codes.TargetNotAllowed, DetailUnknownTarget)
	h.api.Close()
	err = h.runner.CheckTarget(ctx, "lab")
	wantCode(t, err, codes.Unavailable, DetailTargetUnreachable)
	if strings.Contains(err.Error(), testToken) {
		t.Error("error carries the token")
	}
}

// TestRunCutTimeout covers docs/04 G5: the timeout kills the whole
// process group. The limits leave the race-instrumented child time to
// start its grandchild and report it.
func TestRunCutTimeout(t *testing.T) {
	h := newHarness(t, modeExecutable(t, modeSleeper), nil)
	c := parse(t, []string{"get", "pods"}, nil, false)
	start := time.Now()
	res, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 3*time.Second)
	wantCode(t, err, codes.Expired, DetailTimeout)
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("cut took %s", d)
	}
	assertLeafDead(t, res)
	if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.Detail != DetailTimeout {
		t.Errorf("run_cut record = %+v", rec)
	}
	h.assertRuntimeEmpty()
}

// TestRunCutGrantEnded covers docs/04 G5 and D8: when the grant's context
// ends (elevation end, "End now"), the run is killed.
func TestRunCutGrantEnded(t *testing.T) {
	h := newHarness(t, modeExecutable(t, modeSleeper), nil)
	c := parse(t, []string{"get", "pods"}, nil, false)
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(3*time.Second, cancel)
	res, err := h.runner.Run(grantFor(ctx, "lab", c, nil), c, time.Minute)
	wantCode(t, err, codes.Expired, DetailGrantEnded)
	assertLeafDead(t, res)
	if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.Detail != DetailGrantEnded {
		t.Errorf("run_cut record = %+v", rec)
	}
	h.assertRuntimeEmpty()
}

// TestRunCutNotAfter: under an elevation, a run never outlasts its expiry.
func TestRunCutNotAfter(t *testing.T) {
	h := newHarness(t, modeExecutable(t, modeSleeper), nil)
	c := parse(t, []string{"get", "pods"}, nil, false)
	g := grantFor(t.Context(), "lab", c, func(s *decisiontest.Spec) {
		s.CoveredBy, s.ElevationID, s.ApprovalID = codes.CoveredElevation, "elv_test", ""
		s.NotAfter = time.Now().Add(500 * time.Millisecond)
	})
	_, err := h.runner.Run(g, c, 10*time.Minute)
	wantCode(t, err, codes.Expired, DetailGrantExpired)
	if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.ElevationID != "elv_test" || rec.CoveredBy != codes.CoveredElevation {
		t.Errorf("run_cut record = %+v", rec)
	}

	// Already expired: nothing starts.
	g2 := grantFor(t.Context(), "lab", c, func(s *decisiontest.Spec) { s.NotAfter = time.Now().Add(-time.Second) })
	_, err = h.runner.Run(g2, c, 0)
	wantCode(t, err, codes.Expired, DetailGrantEnded)
	h.assertRuntimeEmpty()
}

func TestRunCutRealKubectl(t *testing.T) {
	h := newHarness(t, "", nil)
	c := parse(t, []string{"get", "--raw", "/raw/slow"}, nil, false)
	_, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, time.Second)
	wantCode(t, err, codes.Expired, DetailTimeout)
	h.assertRuntimeEmpty()
}

func TestTimeoutClamped(t *testing.T) {
	h := newHarness(t, modeExecutable(t, modeSleeper), func(c *RunnerConfig) {
		c.Limits = Limits{DefaultTimeout: 300 * time.Millisecond, MaxTimeout: 600 * time.Millisecond}
	})
	c := parse(t, []string{"get", "pods"}, nil, false)
	for _, asked := range []time.Duration{0, time.Hour} {
		start := time.Now()
		_, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, asked)
		wantCode(t, err, codes.Expired, DetailTimeout)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("timeout %s ran %s", asked, d)
		}
	}
}

// assertLeafDead checks that the grandchild in the cut process group is
// gone (or a zombie waiting for init).
func assertLeafDead(t *testing.T, res *Result) {
	t.Helper()
	if res == nil {
		t.Fatal("no partial result for a cut run")
	}
	var pid int
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if v, ok := strings.CutPrefix(line, "LEAF "); ok {
			pid, _ = strconv.Atoi(v)
		}
	}
	if pid == 0 {
		t.Fatalf("no grandchild pid in %q", res.Stdout)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			if _, rest, ok := strings.Cut(string(stat), ") "); ok && strings.HasPrefix(rest, "Z") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("grandchild %d survived the cut", pid)
}

// TestRunDirRemoved covers docs/04 G5: the run directory is removed on
// success, failure and cut (each case asserts an empty runtime dir), and
// on a failed start.
func TestRunDirRemoved(t *testing.T) {
	h := newHarness(t, "", nil)
	// Failure: kubectl exits non-zero, with its own exit code.
	c := parse(t, []string{"get", "--raw", "/raw/missing"}, nil, false)
	res, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 1 || !strings.Contains(string(res.Stderr), "NotFound") && !strings.Contains(string(res.Stderr), "not found") {
		t.Errorf("result = %d %q", res.ExitCode, res.Stderr)
	}
	h.assertRuntimeEmpty()

	// A child that can't start.
	h2 := newHarness(t, "/nonexistent/nyyrikkid", nil)
	c2 := parse(t, []string{"get", "pods"}, nil, false)
	_, err = h2.runner.Run(grantFor(t.Context(), "lab", c2, nil), c2, 0)
	wantCode(t, err, codes.Unavailable, "")
	h2.assertRuntimeEmpty()
	if rec, ok := h2.audit.last(codes.KindRunFinished); !ok || rec.Code != string(codes.Unavailable) {
		t.Errorf("failed start record = %+v", rec)
	}
}

// TestRunAuditFailure: docs/03 D4: if run_started can't be written,
// nothing runs; a failed run_finished still returns the result.
func TestRunAuditFailure(t *testing.T) {
	h := newHarness(t, "", nil)
	h.audit.fail = func(r audit.Record) bool { return r.Kind == codes.KindRunStarted }
	c := parse(t, []string{"get", "--raw", "/raw/hello"}, nil, false)
	_, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 0)
	wantCode(t, err, codes.Unavailable, "")
	if len(h.api.childRequests()) != 0 {
		t.Fatal("kubectl ran without a run_started record")
	}
	h.assertRuntimeEmpty()

	h.audit.fail = func(r audit.Record) bool { return r.Kind == codes.KindRunFinished }
	res, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 0)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("run with a failed finish record: %v %+v", err, res)
	}
}

func TestRunStdinAndTruncation(t *testing.T) {
	h := newHarness(t, "", func(c *RunnerConfig) { c.Limits.MaxOutput = 100 })
	c := parse(t, []string{"create", "--raw", "/raw/post", "-f", "-"}, []byte(`{"kind":"ConfigMap"}`), false)
	res, err := h.runner.Run(grantFor(t.Context(), "lab", c, nil), c, 0)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run: %v %+v", err, res)
	}
	var posted bool
	for _, r := range h.api.childRequests() {
		if r.Path == "/raw/post" && r.Method == http.MethodPost && r.Body == `{"kind":"ConfigMap"}` {
			posted = true
		}
	}
	if !posted {
		t.Errorf("stdin didn't reach the target: %+v", h.api.childRequests())
	}

	big := parse(t, []string{"get", "--raw", "/raw/big"}, nil, false)
	res, err = h.runner.Run(grantFor(t.Context(), "lab", big, nil), big, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 100 || !res.StdoutTruncated || res.StderrTruncated {
		t.Errorf("stdout %d bytes, truncated %v/%v", len(res.Stdout), res.StdoutTruncated, res.StderrTruncated)
	}
	if fin, _ := h.audit.last(codes.KindRunFinished); fin.StdoutBytes != 4096 {
		t.Errorf("audited stdout bytes = %d, want 4096", fin.StdoutBytes)
	}
}

func TestNewRunnerValidation(t *testing.T) {
	dir := t.TempDir()
	ok := RunnerConfig{RuntimeDir: dir, Executable: "x", Audit: &recAudit{}}
	if _, err := NewRunner(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*RunnerConfig){
		"no audit":     func(c *RunnerConfig) { c.Audit = nil },
		"relative dir": func(c *RunnerConfig) { c.RuntimeDir = "run" },
		"missing dir":  func(c *RunnerConfig) { c.RuntimeDir = filepath.Join(dir, "nope") },
		"limits":       func(c *RunnerConfig) { c.Limits = Limits{DefaultTimeout: time.Hour, MaxTimeout: time.Minute} },
		"http server": func(c *RunnerConfig) {
			c.Targets = map[string]Target{"a": {Name: "a", Server: "http://x", CAFile: "c", TokenFile: "t"}}
		},
		"no token file": func(c *RunnerConfig) {
			c.Targets = map[string]Target{"a": {Name: "a", Server: "https://x", CAFile: "c"}}
		},
		"name mismatched": func(c *RunnerConfig) {
			c.Targets = map[string]Target{"a": {Name: "b", Server: "https://x", CAFile: "c", TokenFile: "t"}}
		},
	} {
		cfg := ok
		mod(&cfg)
		if _, err := NewRunner(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
