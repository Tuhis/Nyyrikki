package stream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
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

	"golang.org/x/term"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/client/attach"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
	"github.com/Tuhis/Nyyrikki/internal/kubectl"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/runner"
	"github.com/Tuhis/Nyyrikki/internal/stream/protocol"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// Built from parts so the secret scan, which matches real tickets, stays quiet.
const ticket = "nyst" + "_test-ticket-0123456789abcdefghijklmnopqrstuvwx"

// TestMain lets the test binary act as an interactive child for the end
// to end test, chosen by the name it is started under.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "echo-tty" {
		os.Exit(echoTTY())
	}
	os.Exit(m.Run())
}

func echoTTY() int {
	if !term.IsTerminal(0) {
		return 2
	}
	fmt.Print("READY\r\n")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "size":
			w, h, _ := term.GetSize(0)
			fmt.Printf("SIZE %dx%d\r\n", w, h)
		case strings.HasPrefix(line, "exit "):
			var n int
			fmt.Sscanf(line, "exit %d", &n)
			return n
		default:
			fmt.Printf("got:%s\r\n", line)
		}
	}
	return 0
}

var principal = authn.NewPrincipalForTest(authn.Principal{
	Human: "owner", Subject: "sub-1", AgentKey: "agent-key", ClientID: "nyyrikki-cli",
}, "raw-access-token")

func interactiveRequest(t *testing.T) *request.Canonical {
	t.Helper()
	c, err := request.Parse([]string{"exec", "-it", "web", "--", "sh"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func grantFor(ctx context.Context, c *request.Canonical, mod func(*decisiontest.Spec)) *decision.Grant {
	s := decisiontest.Spec{
		RunID: "run_s", Target: "lab", RunAs: approval.Identity{User: "owner@example.com"},
		Digest: request.Digest("lab", c), CoveredBy: codes.CoveredOneOff, ApprovalID: "apr_s",
		Interactive: true, Human: "owner", AgentKey: "agent-key", ClientID: "nyyrikki-cli",
	}
	if mod != nil {
		mod(&s)
	}
	return decisiontest.Grant(ctx, s)
}

// fakeTickets redeems one ticket once, for one agent key.
type fakeTickets struct {
	mu      sync.Mutex
	grant   *decision.Grant
	req     *request.Canonical
	used    bool
	redeems int
	started int
	ended   int
}

func (f *fakeTickets) Redeem(_ context.Context, tk string, p *authn.Principal) (*decision.Grant, target.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redeems++
	if tk != ticket || f.used || p.AgentKey != "agent-key" {
		return nil, nil, codes.New(codes.Denied, "no such ticket")
	}
	f.used = true
	return f.grant, f.req, nil
}

func (f *fakeTickets) SessionStarted(*decision.Grant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started++
}

func (f *fakeTickets) SessionEnded(*decision.Grant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ended++
}

func (f *fakeTickets) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.redeems
}

type fakeIntro struct{ err error }

func (f fakeIntro) Introspect(context.Context, *authn.Principal) error { return f.err }

// echoRunner is a fake Runner: it echoes input as "echo:<bytes>", reports
// resizes, exits with N on "exit N", and is cut when the grant ends.
type echoRunner struct{ called chan struct{} }

func (e *echoRunner) RunInteractive(g *decision.Grant, c target.Request, t target.Terminal) (int, error) {
	defer g.Release()
	if e.called != nil {
		close(e.called)
	}
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(t)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	fmt.Fprint(t, "READY\n")
	for {
		select {
		case <-g.Context().Done():
			return -1, codes.WithDetail(codes.Expired, kubectl.DetailGrantEnded, "the run was cut: what covered it ended")
		case s := <-t.Resizes():
			fmt.Fprintf(t, "resize:%dx%d\n", s.Cols, s.Rows)
		case l, ok := <-lines:
			if !ok {
				return -1, codes.WithDetail(codes.Expired, kubectl.DetailClientGone, "client gone")
			}
			var n int
			if _, err := fmt.Sscanf(l, "exit %d", &n); err == nil {
				return n, nil
			}
			fmt.Fprintf(t, "echo:%s\n", l)
		}
	}
}

type recAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail bool
}

func (a *recAudit) Append(_ context.Context, r audit.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("audit down")
	}
	a.recs = append(a.recs, r)
	return nil
}

func (a *recAudit) all() []audit.Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Record(nil), a.recs...)
}

type env struct {
	srv     *httptest.Server
	tickets *fakeTickets
	audit   *recAudit
	logs    *bytes.Buffer
	logMu   *sync.Mutex
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// newEnv serves the handler behind a stand-in for the authentication
// middleware, which adds the principal unless withPrincipal is false.
func newEnv(t *testing.T, tickets *fakeTickets, r Runner, intro authn.Introspector, withPrincipal bool) *env {
	t.Helper()
	e := &env{tickets: tickets, audit: &recAudit{}, logs: &bytes.Buffer{}, logMu: &sync.Mutex{}}
	logger := slog.New(slog.NewTextHandler(lockedWriter{e.logMu, e.logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(tickets, r, intro, e.audit, logger)
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if withPrincipal {
			req = req.WithContext(authn.WithPrincipal(req.Context(), principal))
		}
		h.ServeHTTP(w, req)
	}))
	t.Cleanup(e.srv.Close)
	t.Cleanup(func() {
		e.logMu.Lock()
		logs := e.logs.String()
		e.logMu.Unlock()
		if strings.Contains(logs, ticket) {
			t.Errorf("a log line holds the ticket: %s", logs)
		}
		b, _ := json.Marshal(e.audit.all())
		if strings.Contains(string(b), ticket) || strings.Contains(string(b), "raw-access-token") {
			t.Errorf("an audit record holds a secret: %s", b)
		}
	})
	return e
}

func (e *env) url() string { return "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/stream" }

func get(t *testing.T, e *env, withTicket bool) (int, protocol.Error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/stream", nil)
	if withTicket {
		req.Header.Set(protocol.TicketHeader, ticket)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Error protocol.Error `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Error
}

// TestStreamRefusals covers docs/02 G9's refusal half: /stream without a
// principal, with a dead session, without a ticket or with a bad one.
func TestStreamRefusals(t *testing.T) {
	c := interactiveRequest(t)
	t.Run("no principal", func(t *testing.T) {
		e := newEnv(t, &fakeTickets{grant: grantFor(t.Context(), c, nil), req: c}, &echoRunner{}, fakeIntro{}, false)
		if st, er := get(t, e, true); st != http.StatusUnauthorized || er.Code != string(codes.Unauthenticated) {
			t.Fatalf("got %d %+v", st, er)
		}
		if e.tickets.count() != 0 {
			t.Error("ticket redeemed without a principal")
		}
	})
	t.Run("introspection fails", func(t *testing.T) {
		for _, ie := range []error{errors.New("keycloak down"), codes.New(codes.SessionInactive, "inactive")} {
			e := newEnv(t, &fakeTickets{grant: grantFor(t.Context(), c, nil), req: c}, &echoRunner{}, fakeIntro{err: ie}, true)
			st, er := get(t, e, true)
			want := codes.IntrospectionFailed
			if codes.Of(ie) == codes.SessionInactive {
				want = codes.SessionInactive
			}
			if st != http.StatusForbidden || er.Code != string(want) {
				t.Fatalf("got %d %+v, want 403 %s", st, er, want)
			}
			if e.tickets.count() != 0 {
				t.Error("ticket redeemed before introspection passed")
			}
		}
	})
	t.Run("no ticket", func(t *testing.T) {
		e := newEnv(t, &fakeTickets{grant: grantFor(t.Context(), c, nil), req: c}, &echoRunner{}, fakeIntro{}, true)
		if st, er := get(t, e, false); st != http.StatusBadRequest || er.Code != string(codes.InvalidRequest) {
			t.Fatalf("got %d %+v", st, er)
		}
	})
	t.Run("bad and reused ticket", func(t *testing.T) {
		g := grantFor(t.Context(), c, nil)
		e := newEnv(t, &fakeTickets{grant: g, req: c, used: true}, &echoRunner{}, fakeIntro{}, true)
		st, er := get(t, e, true)
		if st != http.StatusForbidden || er.Code != string(codes.Denied) || strings.Contains(er.Message, ticket) {
			t.Fatalf("got %d %+v", st, er)
		}
		_, err := attach.Attach(t.Context(), e.url(), "nyst_wrong", nil, strings.NewReader(""), io.Discard, nil)
		if codes.Of(err) != codes.Denied {
			t.Fatalf("Attach with a bad ticket = %v", err)
		}
	})
	t.Run("grant for another agent", func(t *testing.T) {
		g := grantFor(t.Context(), c, func(s *decisiontest.Spec) { s.AgentKey = "someone-else" })
		e := newEnv(t, &fakeTickets{grant: g, req: c}, &echoRunner{}, fakeIntro{}, true)
		if st, _ := get(t, e, true); st != http.StatusForbidden {
			t.Fatalf("got %d", st)
		}
		if g.Context().Err() == nil {
			t.Error("refused grant not released")
		}
	})
	t.Run("not a GET", func(t *testing.T) {
		e := newEnv(t, &fakeTickets{}, &echoRunner{}, fakeIntro{}, true)
		resp, err := http.Post(e.srv.URL+"/stream", "text/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})
}

// output is a thread-safe buffer the attach client writes to.
type output struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(p)
}

func (o *output) waitFor(t *testing.T, s string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		o.mu.Lock()
		ok := strings.Contains(o.b.String(), s)
		o.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	t.Fatalf("output never showed %q; got %q", s, o.b.String())
}

type attachResult struct {
	code int
	err  error
}

func startAttach(t *testing.T, e *env, in io.Reader, out io.Writer, resizes chan attach.Size) <-chan attachResult {
	done := make(chan attachResult, 1)
	go func() {
		code, err := attach.Attach(t.Context(), e.url(), ticket, http.Header{"X-Test": {"1"}}, in, out, resizes)
		done <- attachResult{code, err}
	}()
	return done
}

func wait(t *testing.T, done <-chan attachResult) attachResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("Attach didn't return")
		return attachResult{}
	}
}

// TestStreamAttachRoundTrip covers docs/02 G9's working half: a ticket
// attaches once, bytes and resizes go both ways, and the exit status comes
// back; the same ticket can't attach again.
func TestStreamAttachRoundTrip(t *testing.T) {
	c := interactiveRequest(t)
	e := newEnv(t, &fakeTickets{grant: grantFor(t.Context(), c, nil), req: c}, &echoRunner{}, fakeIntro{}, true)
	inR, inW := io.Pipe()
	defer inW.Close()
	out := &output{}
	resizes := make(chan attach.Size, 1)
	done := startAttach(t, e, inR, out, resizes)

	out.waitFor(t, "READY")
	io.WriteString(inW, "hello\n")
	out.waitFor(t, "echo:hello")
	resizes <- attach.Size{Cols: 132, Rows: 43}
	out.waitFor(t, "resize:132x43")
	io.WriteString(inW, "exit 7\n")
	r := wait(t, done)
	if r.err != nil || r.code != 7 {
		t.Fatalf("Attach = %d, %v; want 7", r.code, r.err)
	}
	recs := e.audit.all()
	if len(recs) != 1 || recs[0].Kind != codes.KindStreamAttached || recs[0].RunID != "run_s" || recs[0].Agent != "agent-key" {
		t.Errorf("audit = %+v", recs)
	}

	// Once only.
	_, err := attach.Attach(t.Context(), e.url(), ticket, nil, strings.NewReader(""), io.Discard, nil)
	if codes.Of(err) != codes.Denied {
		t.Fatalf("second attach = %v, want denied", err)
	}
}

// TestStreamCutAtGrantEnd covers docs/04 G8's cut: when the grant ends,
// the client gets the error and the stream closes.
func TestStreamCutAtGrantEnd(t *testing.T) {
	c := interactiveRequest(t)
	ctx, cancel := context.WithCancel(t.Context())
	e := newEnv(t, &fakeTickets{grant: grantFor(ctx, c, nil), req: c}, &echoRunner{}, fakeIntro{}, true)
	inR, inW := io.Pipe()
	defer inW.Close()
	out := &output{}
	done := startAttach(t, e, inR, out, nil)
	out.waitFor(t, "READY")
	cancel()
	r := wait(t, done)
	var ce *codes.Error
	if !errors.As(r.err, &ce) || ce.Code != codes.Expired || !strings.Contains(ce.Message, "cut") {
		t.Fatalf("Attach = %d, %v; want expired", r.code, r.err)
	}
}

func TestStreamAuditFailureDoesNotRun(t *testing.T) {
	c := interactiveRequest(t)
	runner := &echoRunner{called: make(chan struct{})}
	g := grantFor(t.Context(), c, nil)
	e := newEnv(t, &fakeTickets{grant: g, req: c}, runner, fakeIntro{}, true)
	e.audit.fail = true
	_, err := attach.Attach(t.Context(), e.url(), ticket, nil, strings.NewReader(""), io.Discard, nil)
	if codes.Of(err) != codes.Unavailable {
		t.Fatalf("Attach = %v, want unavailable", err)
	}
	select {
	case <-runner.called:
		t.Fatal("the run started without a stream_attached record")
	default:
	}
	if g.Context().Err() == nil {
		t.Error("grant not released")
	}
}

// TestStreamEndToEnd runs a real kubectl.Runner (with the test binary as
// an echoing child on a pty) behind the handler, through attach.
func TestStreamEndToEnd(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"major":"1","minor":"35"}`)
	}))
	defer api.Close()
	dir := t.TempDir()
	ca, tok := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0o600)
	os.WriteFile(tok, []byte("tok"), 0o600)
	self, _ := os.Executable()
	exe := filepath.Join(dir, "echo-tty")
	if err := os.Symlink(self, exe); err != nil {
		t.Fatal(err)
	}
	kr, err := kubectl.NewRunner(kubectl.RunnerConfig{
		RuntimeDir: t.TempDir(), Executable: exe, Audit: &recAudit{},
		Targets: map[string]kubectl.Target{"lab": {Name: "lab", Server: api.URL, CAFile: ca, TokenFile: tok}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := interactiveRequest(t)
	e := newEnv(t, &fakeTickets{grant: grantFor(t.Context(), c, nil), req: c}, runner.Runners{Kubernetes: kr}, fakeIntro{}, true)
	inR, inW := io.Pipe()
	defer inW.Close()
	out := &output{}
	resizes := make(chan attach.Size, 1)
	resizes <- attach.Size{Cols: 90, Rows: 30}
	done := startAttach(t, e, inR, out, resizes)
	out.waitFor(t, "READY")
	io.WriteString(inW, "size\n")
	out.waitFor(t, "SIZE 90x30")
	io.WriteString(inW, "ping\n")
	out.waitFor(t, "got:ping")
	io.WriteString(inW, "exit 4\n")
	if r := wait(t, done); r.err != nil || r.code != 4 {
		t.Fatalf("Attach = %d, %v; want 4", r.code, r.err)
	}
}
