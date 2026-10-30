package sshtarget

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// testCA is a user CA written to a key file, as the mounted Secret is.
type testCA struct {
	signer ssh.Signer
	file   string
	pem    []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "nyyrikki-user-ca")
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(block)
	file := filepath.Join(t.TempDir(), "user-ca")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	return &testCA{signer: s, file: file, pem: b}
}

// event is one request the fake host received on a session.
type event struct {
	Type    string
	Payload []byte
	At      time.Time
}

// fakeHost is an in-process SSH server standing in for sshd: it accepts
// only certificates from its user CA for the account's principal, and
// records every session request (docs/07 G4, G5, G6).
type fakeHost struct {
	t         *testing.T
	ln        net.Listener
	hostKey   ssh.Signer
	userCA    ssh.PublicKey
	account   string
	principal string
	now       func() time.Time
	// hostCert, if set, is presented instead of the plain host key.
	hostCert *ssh.Certificate

	mu        sync.Mutex
	events    []event
	certs     []*ssh.Certificate
	logins    int
	conns     []net.Conn
	closed    chan struct{}
	noSession bool
}

func newFakeHost(t *testing.T, ca ssh.PublicKey) *fakeHost {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{t: t, ln: ln, hostKey: hk, userCA: ca, account: "ny-owner",
		principal: Principal("owner", "db-1"), now: time.Now, closed: make(chan struct{})}
	t.Cleanup(func() { ln.Close() })
	return h
}

// start serves; the test's changes to h are done by then.
func (h *fakeHost) start() { go h.serve() }

func (h *fakeHost) loginCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.logins
}

func (h *fakeHost) addr() string { return h.ln.Addr().String() }

func (h *fakeHost) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return nil, fmt.Errorf("plain keys are refused")
			}
			chk := &ssh.CertChecker{
				IsUserAuthority:          func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), h.userCA.Marshal()) },
				Clock:                    h.now,
				SupportedCriticalOptions: []string{"source-address"},
			}
			if md.User() != h.account {
				return nil, fmt.Errorf("wrong account")
			}
			if _, err := chk.Authenticate(principalMeta{md, h.principal}, cert); err != nil {
				return nil, err
			}
			h.mu.Lock()
			h.certs = append(h.certs, cert)
			h.logins++
			h.mu.Unlock()
			return &ssh.Permissions{}, nil
		},
	}
	if h.hostCert != nil {
		cs, err := ssh.NewCertSigner(h.hostCert, h.hostKey)
		if err != nil {
			h.t.Fatal(err)
		}
		cfg.AddHostKey(cs)
	} else {
		cfg.AddHostKey(h.hostKey)
	}
	return cfg
}

// principalMeta makes CertChecker compare the certificate's principals
// with the principals-file entry instead of the user name (docs/07 D4).
type principalMeta struct {
	ssh.ConnMetadata
	principal string
}

func (p principalMeta) User() string { return p.principal }

func (h *fakeHost) serve() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		h.conns = append(h.conns, c)
		h.mu.Unlock()
		go h.handle(c)
	}
}

func (h *fakeHost) handle(nc net.Conn) {
	defer nc.Close()
	_, chans, reqs, err := ssh.NewServerConn(nc, h.config())
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" || h.noSession {
			nch.Reject(ssh.Prohibited, "no")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go h.session(ch, creqs)
	}
}

func (h *fakeHost) record(typ string, payload []byte) {
	h.mu.Lock()
	h.events = append(h.events, event{Type: typ, Payload: payload, At: time.Now()})
	h.mu.Unlock()
}

func (h *fakeHost) eventsOf(typ string) []event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []event
	for _, e := range h.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func (h *fakeHost) allEvents() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, e := range h.events {
		out = append(out, e.Type)
	}
	return out
}

func sshString(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(b)
	if int(n) > len(b)-4 {
		return ""
	}
	return string(b[4 : 4+n])
}

func exitStatus(ch ssh.Channel, code uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], code)
	ch.SendRequest("exit-status", false, b[:])
}

func exitSignal(ch ssh.Channel, sig string) {
	ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
		Signal     string
		CoreDumped bool
		Error      string
		Lang       string
	}{Signal: sig}))
}

// session runs a scripted command:
//
//	echo X        prints X and exits 0
//	fail          prints to stderr and exits 3
//	cat           copies stdin to stdout
//	sleep         waits for a signal; TERM ends it with exit-signal TERM
//	ignore-term   waits for a signal; only KILL ends it
//	die           ends with exit-signal SEGV
//	noexit        closes without an exit status
//	stall-reply   is never answered: the exec reply doesn't come
//	(shell)       echoes lines back, "exit N" ends with N
func (h *fakeHost) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	signals := make(chan string, 8)
	started := make(chan string, 1)
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return
			}
			h.record(req.Type, req.Payload)
			switch req.Type {
			case "pty-req", "window-change":
				req.Reply(true, nil)
			case "exec":
				if sshString(req.Payload) == "stall-reply" {
					continue
				}
				req.Reply(true, nil)
				started <- sshString(req.Payload)
				go h.run(ch, sshString(req.Payload), signals)
			case "shell":
				req.Reply(true, nil)
				go h.run(ch, "(shell)", signals)
			case "signal":
				signals <- sshString(req.Payload)
			default:
				req.Reply(false, nil)
			}
		case <-h.closed:
			return
		}
	}
}

func (h *fakeHost) run(ch ssh.Channel, cmd string, signals <-chan string) {
	switch {
	case strings.HasPrefix(cmd, "echo "):
		io.WriteString(ch, strings.TrimPrefix(cmd, "echo ")+"\n")
		exitStatus(ch, 0)
	case cmd == "fail":
		io.WriteString(ch.Stderr(), "it failed\n")
		exitStatus(ch, 3)
	case cmd == "cat":
		io.Copy(ch, ch)
		exitStatus(ch, 0)
	case cmd == "sleep", cmd == "ignore-term":
		io.WriteString(ch, "started\n")
		for sig := range signals {
			h.record("got-"+sig, nil)
			if sig == "KILL" || (sig == "TERM" && cmd == "sleep") {
				exitSignal(ch, sig)
				break
			}
		}
	case cmd == "die":
		exitSignal(ch, "SEGV")
	case cmd == "noexit":
	case cmd == "(shell)":
		buf := make([]byte, 1024)
		io.WriteString(ch, "READY\r\n")
		var line []byte
		for {
			n, err := ch.Read(buf)
			for _, c := range buf[:n] {
				if c == '\n' || c == '\r' {
					l := string(line)
					line = line[:0]
					var code uint32
					if _, e := fmt.Sscanf(l, "exit %d", &code); e == nil {
						exitStatus(ch, code)
						ch.Close()
						return
					}
					io.WriteString(ch, "got:"+l+"\r\n")
					continue
				}
				line = append(line, c)
			}
			if err != nil {
				return
			}
		}
	default:
		io.WriteString(ch.Stderr(), "unknown command\n")
		exitStatus(ch, 127)
	}
	ch.Close()
}

// recAudit records audit records, and can be made to fail.
type recAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail func(audit.Record) bool
}

func (a *recAudit) Append(_ context.Context, r audit.Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil && a.fail(r) {
		return fmt.Errorf("audit down")
	}
	a.recs = append(a.recs, r)
	return nil
}

func (a *recAudit) kinds() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, r := range a.recs {
		out = append(out, r.Kind)
	}
	return out
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

func (a *recAudit) json() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(a.recs)
	return string(b)
}

// harness is a Runner against a fakeHost.
type harness struct {
	ca     *testCA
	host   *fakeHost
	audit  *recAudit
	runner *Runner
	logs   *bytes.Buffer
}

func newHarness(t *testing.T, mod func(*RunnerConfig, *fakeHost)) *harness {
	t.Helper()
	ca := newTestCA(t)
	host := newFakeHost(t, ca.signer.PublicKey())
	a := &recAudit{}
	cfg := RunnerConfig{
		Targets: map[string]Target{"db-1": {Name: "db-1", Address: host.addr(), Host: "db-1.example.com",
			HostKeys: []ssh.PublicKey{host.hostKey.PublicKey()}}},
		CA:             NewCA(ca.file, []ssh.PublicKey{ca.signer.PublicKey()}, []string{"127.0.0.1/32"}, nil),
		ConnectTimeout: 5 * time.Second,
		Limits:         Limits{DefaultTimeout: 10 * time.Second, MaxTimeout: time.Minute, MaxInteractive: time.Minute, MaxOutput: 1 << 20},
		Audit:          a,
	}
	if mod != nil {
		mod(&cfg, host)
	}
	host.start()
	logs := &bytes.Buffer{}
	cfg.Logger = newTestLogger(logs)
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.cutGrace = 300 * time.Millisecond
	return &harness{ca: ca, host: host, audit: a, runner: r, logs: logs}
}

func build(t *testing.T, args []string, stdin []byte, interactive bool) *Request {
	t.Helper()
	r, err := Build(args, stdin, interactive)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// grantFor makes the Grant the decision point would make for req on
// db-1 as ny-owner.
func grantFor(ctx context.Context, req *Request, mod func(*decisiontest.Spec)) *decision.Grant {
	s := decisiontest.Spec{
		RunID: "run_test", Target: "db-1", Human: "owner", AgentKey: "agent-key", ClientID: "cli",
		CoveredBy: codes.CoveredOneOff, ApprovalID: "apr_test", Interactive: req.Interactive(),
	}
	s.RunAs.User = "ny-owner"
	s.Digest = req.Digest("db-1", "ny-owner")
	if mod != nil {
		mod(&s)
	}
	return decisiontest.Grant(ctx, s)
}

func wantCode(t *testing.T, err error, code codes.Code, detail string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; want %s/%s", code, detail)
	}
	if codes.Of(err) != code || codes.DetailOf(err) != detail {
		t.Fatalf("error %v (%s/%s); want %s/%s", err, codes.Of(err), codes.DetailOf(err), code, detail)
	}
}

// fakeTerm is a target.Terminal driven by the test.
type fakeTerm struct {
	in      *io.PipeReader
	inW     *io.PipeWriter
	mu      sync.Mutex
	out     bytes.Buffer
	resizes chan target.Size
	term    string
}

func newFakeTerm() *fakeTerm {
	r, w := io.Pipe()
	return &fakeTerm{in: r, inW: w, resizes: make(chan target.Size, 4)}
}

func (f *fakeTerm) Read(p []byte) (int, error) { return f.in.Read(p) }
func (f *fakeTerm) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.Write(p)
}
func (f *fakeTerm) Resizes() <-chan target.Size { return f.resizes }
func (f *fakeTerm) Term() string                { return f.term }
func (f *fakeTerm) close()                      { f.in.CloseWithError(io.ErrClosedPipe) }

func (f *fakeTerm) waitFor(t *testing.T, s string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		ok := strings.Contains(f.out.String(), s)
		f.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("terminal never showed %q", s)
}

func targetSize(cols, rows uint16) target.Size { return target.Size{Cols: cols, Rows: rows} }
