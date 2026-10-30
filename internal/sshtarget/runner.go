package sshtarget

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// Detail values on the errors the runner returns.
const (
	DetailDigestMismatch      = "digest_mismatch"
	DetailInteractiveMismatch = "interactive_mismatch"
	DetailUnknownTarget       = "unknown_target"
	DetailHostNotPinned       = "host_not_pinned"
	DetailHostKeyMismatch     = "host_key_mismatch"
	DetailUnreachable         = "target_unreachable"
	DetailAuthRefused         = "auth_refused"
	DetailSessionRefused      = "session_refused"
	DetailConnectionLost      = "connection_lost"
	DetailGrantEnded          = "grant_ended"
	DetailGrantExpired        = "grant_expired"
	DetailTimeout             = "run_timeout"
	DetailClientGone          = "client_gone"
)

// cutGrace is how long a cut waits after TERM before KILL (docs/07 D11);
// killGrace how long after KILL before the connection is closed.
const (
	cutGrace  = 2 * time.Second
	killGrace = time.Second
)

// DefaultTerm is the TERM of a session whose client sent none
// (docs/07 D9).
const DefaultTerm = "xterm-256color"

var termPattern = regexp.MustCompile(`^[a-z0-9.+-]{1,32}$`)

// Target is one SSH host (docs/07 §5.5).
type Target struct {
	Name     string
	Address  string
	Host     string
	HostKeys []ssh.PublicKey
	HostCAs  []ssh.PublicKey
}

// Limits bound runs (docs/04 D7, unchanged for SSH: docs/07 D13).
type Limits struct {
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MaxInteractive time.Duration
	MaxOutput      int64
}

// RunnerConfig configures a Runner.
type RunnerConfig struct {
	Targets        map[string]Target
	CA             *CA
	ConnectTimeout time.Duration
	Limits         Limits
	Audit          audit.Appender
	Logger         *slog.Logger
	// Now is the clock of host certificate checks; time.Now when nil.
	// Run deadlines use the real clock, as contexts do.
	Now func() time.Time
	// Dial replaces the TCP dialler (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Runner runs SSH requests covered by a Grant (docs/07 D9).
type Runner struct {
	targets        map[string]Target
	ca             *CA
	connectTimeout time.Duration
	limits         Limits
	audit          audit.Appender
	log            *slog.Logger
	now            func() time.Time
	dial           func(ctx context.Context, network, addr string) (net.Conn, error)
	cutGrace       time.Duration
	// afterStart, when set, runs between the command's start and the
	// handoff to wait. Tests use it to cut in that window.
	afterStart func(*conn)
}

// NewRunner validates cfg and returns a Runner.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Audit == nil {
		return nil, errors.New("sshtarget: no audit appender")
	}
	if cfg.CA == nil && len(cfg.Targets) > 0 {
		return nil, errors.New("sshtarget: no CA")
	}
	l := cfg.Limits
	if l.DefaultTimeout <= 0 || l.MaxTimeout < l.DefaultTimeout || l.MaxInteractive <= 0 || l.MaxOutput <= 0 {
		return nil, errors.New("sshtarget: invalid run limits")
	}
	for name, t := range cfg.Targets {
		if t.Name != name || t.Address == "" || t.Host == "" {
			return nil, fmt.Errorf("sshtarget: target %q is incomplete", name)
		}
	}
	r := &Runner{
		targets: cfg.Targets, ca: cfg.CA, connectTimeout: cfg.ConnectTimeout, limits: l,
		audit: cfg.Audit, log: cfg.Logger, now: cfg.Now, dial: cfg.Dial, cutGrace: cutGrace,
	}
	if r.connectTimeout <= 0 {
		r.connectTimeout = 10 * time.Second
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.dial == nil {
		d := &net.Dialer{}
		r.dial = d.DialContext
	}
	return r, nil
}

// checkGrant is the runner's own check that the Grant covers exactly this
// request, for this account (docs/07 D2, G2). The decision point already
// did it; a mismatch is a bug, and nothing is dialled.
func checkGrant(g *decision.Grant, req *Request) error {
	want := g.Digest()
	got := req.Digest(g.Target(), g.RunAs().User)
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return codes.WithDetail(codes.Internal, DetailDigestMismatch, "the request doesn't match what was approved")
	}
	if g.Interactive() != req.Interactive() {
		return codes.WithDetail(codes.Internal, DetailInteractiveMismatch, "the request doesn't match what was approved")
	}
	return nil
}

func record(kind string, g *decision.Grant, req *Request) audit.Record {
	a := req.Audit()
	return audit.Record{
		Kind: kind, Human: g.Human(), Agent: g.AgentKey(), ClientID: g.ClientID(),
		Targets: []string{g.Target()}, RunID: g.RunID(),
		ApprovalID: g.ApprovalID(), ElevationID: g.ElevationID(), CoveredBy: g.CoveredBy(),
		Request: &a, RunAs: &audit.RunAs{User: g.RunAs().User},
	}
}

// appendAudit writes rec with a context that outlives the Grant's, so a
// cut run's record is still written.
func (r *Runner) appendAudit(g *decision.Grant, rec audit.Record) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(g.Context()), 10*time.Second)
	defer cancel()
	return r.audit.Append(ctx, rec)
}

// refuse audits a refusal; a failed write changes nothing, the request
// is refused either way.
func (r *Runner) refuse(g *decision.Grant, req *Request, kind string, serial string, err error) error {
	rec := record(kind, g, req)
	rec.Decision = codes.Deny
	rec.Code = string(codes.Of(err))
	rec.Detail = codes.DetailOf(err)
	rec.CertSerial = serial
	if aerr := r.appendAudit(g, rec); aerr != nil {
		r.log.Error("audit write failed for a refused run", "run_id", g.RunID(), "kind", kind, "err", aerr)
	}
	return err
}

// runLimits is the context a run lives in: the Grant's, bounded by limit
// and, under an elevation, by its expiry (docs/04 D7, D8).
type runLimits struct {
	ctx        context.Context
	cancel     context.CancelFunc
	byNotAfter bool
	notAfter   time.Time
	clientGone atomic.Bool
	grant      context.Context
}

func limitsFor(g *decision.Grant, limit time.Duration) *runLimits {
	deadline := time.Now().Add(limit)
	byNotAfter := false
	if na := g.NotAfter(); !na.IsZero() && na.Before(deadline) {
		deadline, byNotAfter = na, true
	}
	ctx, cancel := context.WithDeadline(g.Context(), deadline)
	return &runLimits{ctx: ctx, cancel: cancel, byNotAfter: byNotAfter, notAfter: deadline, grant: g.Context()}
}

func (l *runLimits) cutDetail() string {
	switch {
	case errors.Is(context.Cause(l.grant), decision.ErrEndedByApprover):
		return decision.DetailEndedByApprover
	case l.byNotAfter && !time.Now().Before(l.notAfter):
		return DetailGrantExpired
	case l.grant.Err() != nil:
		return DetailGrantEnded
	case l.clientGone.Load():
		return DetailClientGone
	case l.byNotAfter:
		return DetailGrantExpired
	default:
		return DetailTimeout
	}
}

func cutMessage(detail string) string {
	switch detail {
	case decision.DetailEndedByApprover:
		return "the approver ended it"
	case DetailGrantEnded:
		return "what covered it ended"
	case DetailGrantExpired:
		return "the elevation expired"
	case DetailClientGone:
		return "the client went away"
	default:
		return "its time limit was reached"
	}
}

// conn is an authenticated connection with one session, ready for exec.
type conn struct {
	client  *ssh.Client
	session *ssh.Session
	serial  string
	// mu and running hand the cut over from the guard to wait: until the
	// command has started, the guard ends a run whose cover ended (a host
	// that stalls a session, pty or exec request can't hold the run past
	// its limit); from then on, wait does the full cut of D11.
	mu      sync.Mutex
	running bool
	guarded bool // the guard cut before the handoff; set under mu
	stop    func() bool
}

// guard is the cut before the command has started: TERM, in case the
// exec request is already on its way, then close. A cut while the exec
// or shell reply is awaited may follow a command that started, so the
// caller records it as a cut run (cutEarly), not as nothing ran.
func (c *conn) guard() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return
	}
	c.guarded = true
	if c.session != nil {
		_ = c.session.Signal(ssh.SIGTERM)
	}
	_ = c.client.Close()
}

// started hands the cut to wait. After it, the guard can't act, so
// cutEarly is settled: whether the guard already cut a command that may
// have started.
func (c *conn) started() {
	c.mu.Lock()
	c.running = true
	c.mu.Unlock()
	c.stop()
}

func (c *conn) cutEarly() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.guarded
}

func (c *conn) close() {
	if c.session != nil {
		_ = c.session.Close()
	}
	_ = c.client.Close()
}

// connect does every step before the command is sent (docs/07 D9):
// mint the certificate, audit run_started, dial, verify the host,
// authenticate, open the session. Every failure is a refusal, audited,
// and the command never reaches the host.
func (r *Runner) connect(l *runLimits, g *decision.Grant, req *Request) (*conn, error) {
	if l.ctx.Err() != nil {
		// Nothing has started, so this is a refusal, not a cut; it still
		// says why, e.g. End now (D17).
		d := l.cutDetail()
		return nil, r.refuse(g, req, codes.KindDecision, "", codes.WithDetail(codes.Expired, d, "the run was not started: %s", cutMessage(d)))
	}
	t, ok := r.targets[g.Target()]
	if !ok {
		return nil, r.refuse(g, req, codes.KindDependencyFailed, "", codes.WithDetail(codes.Unavailable, DetailUnknownTarget, "the target is not configured"))
	}
	if len(t.HostKeys) == 0 && len(t.HostCAs) == 0 {
		return nil, r.refuse(g, req, codes.KindDependencyFailed, "", codes.WithDetail(codes.Unavailable, DetailHostNotPinned,
			"the target's host keys are not configured yet"))
	}
	cert, err := r.ca.Mint(g.RunID(), g.Human(), g.Target(), req.Interactive())
	if err != nil {
		return nil, r.refuse(g, req, codes.KindDependencyFailed, "", err)
	}
	serial := strconv.FormatUint(cert.Serial, 10)

	// docs/03 D4: the start, with the certificate it was issued, is
	// recorded before anything reaches the host.
	start := record(codes.KindRunStarted, g, req)
	start.CertSerial = serial
	if err := r.appendAudit(g, start); err != nil {
		r.log.Error("audit write failed; run not started", "run_id", g.RunID(), "err", err)
		return nil, codes.Wrap(codes.Unavailable, err, "the audit log is unavailable")
	}
	fail := func(detail, msg string, err error) (*conn, error) {
		e := codes.WithDetail(codes.Unavailable, detail, "%s", msg)
		e.Err = err
		return nil, r.refuse(g, req, codes.KindDependencyFailed, serial, e)
	}

	dctx, dcancel := context.WithTimeout(l.ctx, r.connectTimeout)
	defer dcancel()
	nc, err := r.dial(dctx, "tcp", t.Address)
	if err != nil {
		return fail(DetailUnreachable, "the host could not be reached", err)
	}
	// The handshake has no context of its own: a deadline bounds it, and
	// the run's end closes the socket.
	_ = nc.SetDeadline(time.Now().Add(r.connectTimeout))
	stop := context.AfterFunc(dctx, func() { _ = nc.Close() })
	hv := newHostVerifier(t.Host, t.HostKeys, t.HostCAs, r.now)
	var hostRefused atomic.Bool
	cfg := &ssh.ClientConfig{
		User: g.RunAs().User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(cert.signer)},
		HostKeyCallback: func(h string, a net.Addr, k ssh.PublicKey) error {
			if err := hv.callback(h, a, k); err != nil {
				hostRefused.Store(true)
				return err
			}
			return nil
		},
		HostKeyAlgorithms: hv.algorithms(t.HostKeys),
		Timeout:           r.connectTimeout,
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, t.Address, cfg)
	if !stop() || err != nil {
		_ = nc.Close()
		switch {
		case hostRefused.Load():
			return fail(DetailHostKeyMismatch, "the host's key matches no pin and no host CA", err)
		case err != nil && isAuthError(err):
			return fail(DetailAuthRefused, "the host refused Nyyrikki's certificate", err)
		case l.ctx.Err() != nil:
			return nil, r.refuse(g, req, codes.KindRunCut, serial, codes.WithDetail(codes.Expired, l.cutDetail(), "the run was cut: %s", cutMessage(l.cutDetail())))
		default:
			return fail(DetailUnreachable, "the SSH handshake with the host failed", err)
		}
	}
	_ = nc.SetDeadline(time.Time{})
	c := &conn{client: ssh.NewClient(sc, chans, reqs), serial: serial}
	c.stop = context.AfterFunc(l.ctx, c.guard)
	s, err := c.client.NewSession()
	if err != nil {
		c.stop()
		_ = c.client.Close()
		if l.ctx.Err() != nil {
			return nil, r.cutBeforeStart(l, g, req, serial)
		}
		return fail(DetailSessionRefused, "the host refused a session", err)
	}
	c.mu.Lock()
	c.session = s
	c.mu.Unlock()
	return c, nil
}

// cutBeforeStart records a run whose cover ended before its command was
// sent: nothing ran.
func (r *Runner) cutBeforeStart(l *runLimits, g *decision.Grant, req *Request, serial string) error {
	d := l.cutDetail()
	return r.refuse(g, req, codes.KindRunCut, serial, codes.WithDetail(codes.Expired, d, "the run was cut: %s", cutMessage(d)))
}

func isAuthError(err error) bool {
	return bytes.Contains([]byte(err.Error()), []byte("unable to authenticate"))
}

// Run runs req, which g must cover, and returns the remote exit status
// and output (docs/07 D9, D10). It is bounded as kubectl runs are
// (docs/04 D7) and cut as D11 says when g's context ends. A cut run
// returns what it printed so far with a *codes.Error with codes.Expired.
// Any failure before the command is sent returns a nil Result: nothing
// ran. g is released on every path.
func (r *Runner) Run(g *decision.Grant, req *Request, timeout time.Duration) (*target.Result, error) {
	if g == nil || req == nil {
		return nil, codes.New(codes.Internal, "no grant or request")
	}
	defer g.Release()
	if err := checkGrant(g, req); err != nil {
		return nil, r.refuse(g, req, codes.KindDecision, "", err)
	}
	if req.Interactive() {
		return nil, r.refuse(g, req, codes.KindDecision, "", codes.WithDetail(codes.Internal, DetailInteractiveMismatch, "interactive runs attach through the stream endpoint"))
	}
	if timeout <= 0 {
		timeout = r.limits.DefaultTimeout
	}
	l := limitsFor(g, min(timeout, r.limits.MaxTimeout))
	defer l.cancel()
	c, err := r.connect(l, g, req)
	if err != nil {
		return nil, err
	}
	defer c.close()

	stdout := target.NewCapWriter(r.limits.MaxOutput)
	stderr := target.NewCapWriter(r.limits.MaxOutput)
	c.session.Stdin = bytes.NewReader(req.Stdin())
	c.session.Stdout, c.session.Stderr = stdout, stderr
	if err := c.session.Start(req.Command()); err != nil {
		if c.cutEarly() {
			return &target.Result{ExitCode: -1}, r.finish(g, req, c, l, true, err, -1, "", 0, 0)
		}
		return nil, r.finishFail(l, g, req, c, DetailSessionRefused, "the host refused the command", err)
	}
	if r.afterStart != nil {
		r.afterStart(c)
	}
	c.started()
	cut, werr := r.wait(l, c)
	res := &target.Result{
		Stdout: stdout.Bytes(), Stderr: stderr.Bytes(),
		StdoutTruncated: stdout.Truncated(), StderrTruncated: stderr.Truncated(),
	}
	res.ExitCode, res.Detail = exitOf(werr)
	return res, r.finish(g, req, c, l, cut, werr, res.ExitCode, res.Detail, stdout.N(), stderr.N())
}

// RunInteractive runs req on a pseudo-terminal bridged to term (docs/07
// D9, docs/04 D12): a login shell when req has no command. It is bounded
// by MaxInteractive and, under an elevation, by its expiry, and cut as
// Run is. g is released on every path.
func (r *Runner) RunInteractive(g *decision.Grant, req *Request, term target.Terminal) (int, error) {
	if g == nil || req == nil || term == nil {
		return -1, codes.New(codes.Internal, "no grant, request or terminal")
	}
	defer g.Release()
	if err := checkGrant(g, req); err != nil {
		return -1, r.refuse(g, req, codes.KindDecision, "", err)
	}
	if !req.Interactive() {
		return -1, r.refuse(g, req, codes.KindDecision, "", codes.WithDetail(codes.Internal, DetailInteractiveMismatch, "not an interactive request"))
	}
	l := limitsFor(g, r.limits.MaxInteractive)
	defer l.cancel()
	c, err := r.connect(l, g, req)
	if err != nil {
		return -1, err
	}
	defer c.close()

	size := target.Size{Cols: 80, Rows: 24}
	select {
	case s := <-term.Resizes():
		if s.Cols > 0 && s.Rows > 0 {
			size = s
		}
	default:
	}
	tname := term.Term()
	if !termPattern.MatchString(tname) {
		tname = DefaultTerm
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := c.session.RequestPty(tname, int(size.Rows), int(size.Cols), modes); err != nil {
		return -1, r.finishFail(l, g, req, c, DetailSessionRefused, "the host refused a terminal", err)
	}
	stdin, err := c.session.StdinPipe()
	if err != nil {
		return -1, r.finishFail(l, g, req, c, DetailSessionRefused, "the host refused a terminal", err)
	}
	out := &countWriter{w: term}
	c.session.Stdout, c.session.Stderr = out, out
	if req.Command() == "" {
		err = c.session.Shell()
	} else {
		err = c.session.Start(req.Command())
	}
	if err != nil {
		if c.cutEarly() {
			return -1, r.finish(g, req, c, l, true, err, -1, "", 0, 0)
		}
		return -1, r.finishFail(l, g, req, c, DetailSessionRefused, "the host refused the session", err)
	}
	c.started()
	go func() {
		_, _ = io.Copy(stdin, term)
		l.clientGone.Store(true)
		l.cancel()
	}()
	go func() {
		for {
			select {
			case <-l.ctx.Done():
				return
			case s, ok := <-term.Resizes():
				if !ok {
					return
				}
				if s.Cols > 0 && s.Rows > 0 {
					_ = c.session.WindowChange(int(s.Rows), int(s.Cols))
				}
			}
		}
	}()
	cut, werr := r.wait(l, c)
	code, detail := exitOf(werr)
	return code, r.finish(g, req, c, l, cut, werr, code, detail, out.n.Load(), 0)
}

// wait waits for the command, and cuts it when l's context ends
// (docs/07 D11): TERM, up to cutGrace for the session to end, KILL, and
// the connection closed. Closing alone would leave a command without a
// PTY running (M10); the host's session kill finishes what the signals
// can't reach.
func (r *Runner) wait(l *runLimits, c *conn) (cut bool, err error) {
	done := make(chan error, 1)
	go func() { done <- c.session.Wait() }()
	if c.cutEarly() {
		// The guard sent TERM and closed the connection between the
		// command's start and the handoff: a cut, though nothing more
		// can reach the host (D11's no-session-kill case).
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
		}
		return true, err
	}
	select {
	case err = <-done:
		return false, err
	case <-l.ctx.Done():
	}
	_ = c.session.Signal(ssh.SIGTERM)
	select {
	case err = <-done:
		c.close()
		return true, err
	case <-time.After(r.cutGrace):
	}
	_ = c.session.Signal(ssh.SIGKILL)
	// A moment for KILL to arrive and the exit to come back, then close
	// whatever is left.
	select {
	case err = <-done:
		c.close()
		return true, err
	case <-time.After(killGrace):
	}
	c.close()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
	}
	return true, err
}

var signalName = regexp.MustCompile(`^[A-Z0-9]{1,16}$`)

// exitOf maps Wait's error to the result's exit code (docs/07 D9): the
// remote status, or 128 plus the signal's number with its name in
// detail; -1 when the host sent neither.
func exitOf(err error) (int, string) {
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return 0, ""
	case errors.As(err, &ee):
		if sig := ee.Signal(); sig != "" {
			if !signalName.MatchString(sig) {
				sig = "unknown"
			}
			return ee.ExitStatus(), "signal: " + sig
		}
		return ee.ExitStatus(), ""
	default:
		return -1, ""
	}
}

// finish records a run's end and returns the error the caller returns.
// The command already ran, so a failed write is logged and the result
// still returned (docs/03 D4).
func (r *Runner) finish(g *decision.Grant, req *Request, c *conn, l *runLimits, cut bool, werr error, exit int, detail string, out, errOut int64) error {
	rec := record(codes.KindRunFinished, g, req)
	rec.CertSerial = c.serial
	rec.ExitCode = &exit
	rec.StdoutBytes, rec.StderrBytes = out, errOut
	rec.Detail = detail
	var ret error
	switch {
	case cut:
		d := l.cutDetail()
		rec.Kind, rec.Code, rec.Detail = codes.KindRunCut, string(codes.Expired), d
		ret = codes.WithDetail(codes.Expired, d, "the run was cut: %s", cutMessage(d))
	case exit == -1 && werr != nil:
		rec.Code, rec.Detail = string(codes.Unavailable), DetailConnectionLost
		ret = codes.WithDetail(codes.Unavailable, DetailConnectionLost, "the connection to the host ended before the command reported its exit")
	}
	if err := r.appendAudit(g, rec); err != nil {
		r.log.Error("audit write failed for a finished run", "run_id", g.RunID(), "err", err)
	}
	return ret
}

// finishFail records a session that was refused after it opened: nothing
// ran. If the run's cover ended meanwhile (the guard closed the client),
// that is the reason.
func (r *Runner) finishFail(l *runLimits, g *decision.Grant, req *Request, c *conn, detail, msg string, err error) error {
	if l.ctx.Err() != nil {
		return r.cutBeforeStart(l, g, req, c.serial)
	}
	e := codes.WithDetail(codes.Unavailable, detail, "%s", msg)
	e.Err = err
	return r.refuse(g, req, codes.KindDependencyFailed, c.serial, e)
}

// countWriter counts what it passes on.
type countWriter struct {
	w io.Writer
	n atomic.Int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}
