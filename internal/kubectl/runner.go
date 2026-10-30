// Package kubectl runs canonical kubectl requests against a target, as the
// human a Grant names, with Nyyrikki's credential (docs/04 D6–D12).
//
// Every run is a child process: nyyrikkid re-executes itself as
// "nyyrikkid kubectl-child <canonical argv…>" (ChildMain), with a fresh
// kubeconfig that holds only paths and the human's identity, and an
// environment that inherits nothing. The child's process group is killed
// when the Grant's context ends or the run's limit is reached.
package kubectl

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// ChildArg is the first argument that makes nyyrikkid run ChildMain.
const ChildArg = "kubectl-child"

// DefaultServiceAccountDir is where a pod's projected ServiceAccount
// credentials are mounted (docs/04 D9, in_cluster targets).
const DefaultServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Detail values on the errors the runner returns.
const (
	DetailDigestMismatch      = "digest_mismatch"
	DetailInteractiveMismatch = "interactive_mismatch"
	DetailGrantEnded          = "grant_ended"
	DetailGrantExpired        = "grant_expired"
	DetailTimeout             = "run_timeout"
	DetailClientGone          = "client_gone"
	DetailTargetVersion       = "target_version"
	DetailTargetUnreachable   = "target_unreachable"
	DetailUnknownTarget       = "unknown_target"
	DetailNoIdentity          = "no_identity"
	DetailSetup               = "setup_failed"
	DetailAudit               = "audit_failed"
)

// Target is one Kubernetes target (docs/04 D9): in-cluster, or a server
// with a CA file and a token file from a mounted Secret.
type Target struct {
	Name      string
	InCluster bool
	Server    string
	CAFile    string
	TokenFile string
}

// Limits bound runs (docs/04 D7).
type Limits struct {
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MaxInteractive time.Duration
	MaxOutput      int64
}

// Defaults of docs/04 §5.5.
const (
	DefaultTimeout        = 60 * time.Second
	DefaultMaxTimeout     = 10 * time.Minute
	DefaultMaxInteractive = 30 * time.Minute
	DefaultMaxOutput      = 1 << 20
)

// RunnerConfig configures a Runner.
type RunnerConfig struct {
	// RuntimeDir holds the per-run directories (an in-memory emptyDir).
	RuntimeDir string
	// Executable is the nyyrikkid binary to re-execute; os.Executable()
	// when empty.
	Executable string
	Targets    map[string]Target
	Limits     Limits
	Audit      audit.Appender
	// Now is the clock of the version-check cache; time.Now when nil.
	// Run deadlines always use the real clock, as contexts do.
	Now    func() time.Time
	Logger *slog.Logger
	// ServiceAccountDir holds ca.crt and token for in-cluster targets;
	// DefaultServiceAccountDir when empty.
	ServiceAccountDir string
}

// Runner runs canonical requests covered by a Grant.
type Runner struct {
	runtimeDir string
	exe        string
	targets    map[string]Target
	limits     Limits
	audit      audit.Appender
	now        func() time.Time
	log        *slog.Logger

	versionMu sync.Mutex
	verified  map[string]time.Time // target name → time of the last good version check
}

// Result is the outcome of a non-interactive run (docs/04 D13).
type Result = target.Result

// NewRunner validates cfg and returns a Runner. In-cluster targets are
// resolved here, from KUBERNETES_SERVICE_HOST/_PORT and the
// ServiceAccount directory.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Audit == nil {
		return nil, errors.New("kubectl: no audit appender")
	}
	if cfg.RuntimeDir == "" || !filepath.IsAbs(cfg.RuntimeDir) {
		return nil, errors.New("kubectl: runtime_dir must be an absolute path")
	}
	if fi, err := os.Stat(cfg.RuntimeDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("kubectl: runtime_dir %s is not a directory", cfg.RuntimeDir)
	}
	exe := cfg.Executable
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, fmt.Errorf("kubectl: finding own executable: %w", err)
		}
	}
	l := cfg.Limits
	if l.DefaultTimeout == 0 {
		l.DefaultTimeout = DefaultTimeout
	}
	if l.MaxTimeout == 0 {
		l.MaxTimeout = DefaultMaxTimeout
	}
	if l.MaxInteractive == 0 {
		l.MaxInteractive = DefaultMaxInteractive
	}
	if l.MaxOutput == 0 {
		l.MaxOutput = DefaultMaxOutput
	}
	if l.DefaultTimeout < 0 || l.MaxTimeout < 0 || l.MaxInteractive < 0 || l.MaxOutput < 0 || l.DefaultTimeout > l.MaxTimeout {
		return nil, errors.New("kubectl: invalid run limits")
	}
	saDir := cfg.ServiceAccountDir
	if saDir == "" {
		saDir = DefaultServiceAccountDir
	}
	targets := make(map[string]Target, len(cfg.Targets))
	for name, t := range cfg.Targets {
		if t.Name != name {
			return nil, fmt.Errorf("kubectl: target %q registered as %q", t.Name, name)
		}
		if t.InCluster {
			host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
			if host == "" || port == "" {
				return nil, fmt.Errorf("kubectl: target %s is in_cluster, but KUBERNETES_SERVICE_HOST/PORT are not set", name)
			}
			t.Server = "https://" + net.JoinHostPort(host, port)
			t.CAFile = filepath.Join(saDir, "ca.crt")
			t.TokenFile = filepath.Join(saDir, "token")
		}
		u, err := url.Parse(t.Server)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("kubectl: target %s: server must be an https URL", name)
		}
		if t.CAFile == "" || t.TokenFile == "" {
			return nil, fmt.Errorf("kubectl: target %s: ca_file and token_file are required", name)
		}
		targets[name] = t
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		runtimeDir: cfg.RuntimeDir,
		exe:        exe,
		targets:    targets,
		limits:     l,
		audit:      cfg.Audit,
		now:        now,
		log:        logger,
		verified:   make(map[string]time.Time),
	}, nil
}

// checkGrant is the runner's own check that the Grant covers exactly this
// request (docs/04 §5.3, G3). The decision point already did this; a
// mismatch here is a bug, and nothing runs.
func checkGrant(g *decision.Grant, c *request.Canonical) error {
	want := g.Digest()
	got := request.Digest(g.Target(), c)
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return codes.WithDetail(codes.Internal, DetailDigestMismatch, "the request doesn't match what was approved")
	}
	if g.Interactive() != c.Interactive() {
		return codes.WithDetail(codes.Internal, DetailInteractiveMismatch, "the request doesn't match what was approved")
	}
	return nil
}

// record is the audit record of a run, filled from the Grant.
func record(kind string, g *decision.Grant, c *request.Canonical) audit.Record {
	req := c.Audit()
	ra := g.RunAs()
	return audit.Record{
		Kind:        kind,
		Human:       g.Human(),
		Agent:       g.AgentKey(),
		ClientID:    g.ClientID(),
		Targets:     []string{g.Target()},
		RunID:       g.RunID(),
		ApprovalID:  g.ApprovalID(),
		ElevationID: g.ElevationID(),
		CoveredBy:   g.CoveredBy(),
		Request:     &req,
		RunAs:       &audit.RunAs{User: ra.User, Groups: ra.Groups},
	}
}

// appendAudit writes r with a context that outlives the Grant's, so a cut
// run's record is still written.
func (r *Runner) appendAudit(g *decision.Grant, rec audit.Record) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(g.Context()), 10*time.Second)
	defer cancel()
	return r.audit.Append(ctx, rec)
}

// auditRefusal records a refusal before anything started. A failed write
// changes nothing: the request is refused either way.
func (r *Runner) auditRefusal(g *decision.Grant, c *request.Canonical, kind string, err error) {
	rec := record(kind, g, c)
	rec.Decision = codes.Deny
	rec.Code = string(codes.Of(err))
	rec.Detail = codes.DetailOf(err)
	if aerr := r.appendAudit(g, rec); aerr != nil {
		r.log.Error("audit write failed for a refused run", "run_id", g.RunID(), "kind", kind, "err", aerr)
	}
}

// runLimits is the context a run lives in: the Grant's, bounded by limit
// and, under an elevation, by its expiry (docs/04 D7, D8).
type runLimits struct {
	ctx        context.Context
	cancel     context.CancelFunc
	byNotAfter bool
	notAfter   time.Time // the deadline when byNotAfter
	clientGone atomic.Bool
	grant      context.Context
}

func (r *Runner) limitsFor(g *decision.Grant, limit time.Duration) *runLimits {
	// The real clock, not r.now: context deadlines run on it.
	deadline := time.Now().Add(limit)
	byNotAfter := false
	if na := g.NotAfter(); !na.IsZero() && na.Before(deadline) {
		deadline, byNotAfter = na, true
	}
	ctx, cancel := context.WithDeadline(g.Context(), deadline)
	return &runLimits{ctx: ctx, cancel: cancel, byNotAfter: byNotAfter, notAfter: deadline, grant: g.Context()}
}

// cutDetail says why a killed run was cut.
func (l *runLimits) cutDetail() string {
	switch {
	// "End now" on the session (docs/07 D17).
	case errors.Is(context.Cause(l.grant), decision.ErrEndedByApprover):
		return decision.DetailEndedByApprover
	// At an elevation's expiry the decision point also ends the grant, at
	// the same instant as this deadline: past it, the cut was the expiry.
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

// prepare runs the steps before the child starts: the target version
// check (docs/04 D11) and the run directory with its kubeconfig (D9). Any
// failure is a refusal, audited, and nothing runs.
func (r *Runner) prepare(ctx context.Context, g *decision.Grant, c *request.Canonical) (*runDir, error) {
	if err := ctx.Err(); err != nil {
		err := codes.WithDetail(codes.Expired, DetailGrantEnded, "what covered this run has ended")
		r.auditRefusal(g, c, codes.KindDecision, err)
		return nil, err
	}
	if err := r.CheckTarget(ctx, g.Target()); err != nil {
		r.auditRefusal(g, c, codes.KindDependencyFailed, err)
		return nil, err
	}
	t := r.targets[g.Target()]
	rd, err := r.newRunDir(t, g.RunAs())
	if err != nil {
		r.auditRefusal(g, c, codes.KindDependencyFailed, err)
		return nil, err
	}
	return rd, nil
}

// childEnv is exactly docs/04 D6's environment. Nothing is inherited, so
// no HTTPS_PROXY or KUBECONFIG from the pod applies.
func childEnv(dir string) []string {
	return []string{
		"KUBECONFIG=" + filepath.Join(dir, "kubeconfig"),
		"KUBERC=off",
		"HOME=" + dir,
		"KUBECACHEDIR=" + filepath.Join(dir, "cache"),
		"PATH=",
		"LANG=C.UTF-8",
	}
}

// childCommand builds the child process. Its context is the run's: when it
// ends, Cancel kills the whole process group (docs/04 D8).
func (r *Runner) childCommand(l *runLimits, dir string, c *request.Canonical) (*exec.Cmd, *atomic.Bool) {
	cmd := exec.CommandContext(l.ctx, r.exe, append([]string{ChildArg}, c.Argv()...)...)
	cmd.Env = childEnv(dir)
	cmd.Dir = dir
	killed := new(atomic.Bool)
	cmd.Cancel = func() error {
		killed.Store(true)
		if cmd.Process == nil {
			return nil
		}
		// The child leads its own process group (Setpgid or Setsid), so
		// -pid reaches everything it started.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	return cmd, killed
}

// Run runs c, which g must cover, and returns kubectl's exit status and
// output (docs/04 D6–D8, D13). The run is bounded by timeout (the agent's
// value; DefaultTimeout when zero, at most MaxTimeout) and, under an
// elevation, by its expiry; it is killed when g's context ends.
//
// A run that was cut returns the output captured so far together with a
// *codes.Error with codes.Expired and a Detail of DetailTimeout,
// DetailGrantExpired or DetailGrantEnded. Any failure before the child
// starts returns a nil Result and an error: nothing ran. g is released on
// every path.
func (r *Runner) Run(g *decision.Grant, c *request.Canonical, timeout time.Duration) (*Result, error) {
	if g == nil || c == nil {
		return nil, codes.New(codes.Internal, "no grant or request")
	}
	defer g.Release()
	if err := checkGrant(g, c); err != nil {
		r.auditRefusal(g, c, codes.KindDecision, err)
		return nil, err
	}
	if c.Interactive() {
		err := codes.WithDetail(codes.Internal, DetailInteractiveMismatch, "interactive runs attach through the stream endpoint")
		r.auditRefusal(g, c, codes.KindDecision, err)
		return nil, err
	}
	if timeout <= 0 {
		timeout = r.limits.DefaultTimeout
	}
	timeout = min(timeout, r.limits.MaxTimeout)
	l := r.limitsFor(g, timeout)
	defer l.cancel()

	rd, err := r.prepare(l.ctx, g, c)
	if err != nil {
		return nil, err
	}
	defer rd.remove(r.log)

	cmd, killed := r.childCommand(l, rd.dir, c)
	cmd.Stdin = bytes.NewReader(c.Stdin())
	stdout := target.NewCapWriter(r.limits.MaxOutput)
	stderr := target.NewCapWriter(r.limits.MaxOutput)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}

	// docs/03 D4: the start is recorded before the child starts; if the
	// record can't be written, nothing runs.
	if err := r.appendAudit(g, record(codes.KindRunStarted, g, c)); err != nil {
		r.log.Error("audit write failed; run not started", "run_id", g.RunID(), "err", err)
		return nil, codes.Wrap(codes.Unavailable, err, "the audit log is unavailable")
	}
	if err := cmd.Start(); err != nil {
		r.finish(g, c, codes.KindRunFinished, -1, 0, 0, codes.Unavailable, DetailSetup)
		return nil, codes.Wrap(codes.Unavailable, err, "kubectl could not be started")
	}
	waitErr := cmd.Wait()
	res := &Result{
		ExitCode:        exitCode(cmd, waitErr),
		Stdout:          stdout.Bytes(),
		Stderr:          stderr.Bytes(),
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
	}
	if killed.Load() {
		detail := l.cutDetail()
		r.finish(g, c, codes.KindRunCut, res.ExitCode, stdout.N(), stderr.N(), codes.Expired, detail)
		return res, codes.WithDetail(codes.Expired, detail, "the run was cut: %s", cutMessage(detail))
	}
	r.finish(g, c, codes.KindRunFinished, res.ExitCode, stdout.N(), stderr.N(), "", "")
	return res, nil
}

// finish records a run's end. The request already ran, so a failed write
// is logged and the result still returned (docs/03 D4).
func (r *Runner) finish(g *decision.Grant, c *request.Canonical, kind string, exit int, out, errOut int64, code codes.Code, detail string) {
	rec := record(kind, g, c)
	rec.ExitCode = &exit
	rec.StdoutBytes, rec.StderrBytes = out, errOut
	rec.Code, rec.Detail = string(code), detail
	if err := r.appendAudit(g, rec); err != nil {
		r.log.Error("audit write failed for a finished run", "run_id", g.RunID(), "kind", kind, "err", err)
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

func exitCode(cmd *exec.Cmd, err error) int {
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}
