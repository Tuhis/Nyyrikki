package sopstarget

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopscodes "github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/logging"
	"github.com/urfave/cli"
	"google.golang.org/api/option"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// Detail values on the errors the runner returns, besides those of
// docs/10 D9 (keyservice.go, request.go).
const (
	DetailDigestMismatch      = "digest_mismatch"
	DetailInteractiveMismatch = "interactive_mismatch"
	DetailUnknownTarget       = "unknown_target"
	DetailCredentials         = "credentials_unavailable"
	DetailNotWritable         = "result_not_writable"
	DetailOutputTooLarge      = "output_too_large"
	DetailGrantEnded          = "grant_ended"
	DetailGrantExpired        = "grant_expired"
	DetailTimeout             = "run_timeout"
)

// maxReason is the longest request reason sent (docs/10 D7).
const maxReason = 256

// Target is one SOPS target (docs/10 §5.4).
type Target struct {
	Name            string
	CredentialsFile string
	Keys            []string
}

// Limits bound runs (docs/04 D7, docs/10 D11).
type Limits struct {
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MaxOutput      int64
}

// RunnerConfig configures a Runner.
type RunnerConfig struct {
	Targets map[string]Target
	Limits  Limits
	Audit   audit.Appender
	Logger  *slog.Logger
	// ClientOptions are added to every Cloud KMS client after Nyyrikki's
	// own (tests: the fake KMS's endpoint).
	ClientOptions []option.ClientOption
	// TokenHTTPClient replaces the HTTP client of token exchanges
	// (tests).
	TokenHTTPClient *http.Client
	// Getenv replaces os.Getenv (tests).
	Getenv func(string) string
}

// Runner runs SOPS requests covered by a Grant (docs/10 D5).
type Runner struct {
	targets map[string]Target
	creds   map[string]*credentials
	limits  Limits
	audit   audit.Appender
	log     *slog.Logger
	extra   []option.ClientOption
	// skipFileCheck leaves out Run's own check of the file, so that a
	// test can hand the key service a file the check refuses.
	skipFileCheck bool
}

// endpointEnv are the environment variables that decide where a Cloud
// KMS call, and the access token with it, is sent (docs/10 M16). SOPS
// reads the first two after every option it is given, so no option
// overrides them; the Google client under it reads the rest. NewRunner
// refuses to start with any of them set.
var endpointEnv = []string{
	gcpkms.SopsGCPKMSEndpointEnv, gcpkms.SopsGCPKMSUniverseDomainEnv,
	"GOOGLE_CLOUD_UNIVERSE_DOMAIN", "GOOGLE_API_USE_MTLS_ENDPOINT", "GOOGLE_API_USE_MTLS", "GOOGLE_API_USE_CLIENT_CERTIFICATE",
}

// NewRunner validates cfg and returns a Runner. It refuses to start
// when the environment redirects SOPS's Cloud KMS client: SOPS reads
// the endpoint and the universe domain from the environment whatever
// credential it is given (docs/10 §10), and a call sent elsewhere would
// carry the target's access token.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Audit == nil {
		return nil, errors.New("sopstarget: no audit appender")
	}
	l := cfg.Limits
	if l.DefaultTimeout <= 0 || l.MaxTimeout < l.DefaultTimeout || l.MaxOutput <= 0 {
		return nil, errors.New("sopstarget: invalid run limits")
	}
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	for _, name := range endpointEnv {
		if getenv(name) != "" {
			return nil, fmt.Errorf("sopstarget: %s is set; Nyyrikki doesn't take the Cloud KMS endpoint from the environment", name)
		}
	}
	r := &Runner{targets: cfg.Targets, creds: map[string]*credentials{}, limits: l, audit: cfg.Audit, log: cfg.Logger, extra: cfg.ClientOptions}
	if r.log == nil {
		r.log = slog.Default()
	}
	for name, t := range cfg.Targets {
		if t.Name != name || t.CredentialsFile == "" || len(t.Keys) == 0 {
			return nil, fmt.Errorf("sopstarget: target %q is incomplete", name)
		}
		r.creds[name] = &credentials{file: t.CredentialsFile, client: cfg.TokenHTTPClient}
	}
	return r, nil
}

// SOPS's own logging is discarded (docs/10 D9): it names keys and files,
// and Nyyrikki's log is agent-readable. This package is the only one
// that imports the SOPS library, and its init runs after theirs, when
// every logger of theirs exists.
func init() {
	for _, lg := range logging.Loggers {
		lg.SetOutput(io.Discard)
	}
}

// CheckCredentials reads and checks every target's credential file,
// without any call to Google (docs/10 D12), and returns what is wrong,
// by target. Runs read the files again on each use.
func (r *Runner) CheckCredentials() map[string]error {
	out := map[string]error{}
	for name, c := range r.creds {
		if _, err := c.tokenSource(); err != nil {
			out[name] = err
		}
	}
	return out
}

// checkGrant is the runner's own check that the Grant covers exactly
// this request (docs/10 D5). The decision point already did it; a
// mismatch is a bug, and nothing is called.
func checkGrant(g *decision.Grant, req *Request) error {
	want := g.Digest()
	got := req.Digest(g.Target(), g.RunAs().User)
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return codes.WithDetail(codes.Internal, DetailDigestMismatch, "the request doesn't match what was approved")
	}
	if g.Interactive() {
		return codes.WithDetail(codes.Internal, DetailInteractiveMismatch, "a sops target has no interactive runs")
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

// refuse audits a refusal before anything started; a failed write
// changes nothing, the request is refused either way.
func (r *Runner) refuse(g *decision.Grant, req *Request, kind string, err error) error {
	rec := record(kind, g, req)
	rec.Decision = codes.Deny
	rec.Code = string(codes.Of(err))
	rec.Detail = codes.DetailOf(err)
	if aerr := r.appendAudit(g, rec); aerr != nil {
		r.log.Error("audit write failed for a refused run", "run_id", g.RunID(), "kind", kind, "err", aerr)
	}
	return err
}

// requestReason is what every Cloud KMS call of a run carries (docs/10
// D7), built from the Grant only: Nyyrikki's own IDs and the human's.
func requestReason(g *decision.Grant) string {
	cover := "approval:" + g.ApprovalID()
	if g.ElevationID() != "" {
		cover = "elevation:" + g.ElevationID()
	}
	s := "nyyrikki run=" + g.RunID() + " human=" + g.Human() + " covered_by=" + cover
	if len(s) > maxReason {
		s = s[:maxReason]
	}
	return s
}

// cutDetail says why a run's context ended (docs/04 D8).
func cutDetail(g *decision.Grant, deadline time.Time, byNotAfter bool) string {
	switch {
	case errors.Is(context.Cause(g.Context()), decision.ErrEndedByApprover):
		return decision.DetailEndedByApprover
	case byNotAfter && !time.Now().Before(deadline):
		return DetailGrantExpired
	case g.Context().Err() != nil:
		return DetailGrantEnded
	case byNotAfter:
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
	default:
		return "its time limit was reached"
	}
}

// failure is how a run that started ended without a result: a fixed
// code, detail and message (docs/10 D9).
func failure(detail string) *codes.Error {
	switch detail {
	case DetailMACMismatch:
		return codes.WithDetail(codes.InvalidRequest, detail, "mac_mismatch: the file's MAC doesn't match its contents; nothing is returned")
	case DetailValueNotDecryptable:
		return codes.WithDetail(codes.InvalidRequest, detail, "value_not_decryptable: the file's data key or one of its values could not be decrypted; nothing is returned")
	case DetailKeyNotAllowed:
		return codes.WithDetail(codes.InvalidRequest, detail, "key_not_allowed: the file names a key this target doesn't use")
	case DetailKMSCallLimit:
		return codes.WithDetail(codes.InvalidRequest, detail, "kms_call_limit: the file would use a Cloud KMS key more than once")
	case DetailPathNotFound:
		return codes.WithDetail(codes.InvalidRequest, detail, "path_not_found: the file has nothing at that path")
	case DetailNotWritable:
		return codes.WithDetail(codes.InvalidRequest, detail, "result_not_writable: the result can't be written as that file type")
	case DetailOutputTooLarge:
		return codes.WithDetail(codes.InvalidRequest, detail, "output_too_large: the result is larger than the output limit; nothing is returned")
	case DetailKMSDenied:
		return codes.WithDetail(codes.Unavailable, detail, "kms_denied: Cloud KMS refused Nyyrikki's credential for the key")
	default:
		return codes.WithDetail(codes.Unavailable, DetailKMSUnavailable, "kms_unavailable: Cloud KMS could not be used")
	}
}

// opError is a failure of the operation itself, by its detail.
type opError struct{ detail string }

func (e *opError) Error() string { return e.detail }

func fail(detail string) error { return &opError{detail: detail} }

// Run runs req, which g must cover, and returns the result (docs/10 D5,
// D9). It is bounded as kubectl runs are (docs/04 D7) and its Cloud KMS
// calls end when g's context does. Every failure returns a nil Result:
// a run returns all of its result or none of it. g is released on every
// path.
func (r *Runner) Run(g *decision.Grant, req *Request, timeout time.Duration) (*target.Result, error) {
	if g == nil || req == nil {
		return nil, codes.New(codes.Internal, "no grant or request")
	}
	defer g.Release()
	if err := checkGrant(g, req); err != nil {
		return nil, r.refuse(g, req, codes.KindDecision, err)
	}
	if timeout <= 0 {
		timeout = r.limits.DefaultTimeout
	}
	deadline, byNotAfter := time.Now().Add(min(timeout, r.limits.MaxTimeout)), false
	if na := g.NotAfter(); !na.IsZero() && na.Before(deadline) {
		deadline, byNotAfter = na, true
	}
	ctx, cancel := context.WithDeadline(g.Context(), deadline)
	defer cancel()
	cut := func() *codes.Error {
		d := cutDetail(g, deadline, byNotAfter)
		return codes.WithDetail(codes.Expired, d, "the run was cut: %s; nothing is returned", cutMessage(d))
	}
	if ctx.Err() != nil {
		d := cutDetail(g, deadline, byNotAfter)
		return nil, r.refuse(g, req, codes.KindDecision, codes.WithDetail(codes.Expired, d, "the run was not started: %s", cutMessage(d)))
	}
	t, ok := r.targets[g.Target()]
	if !ok {
		return nil, r.refuse(g, req, codes.KindDependencyFailed, codes.WithDetail(codes.Unavailable, DetailUnknownTarget, "the target is not configured"))
	}
	// The check of docs/10 D4 again, against this runner's own list of
	// the target's keys: nothing is called for a file it refuses.
	if err := guarded(func() error {
		if r.skipFileCheck {
			return nil
		}
		_, err := req.checkFile(t.Keys)
		return err
	}); err != nil {
		if _, ok := err.(*codes.Error); !ok {
			err = invalid(DetailFileNotParsed, "the file could not be read")
		}
		return nil, r.refuse(g, req, codes.KindDecision, err)
	}
	tokens, err := r.creds[t.Name].tokenSource()
	if err != nil {
		// The loader's errors are Nyyrikki's own text, with nothing from
		// the file.
		r.log.Error("a sops target's Google credential is unavailable", "target", t.Name, "reason", err.Error())
		return nil, r.refuse(g, req, codes.KindDependencyFailed,
			codes.WithDetail(codes.Unavailable, DetailCredentials, "credentials_unavailable: the target's Google credential could not be loaded"))
	}

	// docs/03 D4: the start is recorded before anything is called.
	if err := r.appendAudit(g, record(codes.KindRunStarted, g, req)); err != nil {
		r.log.Error("audit write failed; run not started", "run_id", g.RunID(), "err", err)
		return nil, codes.Wrap(codes.Unavailable, err, "the audit log is unavailable")
	}
	ks := &keyService{ctx: ctx, allowed: slices.Clone(t.Keys), tokens: tokens, reason: requestReason(g), extra: r.extra}
	var out []byte
	opErr := guarded(func() error {
		var err error
		out, err = req.run(ks)
		return err
	})
	calls, refused := ks.record()
	var called []string
	for _, c := range calls {
		if c.Made {
			called = append(called, c.Key)
		}
		if c.Outcome == "" {
			continue
		}
		// docs/10 D10: every call that failed or was refused, with its
		// code, from the key service's record.
		kind := codes.KindDependencyFailed
		if !c.Made {
			kind = codes.KindDecision
		}
		rec := record(kind, g, req)
		if !c.Made {
			rec.Decision = codes.Deny
		}
		if c.Key != "" {
			rec.KMSKeys = []string{c.Key}
		}
		f := failure(c.Outcome)
		rec.Code, rec.Detail = string(f.Code), f.Detail
		if aerr := r.appendAudit(g, rec); aerr != nil {
			r.log.Error("audit write failed for a KMS call", "run_id", g.RunID(), "err", aerr)
		}
	}

	finish := func(kind string, exit int, n int64, e *codes.Error) {
		rec := record(kind, g, req)
		rec.ExitCode = &exit
		rec.StdoutBytes = n
		rec.KMSKeys = called
		if e != nil {
			rec.Code, rec.Detail = string(e.Code), e.Detail
		}
		if aerr := r.appendAudit(g, rec); aerr != nil {
			r.log.Error("audit write failed for a finished run", "run_id", g.RunID(), "kind", kind, "err", aerr)
		}
	}
	var e *codes.Error
	switch {
	case ctx.Err() != nil:
		// A cut run returns nothing, whatever the library got done
		// (docs/10 D11).
		e = cut()
		finish(codes.KindRunCut, -1, 0, e)
		return nil, e
	case refused != "":
		// The latch (docs/10 D5): the key service refused something, so
		// the run fails whatever SOPS went on to do.
		e = failure(refused)
	case opErr != nil:
		e = failure(r.detailOf(opErr, calls))
	case int64(len(out)) > r.limits.MaxOutput:
		e = failure(DetailOutputTooLarge)
	}
	if e != nil {
		finish(codes.KindRunFinished, 1, 0, e)
		return nil, e
	}
	finish(codes.KindRunFinished, 0, int64(len(out)), nil)
	return &target.Result{ExitCode: 0, Stdout: out}, nil
}

// detailOf maps a failed operation to one of the fixed details (docs/10
// D9). SOPS's own errors are read only for their exit code; a failure
// to get the data key takes its detail from the key service's record,
// since SOPS reports it only as text (M15).
func (r *Runner) detailOf(err error, calls []kmsCall) string {
	var oe *opError
	if errors.As(err, &oe) {
		return oe.detail
	}
	var xe *cli.ExitError
	if errors.As(err, &xe) {
		switch xe.ExitCode() {
		case sopscodes.MacMismatch:
			return DetailMACMismatch
		case sopscodes.ErrorDecryptingTree:
			return DetailValueNotDecryptable
		case sopscodes.CouldNotRetrieveKey:
			return keyFailure(calls)
		}
	}
	if errors.Is(err, errNoDataKey) {
		return keyFailure(calls)
	}
	// Anything else, a panic of the library's included, came after the
	// data key was there: the result couldn't be made.
	return DetailNotWritable
}

// errNoDataKey is an encrypt whose new data key couldn't be wrapped.
var errNoDataKey = errors.New("sopstarget: no data key")

// keyFailure is the detail of a run that got no data key: the worst of
// its calls' outcomes, an outage before a refusal before a wrapped key
// that Cloud KMS couldn't decrypt.
func keyFailure(calls []kmsCall) string {
	worst := DetailKMSUnavailable
	rank := map[string]int{DetailValueNotDecryptable: 1, DetailKMSDenied: 2, DetailKMSUnavailable: 3}
	best := 0
	for _, c := range calls {
		if n := rank[c.Outcome]; c.Made && n > best {
			best, worst = n, c.Outcome
		}
	}
	return worst
}

// run does the operation with ks as the only key service (docs/10 D5)
// and returns the bytes of its result. Its errors are an *opError, or
// one of the SOPS library's, which the caller maps and never passes on.
func (r *Request) run(ks *keyService) ([]byte, error) {
	svcs := []keyservice.KeyServiceClient{ks}
	st := store(r.flags[flagInputType])
	if r.op == opEncrypt {
		branches, err := st.LoadPlainFile(r.stdin)
		if err != nil || len(branches) != 1 || st.HasSopsTopLevelKey(branches[0]) {
			return nil, fail(DetailNotWritable)
		}
		tree := sops.Tree{Branches: branches, Metadata: r.metadata()}
		key, errs := tree.GenerateDataKeyWithKeyServices(svcs)
		defer wipe(key)
		if len(errs) > 0 {
			return nil, errNoDataKey
		}
		if err := common.EncryptTree(common.EncryptTreeOpts{DataKey: key, Tree: &tree, Cipher: aes.NewCipher()}); err != nil {
			return nil, fail(DetailNotWritable)
		}
		return emit(func() ([]byte, error) { return st.EmitEncryptedFile(tree) })
	}

	tree, err := st.LoadEncryptedFile(r.stdin)
	if err != nil || len(tree.Branches) != 1 {
		return nil, fail(DetailNotWritable)
	}
	// The MAC is always checked: IgnoreMac is never set (docs/10 D5).
	key, err := common.DecryptTree(common.DecryptTreeOpts{Cipher: aes.NewCipher(), Tree: &tree, KeyServices: svcs})
	defer wipe(key)
	if err != nil {
		return nil, err
	}
	switch r.op {
	case opDecrypt:
		out := st
		if t, ok := r.flags[flagOutputType]; ok {
			out = store(t)
		}
		if r.path == nil {
			return emit(func() ([]byte, error) { return out.EmitPlainFile(tree.Branches) })
		}
		v, found := lookup(tree.Branches[0], r.path)
		if !found {
			return nil, fail(DetailPathNotFound)
		}
		switch v := v.(type) {
		case sops.TreeBranch:
			tree.Branches[0] = v
			return emit(func() ([]byte, error) { return out.EmitPlainFile(tree.Branches) })
		case string:
			return []byte(v), nil
		}
		return emit(func() ([]byte, error) { return out.EmitValue(v) })
	case opSet:
		// Read again for this run: the library encrypts a tree in place.
		value, err := insertable(r.positionals[1])
		if err != nil {
			return nil, fail(DetailNotWritable)
		}
		// Set's second result says whether the value changed, not
		// whether it worked: it has no error, and panics on a path it
		// can't follow, which guarded turns into a failure.
		tree.Branches[0], _ = tree.Branches[0].Set(r.path, value)
	case opUnset:
		b, err := tree.Branches[0].Unset(r.path)
		if err != nil {
			return nil, fail(DetailPathNotFound)
		}
		tree.Branches[0] = b
	}
	if st.HasSopsTopLevelKey(tree.Branches[0]) {
		return nil, fail(DetailNotWritable)
	}
	if err := common.EncryptTree(common.EncryptTreeOpts{DataKey: key, Tree: &tree, Cipher: aes.NewCipher()}); err != nil {
		return nil, fail(DetailNotWritable)
	}
	return emit(func() ([]byte, error) { return st.EmitEncryptedFile(tree) })
}

func emit(f func() ([]byte, error)) ([]byte, error) {
	b, err := f()
	if err != nil {
		return nil, fail(DetailNotWritable)
	}
	return b, nil
}

// wipe zeroes a data key once the run is done with it.
func wipe(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
