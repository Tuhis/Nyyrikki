package hostsetup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
	"github.com/Tuhis/Nyyrikki/internal/sshtarget"
)

// The enrollment endpoints (docs/08 D7), on :8443 next to setup.sh.
const (
	EnrollPattern = "POST /hosts/{target}/enroll"
	CheckPattern  = "POST /hosts/{target}/enroll/check"
	// AuthScheme is the Authorization scheme of an enrollment token.
	AuthScheme = "Nyyrikki-Enroll"
	// maxEnrollBody bounds the enrollment's data lines (docs/08 §6).
	maxEnrollBody = 4 << 10
	// enrollBodyTimeout bounds the read of an enrollment body (round 1 of #47).
	enrollBodyTimeout = 30 * time.Second
)

// Token refusals, each a 401 and an audit detail (docs/08 D6, G6). A
// forged, truncated or other target's token is token_invalid: the
// caller learns nothing about why.
const (
	detailTokenInvalid = "token_invalid"
	detailTokenExpired = "token_expired"
	detailTokenUsed    = "token_used"
	detailBadBody      = "body_malformed"
)

// Enroller is the decision point's enrollment (decision.Point).
type Enroller interface {
	DecideEnroll(ctx context.Context, r decision.EnrollRequest, issue func(ctx context.Context, approvalID string) error) error
}

// Prober is the SSH runner's check after enrollment (sshtarget.Runner).
type Prober interface {
	Probe(ctx context.Context, target string, issued *ssh.Certificate, humans []string,
		beforeAuth func(human, account, serial string) error) ([]sshtarget.ProbeAccount, error)
}

// EnrollConfig wires an Enroll.
type EnrollConfig struct {
	Config   *config.Config
	Keys     *sshca.Keys
	Decision Enroller
	Prober   Prober
	Audit    audit.Appender
	Logger   *slog.Logger
	Now      func() time.Time
}

// Enroll serves POST /hosts/<target>/enroll and /enroll/check
// (docs/08 D7). Neither has an authorization server's token: the
// enrollment token of D6 is checked before anything else is read, and
// is kept in memory, by its random part, until it expires, so that it
// starts one enrollment and one check. A restart forgets it (D6).
type Enroll struct {
	c   EnrollConfig
	log *slog.Logger

	mu     sync.Mutex
	tokens map[[tokenRandomLen]byte]*tokenUse
}

// A token's use: enrolling while the approval is asked, enrolled with
// the certificate issued, and used once checked, denied or failed.
type tokenUse struct {
	expires time.Time
	stage   int
	cert    *ssh.Certificate
}

const (
	stageEnrolling = iota + 1
	stageEnrolled
	stageUsed
)

// NewEnroll checks c and returns the handlers.
func NewEnroll(c EnrollConfig) (*Enroll, error) {
	if c.Config == nil || c.Keys == nil || c.Decision == nil || c.Prober == nil || c.Audit == nil {
		return nil, errors.New("hostsetup: incomplete enrollment wiring")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	log := c.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Enroll{c: c, log: log.With("component", "enroll"), tokens: map[[tokenRandomLen]byte]*tokenUse{}}, nil
}

// Register mounts both endpoints on mux.
func (e *Enroll) Register(mux *http.ServeMux) {
	mux.HandleFunc(EnrollPattern, e.serveEnroll)
	mux.HandleFunc(CheckPattern, e.serveCheck)
}

// request is what both endpoints share once the token passed.
type request struct {
	target *config.Target
	token  Token
	client string
}

// refusal answers and audits a request refused before any prompt.
func (e *Enroll) refuse(w http.ResponseWriter, r *http.Request, rec audit.Record, status int, detail string) {
	rec.Kind = codes.KindHostEnrollDenied
	if strings.HasSuffix(r.URL.Path, "/check") {
		rec.Kind = codes.KindHostEnrollChecked
	}
	rec.Decision = codes.Deny
	switch status {
	case http.StatusUnauthorized, http.StatusBadRequest:
		rec.Code = string(codes.InvalidRequest)
	default:
		rec.Code = string(codes.Unavailable)
	}
	rec.Detail = detail
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	if err := e.c.Audit.Append(ctx, rec); err != nil {
		e.log.Error("audit write failed", "err", err)
	}
	e.log.Info("enrollment request refused", "target", strings.Join(rec.Targets, ","), "detail", detail, "client", rec.ClientAddr)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", AuthScheme)
	}
	http.Error(w, http.StatusText(status)+": "+detail, status)
}

// begin does the checks both endpoints share, in order: no query, an
// SSH target in the registry (404 otherwise, as setup.sh answers), the
// CA keys readable and host-ca present (503), and a token signed by
// this Nyyrikki, for this target, not expired (401). It answers and
// returns false on any failure.
func (e *Enroll) begin(w http.ResponseWriter, r *http.Request) (request, bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var q request
	q.client = clientAddr(r.RemoteAddr)
	rec := audit.Record{ClientAddr: q.client}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "no query string", http.StatusBadRequest)
		return q, false
	}
	name := r.PathValue("target")
	if config.IsSlug(name) {
		if t, ok := e.c.Config.TargetByName(name); ok && t.SSH != nil {
			q.target = t
		}
	}
	if q.target == nil {
		http.NotFound(w, r)
		return q, false
	}
	rec.Targets = []string{q.target.Name}
	set, err := e.c.Keys.Load()
	if err != nil {
		e.refuse(w, r, rec, http.StatusServiceUnavailable, detailOr(err, "unavailable"))
		return q, false
	}
	key, err := set.EnrollTokenKey()
	set = nil
	if err != nil {
		e.refuse(w, r, rec, http.StatusServiceUnavailable, detailOr(err, "unavailable"))
		return q, false
	}
	defer clear(key)
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), AuthScheme+" ")
	if !ok || len(r.Header.Values("Authorization")) != 1 {
		e.refuse(w, r, rec, http.StatusUnauthorized, detailTokenInvalid)
		return q, false
	}
	tok, err := ParseToken(key, raw)
	if err != nil {
		e.refuse(w, r, rec, http.StatusUnauthorized, detailTokenInvalid)
		return q, false
	}
	// Authentic from here on: its hash may be audited.
	rec.TokenSHA256 = tok.SHA256()
	if tok.Target != q.target.Name {
		e.refuse(w, r, rec, http.StatusUnauthorized, detailTokenInvalid)
		return q, false
	}
	if !e.c.Now().Before(tok.Expires) {
		e.refuse(w, r, rec, http.StatusUnauthorized, detailTokenExpired)
		return q, false
	}
	q.token = tok
	return q, true
}

func detailOr(err error, def string) string {
	if d := codes.DetailOf(err); d != "" {
		return d
	}
	return def
}

func clientAddr(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return "unknown"
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	return a.Unmap().String()
}

// claim moves the token from one stage to the next, atomically; it
// reports false if the token wasn't in stage from (0: never seen), and
// expired true if the token's life has ended, which it checks first: a
// client sending its body slowly can pass begin's expiry check and reach
// this after expiry, when the sweep below has already dropped an earlier
// use, so "never seen" would wrongly hold (round 1 of #47). It then drops
// tokens past their expiry.
func (e *Enroll) claim(t Token, from, to int, cert *ssh.Certificate) (prev *ssh.Certificate, ok, expired bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.c.Now()
	if !now.Before(t.Expires) {
		return nil, false, true
	}
	for k, u := range e.tokens {
		if !now.Before(u.expires) {
			delete(e.tokens, k)
		}
	}
	u := e.tokens[t.Random]
	cur := 0
	if u != nil {
		cur = u.stage
	}
	if cur != from {
		return nil, false, false
	}
	if u == nil {
		u = &tokenUse{expires: t.Expires}
		e.tokens[t.Random] = u
	}
	prev = u.cert
	u.stage = to
	if cert != nil {
		u.cert = cert
	}
	if to == stageUsed {
		u.cert = nil
	}
	return prev, true, false
}

func (e *Enroll) serveEnroll(w http.ResponseWriter, r *http.Request) {
	q, ok := e.begin(w, r)
	if !ok {
		return
	}
	rec := audit.Record{Targets: []string{q.target.Name}, ClientAddr: q.client, TokenSHA256: q.token.SHA256()}
	// Bound how long a client may take over its body; the claim below
	// refuses an expired token whatever the deadline (round 1 of #47).
	// Not every ResponseWriter supports deadlines, so the error is ignored.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(enrollBodyTimeout))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnrollBody))
	if err != nil {
		e.refuse(w, r, rec, http.StatusBadRequest, detailBadBody)
		return
	}
	hostKey, sessionKill, err := ParseEnrollBody(body)
	if err != nil {
		e.refuse(w, r, rec, http.StatusBadRequest, detailBadBody)
		return
	}
	rec.HostKey = ssh.FingerprintSHA256(hostKey)
	// A revoked host key would be refused on every run (docs/08 D9):
	// refuse it before anyone is asked, without using the token up
	// (round 1 of #47).
	for _, k := range e.c.Config.SSH.RevokedHostKeys {
		if pk, err := config.ParsePublicKey(k); err == nil && bytes.Equal(pk.Marshal(), hostKey.Marshal()) {
			e.refuse(w, r, rec, http.StatusBadRequest, "host_key_revoked")
			return
		}
	}
	// One enrollment per token (docs/08 D6), claimed before anyone is
	// asked.
	if _, ok, expired := e.claim(q.token, 0, stageEnrolling, nil); !ok {
		detail := detailTokenUsed
		if expired {
			detail = detailTokenExpired
		}
		e.refuse(w, r, rec, http.StatusUnauthorized, detail)
		return
	}
	host, _, err := config.SplitAddress(q.target.SSH.Address)
	if err != nil {
		e.claim(q.token, stageEnrolling, stageUsed, nil)
		e.refuse(w, r, rec, http.StatusServiceUnavailable, "bad_address")
		return
	}
	var cert *ssh.Certificate
	issue := func(ctx context.Context, approvalID string) error {
		set, err := e.c.Keys.Load()
		if err != nil {
			return err
		}
		c, err := set.SignHostCert(sshca.HostCert{
			Key: hostKey, Target: q.target.Name, Host: host,
			Validity: e.c.Config.SSH.HostCertValidity.D(), SessionKill: sessionKill, Now: e.c.Now(),
		})
		set = nil
		if err != nil {
			return err
		}
		issued := rec
		issued.Kind = codes.KindHostCertIssued
		issued.ApprovalID = approvalID
		issued.CertSerial = strconv.FormatUint(c.Serial, 10)
		issued.Detail = sessionKillDetail(sessionKill)
		// No record, no certificate (docs/03 D4).
		if err := e.c.Audit.Append(ctx, issued); err != nil {
			return codes.Wrap(codes.Unavailable, err, "audit log unavailable")
		}
		cert = c
		return nil
	}
	err = e.c.Decision.DecideEnroll(r.Context(), decision.EnrollRequest{
		Target: q.target.Name, HostKey: "ED25519 " + rec.HostKey, Fingerprint: rec.HostKey,
		Digest: enrollDigest(q.target.Name, hostKey, sessionKill), SessionKill: sessionKill,
		ClientAddr: q.client, TokenIssued: q.token.Issued(), TokenSHA256: q.token.SHA256(),
	}, issue)
	if err != nil || cert == nil {
		e.claim(q.token, stageEnrolling, stageUsed, nil)
		if err == nil {
			err = codes.New(codes.Internal, "approved without a certificate")
		}
		writeError(w, err)
		return
	}
	e.claim(q.token, stageEnrolling, stageEnrolled, cert)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	fmt.Fprintf(w, "HOST_CERT=%s\nEND=1\n", line)
}

// writeError answers a refused enrollment. Its message is Nyyrikki's
// own and holds no secret.
func writeError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	switch codes.Of(err) {
	case codes.Denied, codes.Expired, codes.Withdrawn:
		status = http.StatusForbidden
	case codes.InvalidRequest:
		status = http.StatusBadRequest
	case codes.Internal:
		status = http.StatusInternalServerError
	}
	msg := string(codes.Of(err))
	if d := codes.DetailOf(err); d != "" {
		msg += ": " + d
	}
	http.Error(w, msg, status)
}

func sessionKillDetail(kill bool) string {
	if kill {
		return "session_kill"
	}
	return "no_session_kill"
}

// enrollDigest binds an enrollment's approvals to what the approver is
// asked about.
func enrollDigest(target string, key ssh.PublicKey, kill bool) [32]byte {
	h := sha256.New()
	h.Write([]byte("nyyrikki-enroll-v1\x00" + target + "\x00"))
	h.Write(key.Marshal())
	h.Write([]byte("\x00" + strconv.FormatBool(kill)))
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// ParseEnrollBody reads the enrollment's data lines (docs/08 D7) with
// docs/07 D16's strict grammar: exactly HOST_KEY=<ssh-ed25519 key, type
// and base64 only>, SESSION_KILL=true|false and END=2, in that order,
// each ending in a newline, printable ASCII only, nothing else.
func ParseEnrollBody(b []byte) (ssh.PublicKey, bool, error) {
	bad := errors.New("hostsetup: malformed enrollment body")
	if len(b) == 0 || len(b) > maxEnrollBody || b[len(b)-1] != '\n' {
		return nil, false, bad
	}
	for _, c := range b {
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			return nil, false, bad
		}
	}
	lines := strings.Split(string(b[:len(b)-1]), "\n")
	if len(lines) != 3 || lines[2] != "END=2" {
		return nil, false, bad
	}
	keyLine, ok := strings.CutPrefix(lines[0], "HOST_KEY=")
	if !ok {
		return nil, false, bad
	}
	var kill bool
	switch lines[1] {
	case "SESSION_KILL=true":
		kill = true
	case "SESSION_KILL=false":
	default:
		return nil, false, bad
	}
	pk, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil || len(opts) > 0 || len(rest) > 0 || pk.Type() != ssh.KeyAlgoED25519 {
		return nil, false, bad
	}
	if _, isCert := pk.(*ssh.Certificate); isCert {
		return nil, false, bad
	}
	// One spelling only: type, one space, the canonical base64.
	if !bytes.Equal([]byte(keyLine), []byte(sshca.AuthorizedKey(pk))) {
		return nil, false, bad
	}
	return pk, kill, nil
}

func (e *Enroll) serveCheck(w http.ResponseWriter, r *http.Request) {
	q, ok := e.begin(w, r)
	if !ok {
		return
	}
	rec := audit.Record{Kind: codes.KindHostEnrollChecked, Targets: []string{q.target.Name}, ClientAddr: q.client, TokenSHA256: q.token.SHA256()}
	// The check takes no body.
	if n, _ := io.ReadFull(http.MaxBytesReader(w, r.Body, 1), make([]byte, 1)); n != 0 {
		e.refuse(w, r, rec, http.StatusBadRequest, detailBadBody)
		return
	}
	// After an approved enrollment only, once (docs/08 D7).
	cert, ok, expired := e.claim(q.token, stageEnrolled, stageUsed, nil)
	if !ok || cert == nil {
		detail := detailTokenUsed
		if expired {
			detail = detailTokenExpired
		}
		e.refuse(w, r, rec, http.StatusUnauthorized, detail)
		return
	}
	rec.HostKey = ssh.FingerprintSHA256(cert.Key)
	bg := context.WithoutCancel(r.Context())
	results, err := e.c.Prober.Probe(r.Context(), q.target.Name, cert, q.target.Humans, func(human, account, serial string) error {
		// The run certificate is recorded before it reaches the host
		// (docs/03 D4).
		pre := rec
		pre.Human = human
		pre.RunAs = &audit.RunAs{User: account}
		pre.CertSerial = serial
		pre.Detail = "probe_started"
		if err := e.c.Audit.Append(r.Context(), pre); err != nil {
			return codes.Wrap(codes.Unavailable, err, "audit log unavailable")
		}
		return nil
	})
	done := rec
	if err != nil {
		done.Decision = codes.Deny
		done.Code = string(codes.Of(err))
		done.Detail = detailOr(err, "unavailable") + " " + summary(results)
		if aerr := e.c.Audit.Append(bg, done); aerr != nil {
			e.log.Error("audit write failed", "err", aerr)
		}
		writeError(w, err)
		return
	}
	done.Detail = summary(results)
	if err := e.c.Audit.Append(bg, done); err != nil {
		e.log.Error("audit write failed", "err", err)
		http.Error(w, "unavailable: audit", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(CheckLines(e.c.Config, results))
}

// summary is the audit detail of a check: each account's status.
func summary(rs []sshtarget.ProbeAccount) string {
	var parts []string
	for _, a := range rs {
		parts = append(parts, a.Account+"="+a.Status)
	}
	return strings.Join(parts, " ")
}

// CheckLines is the check's answer, data lines as docs/07 D16 writes
// them: OK=<account> or REFUSED=<account> per account checked,
// NOT_CHECKED=<account> for those after the first refusal, a HINT line
// after a refusal, and END.
func CheckLines(c *config.Config, rs []sshtarget.ProbeAccount) []byte {
	var lines []string
	refused := ""
	for _, a := range rs {
		switch a.Status {
		case sshtarget.ProbeOK:
			lines = append(lines, "OK="+a.Account)
		case sshtarget.ProbeRefused:
			lines = append(lines, "REFUSED="+a.Account)
			refused = a.Account
		default:
			lines = append(lines, "NOT_CHECKED="+a.Account)
		}
	}
	if refused != "" {
		lines = append(lines, "HINT="+refusedHint(c, refused))
	}
	lines = append(lines, "END="+strconv.Itoa(len(lines)))
	return []byte(strings.Join(lines, "\n") + "\n")
}

// refusedHint names the two usual causes of a refused login (docs/08
// D7): a source address the host doesn't accept, and a missing
// principals file. Every value in it is a config value of a checked
// format.
func refusedHint(c *config.Config, account string) string {
	return "the host refused Nyyrikki's login as " + account +
		"; check that ssh.source_addresses (" + strings.Join(c.SSH.SourceAddresses, ",") +
		") holds the address Nyyrikki connects from, and that /etc/ssh/nyyrikki/principals/" + account +
		" exists; the accounts after it were not tried, so the host's PerSourcePenalties are tripped once at most"
}
