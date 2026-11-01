// Package hostsetup serves GET /hosts/<target>/setup.sh (docs/07 D16,
// OD3): the host setup script, byte for byte the file in the repo,
// followed by data lines built from config; and GET /hosts/<target>/trust
// (docs/08 D4): the trust bundle hosts pull, the same kind of data lines
// signed by user-ca. Neither needs a token, since a host has none. The CA
// key files are read to derive the public keys hosts trust (docs/08 D1)
// and to sign the bundle; nothing of a private key is served.
package hostsetup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// Prefix is the path the handler is mounted at.
const Prefix = "/hosts/"

// MainLine is the body's last line: the heredoc its data lines are read
// from (docs/07 D16, M22).
const MainLine = `main "$@" <<'NYYRIKKI_VALUES_END'`

// Terminator ends the data lines.
const Terminator = "NYYRIKKI_VALUES_END"

// mainPattern matches any line that could start main's heredoc; the body
// must have exactly one, its last (docs/07 G13).
var mainPattern = regexp.MustCompile(`(?m)^main .*<<.*NYYRIKKI_VALUES_END`)

// CheckBody checks the invariants of docs/07 D16 on the script body.
func CheckBody(body []byte) error {
	if !bytes.HasSuffix(body, []byte("\n"+MainLine+"\n")) {
		return errors.New("hostsetup: the script must end with the main line")
	}
	if n := len(mainPattern.FindAll(body, -1)); n != 1 {
		return fmt.Errorf("hostsetup: the script has %d main lines, want exactly 1", n)
	}
	if bytes.Contains(body, []byte("\n"+Terminator+"\n")) {
		return errors.New("hostsetup: the script contains the terminator")
	}
	return nil
}

// lines collects data lines in docs/07 D16's grammar. The first error
// sticks; every value is checked before it is added, so nothing the host
// would refuse is ever served.
type lines struct {
	l   []string
	err error
}

func (b *lines) add(name, value string) {
	if b.err != nil {
		return
	}
	if strings.ContainsAny(value, "\n\r\x00") {
		b.err = fmt.Errorf("hostsetup: %s holds a line break", name)
		return
	}
	b.l = append(b.l, name+"="+value)
}

// key adds a user CA key in the data lines' form, type and base64 only,
// after the same format checks as a configured key.
func (b *lines) key(name string, pk ssh.PublicKey) {
	if b.err != nil {
		return
	}
	line := sshca.AuthorizedKey(pk)
	if _, err := config.ParseUserCAKey(line); err != nil {
		b.err = fmt.Errorf("hostsetup: %s: %w", name, err)
		return
	}
	b.add(name, line)
}

func (b *lines) humans(t *config.Target) {
	for _, h := range t.Humans {
		if b.err != nil {
			return
		}
		if !config.IsSlug(h) || len(h) > config.MaxSSHHumanID {
			b.err = fmt.Errorf("hostsetup: human %q can't have an SSH account", h)
			return
		}
		b.add("HUMAN", h)
	}
}

// end appends END, counting the lines before it.
func (b *lines) end() {
	b.add("END", strconv.Itoa(len(b.l)))
}

func (b *lines) bytes() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	return []byte(strings.Join(b.l, "\n") + "\n"), nil
}

// DataLines builds the data lines for target t (docs/07 D16, docs/08
// D13): every value from config or the CA keys, each in a format config
// validation already checked and the script checks again, in order:
// TARGET; one HUMAN per human; one CA_KEY per key of the trusted set
// (docs/08 D1); one SIGNER_KEY per bundle signer (D4), a subset of the
// CA_KEYs; one REVOKED_CA_KEY per revoked key (D3); one SOURCE per
// source address; SUDO; ISSUED, the server's time in Unix milliseconds;
// URL, the canonical URL the host pulls from and enrolls at (D5, D7).
// The last line counts the others.
func DataLines(c *config.Config, t *config.Target, set *sshca.Set, issued time.Time) ([]byte, error) {
	if t == nil || t.SSH == nil {
		return nil, errors.New("hostsetup: not an SSH target")
	}
	if set == nil {
		return nil, errors.New("hostsetup: no CA keys")
	}
	trusted, signers := set.Trusted(), set.Signers()
	if len(trusted) == 0 || len(signers) == 0 {
		return nil, errors.New("hostsetup: no trusted user CA key or no signer")
	}
	if err := signersTrusted(trusted, signers); err != nil {
		return nil, err
	}
	u, err := config.HostURL(c.Server.CanonicalURL)
	if err != nil {
		return nil, fmt.Errorf("hostsetup: server.canonical_url %w", err)
	}
	ms, err := issuedMillis(issued)
	if err != nil {
		return nil, err
	}
	var b lines
	b.add("TARGET", t.Name)
	b.humans(t)
	for _, pk := range trusted {
		b.key("CA_KEY", pk)
	}
	for _, pk := range signers {
		b.key("SIGNER_KEY", pk)
	}
	for _, pk := range set.Revoked() {
		b.key("REVOKED_CA_KEY", pk)
	}
	for _, a := range c.SSH.SourceAddresses {
		p, err := config.ParseSourceAddress(a)
		if err != nil {
			return nil, err
		}
		b.add("SOURCE", p.String())
	}
	b.add("SUDO", strconv.FormatBool(t.SSH.Sudo))
	b.add("ISSUED", ms)
	b.add("URL", u)
	b.end()
	b.l = append(b.l, Terminator)
	return b.bytes()
}

// issuedMillis is ISSUED's form: Unix milliseconds, 13 digits without a
// leading zero (2001 to 2286), as the script checks it.
func issuedMillis(t time.Time) (string, error) {
	s := strconv.FormatInt(t.UnixMilli(), 10)
	if len(s) != 13 || s[0] == '0' || s[0] == '-' {
		return "", errors.New("hostsetup: the clock is outside the years ISSUED can express")
	}
	return s, nil
}

// signersTrusted checks D4's invariant: every signer is a trusted key.
// A host refuses data lines where it doesn't hold (D5, D13).
func signersTrusted(trusted, signers []ssh.PublicKey) error {
	for _, s := range signers {
		if !slices.ContainsFunc(trusted, func(p ssh.PublicKey) bool { return bytes.Equal(p.Marshal(), s.Marshal()) }) {
			return errors.New("hostsetup: a signer is not a trusted key")
		}
	}
	return nil
}

// SignatureLine separates a trust bundle's data lines from its signature
// (docs/08 D4).
const SignatureLine = "NYYRIKKI_SIGNATURE"

// TrustLines builds the data lines of target t's trust bundle (docs/08
// D4), in order: TARGET; one CA_KEY per trusted key; one SIGNER_KEY per
// signer; one REVOKED_CA_KEY per revoked key; one HUMAN per human; SUDO;
// ISSUED in Unix milliseconds; END counting the lines before it. Every
// value comes from config and the key files, never from the request.
func TrustLines(t *config.Target, set *sshca.Set, issued time.Time) ([]byte, error) {
	if t == nil || t.SSH == nil {
		return nil, errors.New("hostsetup: not an SSH target")
	}
	trusted, signers := set.Trusted(), set.Signers()
	if len(trusted) == 0 || len(signers) == 0 {
		return nil, errors.New("hostsetup: no trusted user CA key or no signer")
	}
	// SIGNER_KEY is always a subset of CA_KEY (docs/08 D4); a host
	// refuses a bundle where it isn't (D5).
	if err := signersTrusted(trusted, signers); err != nil {
		return nil, err
	}
	ms, err := issuedMillis(issued)
	if err != nil {
		return nil, err
	}
	var b lines
	b.add("TARGET", t.Name)
	for _, pk := range trusted {
		b.key("CA_KEY", pk)
	}
	for _, pk := range signers {
		b.key("SIGNER_KEY", pk)
	}
	for _, pk := range set.Revoked() {
		b.key("REVOKED_CA_KEY", pk)
	}
	b.humans(t)
	b.add("SUDO", strconv.FormatBool(t.SSH.Sudo))
	b.add("ISSUED", ms)
	b.end()
	return b.bytes()
}

// TrustBundle is target t's trust bundle (docs/08 D4): TrustLines, the
// SignatureLine, then an SSHSIG signature by user-ca in namespace
// nyyrikki-trust@v1 over every byte before the SignatureLine.
func TrustBundle(t *config.Target, set *sshca.Set, issued time.Time) ([]byte, error) {
	data, err := TrustLines(t, set, issued)
	if err != nil {
		return nil, err
	}
	// Only a SIGNER_KEY signs (D4): user-ca, which Load never returns
	// revoked, so it is always one.
	if !slices.ContainsFunc(set.Signers(), func(p ssh.PublicKey) bool {
		return bytes.Equal(p.Marshal(), set.UserCA.PublicKey().Marshal())
	}) {
		return nil, errors.New("hostsetup: user-ca is not a signer")
	}
	sig, err := sshca.SignSSHSIG(set.UserCA, sshca.TrustNamespace, data)
	if err != nil {
		return nil, err
	}
	out := append(data, SignatureLine+"\n"...)
	return append(out, sig...), nil
}

// Handler serves the setup script and the trust bundle.
type Handler struct {
	cfg   *config.Config
	body  []byte
	keys  *sshca.Keys
	audit audit.Appender
	log   *slog.Logger
	now   func() time.Time
}

// New returns the handler. body is the embedded script; it is checked
// here, so a broken build never serves. keys are the CA keys the trusted
// set is derived from, read on each fetch (docs/08 D1).
func New(cfg *config.Config, body []byte, keys *sshca.Keys, a audit.Appender, logger *slog.Logger) (*Handler, error) {
	if err := CheckBody(body); err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, errors.New("hostsetup: no CA keys")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{cfg: cfg, body: bytes.Clone(body), keys: keys, audit: a, log: logger, now: time.Now}, nil
}

// The paths under Prefix: /hosts/<target>/setup.sh (docs/07 D16) and
// /hosts/<target>/trust (docs/08 D4), with the same rules.
const (
	pathSetup = "setup.sh"
	pathTrust = "trust"
)

var pathPattern = regexp.MustCompile(`^/hosts/([^/]+)/(setup\.sh|trust)$`)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "only GET", http.StatusMethodNotAllowed)
		return
	}
	// docs/07 D16: the paths take no parameters; nothing in the request
	// may change what is served.
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "no query string", http.StatusBadRequest)
		return
	}
	m := pathPattern.FindStringSubmatch(r.URL.Path)
	var t *config.Target
	if m != nil && config.IsSlug(m[1]) {
		if tt, ok := h.cfg.TargetByName(m[1]); ok && tt.SSH != nil {
			t = tt
		}
	}
	if t == nil {
		// The same answer for an unknown, a Kubernetes and a malformed
		// name, on either path.
		http.NotFound(w, r)
		return
	}
	what := "setup script"
	if m[2] == pathTrust {
		what = "trust bundle"
	}
	// docs/08 D1, D3: a broken key file or a revoked user-ca serves
	// nothing and signs nothing, so no host is set up to trust, or pulls,
	// the wrong keys.
	set, err := h.keys.Load()
	if err != nil {
		detail := codes.DetailOf(err)
		if detail == "" {
			detail = "unavailable"
		}
		h.log.Error("the SSH CA keys are unavailable; "+what+" not served", "target", t.Name, "detail", detail)
		http.Error(w, "unavailable: "+detail, http.StatusServiceUnavailable)
		return
	}
	client, _, _ := net.SplitHostPort(r.RemoteAddr)
	var out [][]byte
	var rec audit.Record
	contentType := "text/x-shellscript; charset=utf-8"
	switch m[2] {
	case pathSetup:
		data, err := DataLines(h.cfg, t, set, h.now())
		if err != nil {
			h.log.Error("building the setup script's data lines failed", "target", t.Name, "err", err)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		out = [][]byte{h.body, data}
		rec = audit.Record{Kind: codes.KindHostSetupServed, Targets: []string{t.Name}, Detail: "client " + client}
	case pathTrust:
		issued := h.now()
		bundle, err := TrustBundle(t, set, issued)
		if err != nil {
			h.log.Error("building the trust bundle failed", "target", t.Name, "err", err)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		out = [][]byte{bundle}
		rec = audit.Record{Kind: codes.KindHostTrustServed, Targets: []string{t.Name},
			Detail: "client " + client + " issued " + strconv.FormatInt(issued.UnixMilli(), 10) +
				" ca_keys " + fingerprints(set.Trusted()) + " signer_keys " + fingerprints(set.Signers())}
		contentType = "text/plain; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	if err := h.audit.Append(ctx, rec); err != nil {
		// Every fetch is audited (docs/07 D16, docs/08 D4): no record,
		// nothing served.
		h.log.Error("audit write failed; "+what+" not served", "target", t.Name, "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", contentType)
	for _, b := range out {
		_, _ = w.Write(b)
	}
}

// fingerprints are the keys' SHA256 fingerprints, comma-separated.
func fingerprints(keys []ssh.PublicKey) string {
	fps := make([]string, len(keys))
	for i, k := range keys {
		fps[i] = ssh.FingerprintSHA256(k)
	}
	return strings.Join(fps, ",")
}
