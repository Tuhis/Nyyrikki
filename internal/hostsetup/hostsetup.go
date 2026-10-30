// Package hostsetup serves GET /hosts/<target>/setup.sh (docs/07 D16,
// OD3): the host setup script, byte for byte the file in the repo,
// followed by data lines built from config. It needs no token, since a
// host has none, and reads no secret.
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
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
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

// DataLines builds the data lines for target t (docs/07 D16): every
// value from config, each in a format config validation already checked
// and the script checks again. The last line counts the others.
func DataLines(c *config.Config, t *config.Target) ([]byte, error) {
	if t == nil || t.SSH == nil {
		return nil, errors.New("hostsetup: not an SSH target")
	}
	var lines []string
	add := func(name, value string) error {
		if strings.ContainsAny(value, "\n\r\x00") {
			return fmt.Errorf("hostsetup: %s holds a line break", name)
		}
		lines = append(lines, name+"="+value)
		return nil
	}
	if err := add("TARGET", t.Name); err != nil {
		return nil, err
	}
	for _, h := range t.Humans {
		if !config.IsSlug(h) || len(h) > config.MaxSSHHumanID {
			return nil, fmt.Errorf("hostsetup: human %q can't have an SSH account", h)
		}
		if err := add("HUMAN", h); err != nil {
			return nil, err
		}
	}
	for _, k := range c.SSH.UserCAPublicKeys {
		pk, err := config.ParseUserCAKey(k)
		if err != nil {
			return nil, err
		}
		// Type and base64 only: the comment is free text and stays out.
		if err := add("CA_KEY", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))); err != nil {
			return nil, err
		}
	}
	for _, a := range c.SSH.SourceAddresses {
		p, err := config.ParseSourceAddress(a)
		if err != nil {
			return nil, err
		}
		if err := add("SOURCE", p.String()); err != nil {
			return nil, err
		}
	}
	if err := add("SUDO", strconv.FormatBool(t.SSH.Sudo)); err != nil {
		return nil, err
	}
	n := len(lines)
	lines = append(lines, "END="+strconv.Itoa(n), Terminator)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// Handler serves the setup script.
type Handler struct {
	cfg   *config.Config
	body  []byte
	audit audit.Appender
	log   *slog.Logger
}

// New returns the handler. body is the embedded script; it is checked
// here, so a broken build never serves.
func New(cfg *config.Config, body []byte, a audit.Appender, logger *slog.Logger) (*Handler, error) {
	if err := CheckBody(body); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{cfg: cfg, body: bytes.Clone(body), audit: a, log: logger}, nil
}

var pathPattern = regexp.MustCompile(`^/hosts/([^/]+)/setup\.sh$`)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "only GET", http.StatusMethodNotAllowed)
		return
	}
	// docs/07 D16: the path takes no parameters; nothing in the request
	// may change what the script does.
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
		// name.
		http.NotFound(w, r)
		return
	}
	data, err := DataLines(h.cfg, t)
	if err != nil {
		h.log.Error("building the setup script's data lines failed", "target", t.Name, "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	client, _, _ := net.SplitHostPort(r.RemoteAddr)
	rec := audit.Record{Kind: codes.KindHostSetupServed, Targets: []string{t.Name}, Detail: "client " + client}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	if err := h.audit.Append(ctx, rec); err != nil {
		// Every fetch is audited (docs/07 D16): no record, no script.
		h.log.Error("audit write failed; setup script not served", "target", t.Name, "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(h.body)
	_, _ = w.Write(data)
}
