package server_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/hostsetup"
	"github.com/Tuhis/Nyyrikki/internal/server/servertest"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// enrollSetup is an unpinned SSH target db-1 at addr, with user-ca and
// host-ca key files, and the token key a `nyyrikkid enroll-token` in the
// same pod would derive.
type enrollSetup struct {
	caPEM, hostPEM []byte
	files          sshca.Files
}

func newEnrollSetup(t *testing.T) *enrollSetup {
	t.Helper()
	caPEM, _ := newCA(t)
	hostPEM, _ := newCA(t)
	dir := t.TempDir()
	s := &enrollSetup{caPEM: caPEM, hostPEM: hostPEM,
		files: sshca.Files{UserCA: filepath.Join(dir, "user-ca"), HostCA: filepath.Join(dir, "host-ca")}}
	os.WriteFile(s.files.UserCA, caPEM, 0o600)
	os.WriteFile(s.files.HostCA, hostPEM, 0o600)
	return s
}

func (s *enrollSetup) option(addr string) servertest.Option {
	return func(c *config.Config) {
		c.SSH = config.SSH{UserCAKeyFile: s.files.UserCA, HostCAKeyFile: s.files.HostCA,
			SourceAddresses: []string{"127.0.0.1/32"}, ConnectTimeout: config.Duration(5 * time.Second),
			HostCertValidity: config.Duration(config.DefaultHostCertValidity)}
		c.Targets = append(c.Targets, config.Target{Name: "db-1", Humans: []string{"owner"}, SSH: &config.SSHTarget{Address: addr, Sudo: true}})
	}
}

func (s *enrollSetup) token(t *testing.T, target string) string {
	t.Helper()
	set, err := sshca.New(sshca.Options{Files: s.files}).Load()
	if err != nil {
		t.Fatal(err)
	}
	key, err := set.EnrollTokenKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := hostsetup.MintToken(key, target, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type httpResult struct {
	status int
	body   string
}

func postAsync(t *testing.T, e *servertest.Env, path, token, body string) chan httpResult {
	t.Helper()
	ch := make(chan httpResult, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, e.URL()+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", hostsetup.AuthScheme+" "+token)
		}
		resp, err := e.Client.Do(req)
		if err != nil {
			ch <- httpResult{status: -1, body: err.Error()}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ch <- httpResult{resp.StatusCode, string(b)}
	}()
	return ch
}

func waitHTTP(t *testing.T, ch chan httpResult) httpResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("no answer")
		return httpResult{}
	}
}

// TestEnrollEndToEnd covers docs/08 G7 in process, from the token to the
// check: the token minted from host-ca as enroll-token mints it starts
// one enrollment; the approver sees the fingerprint, the address, sudo
// and session_kill; the approval returns a certificate with exactly
// D8's fields; the host then presents it, and the check logs in as the
// target's account without opening a channel, and answers OK.
func TestEnrollEndToEnd(t *testing.T) {
	s := newEnrollSetup(t)
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewSignerFromKey(hostPriv)
	// The host's sshd, presenting the certificate once it has one.
	var presented ssh.Signer
	caPub, _ := ssh.ParsePrivateKey(s.caPEM)
	ready := make(chan struct{})
	host := startSSHHostWith(t, caPub.PublicKey(), func(ssh.Signer) ssh.Signer { return &lateSigner{ready: ready, s: &presented} })
	e := servertest.Start(t, s.option(host.ln.Addr().String()))
	tok := s.token(t, "db-1")

	body := fmt.Sprintf("HOST_KEY=%s\nSESSION_KILL=true\nEND=2\n", sshca.AuthorizedKey(hostKey.PublicKey()))
	ch := postAsync(t, e, "/hosts/db-1/enroll", tok, body)
	msg := e.Telegram.WaitSent(t, 1)[0]
	for _, want := range []string{
		"<b>Enroll SSH host:</b> <code>db-1</code>",
		"<code>ED25519 " + ssh.FingerprintSHA256(hostKey.PublicKey()) + "</code>",
		"<b>Address:</b> <code>" + host.ln.Addr().String() + "</code>",
		"<b>root via sudo</b> · finishes cuts (as the host reports)",
		"Asked from <code>127.0.0.1</code>",
	} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("prompt lacks %q:\n%s", want, msg.Text)
		}
	}
	// The same token can't start a second enrollment while this one waits.
	if r := waitHTTP(t, postAsync(t, e, "/hosts/db-1/enroll", tok, body)); r.status != http.StatusUnauthorized {
		t.Fatalf("a second enrollment: %+v", r)
	}
	start := time.Now()
	e.Tap(t, 1, "Approve")
	r := waitHTTP(t, ch)
	if r.status != 200 {
		t.Fatalf("enroll: %+v", r)
	}
	line := strings.TrimSuffix(strings.TrimPrefix(r.body, "HOST_CERT="), "\nEND=1\n")
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("response %q: %v", r.body, err)
	}
	cert := pk.(*ssh.Certificate)
	hostCA, _ := ssh.ParsePrivateKey(s.hostPEM)
	validity := uint64(config.DefaultHostCertValidity / time.Second)
	if cert.CertType != ssh.HostCert || !bytes.Equal(cert.Key.Marshal(), hostKey.PublicKey().Marshal()) ||
		len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "127.0.0.1" || cert.KeyId != "nyyrikki-host:db-1" ||
		!bytes.Equal(cert.SignatureKey.Marshal(), hostCA.PublicKey().Marshal()) || len(cert.CriticalOptions) != 0 ||
		len(cert.Extensions) != 1 || cert.Extensions["session-kill@nyyrikki"] != "" ||
		cert.ValidBefore-cert.ValidAfter != validity+300 || int64(cert.ValidAfter) > start.Add(-5*time.Minute).Unix()+2 {
		t.Fatalf("certificate %+v", cert)
	}
	if !strings.Contains(e.Telegram.WaitSent(t, 1)[0].Text, "Enroll") {
		t.Fatal("prompt lost")
	}

	// The host installs it; the check finds it and logs in.
	cs, err := ssh.NewCertSigner(cert, hostKey)
	if err != nil {
		t.Fatal(err)
	}
	presented = cs
	close(ready)
	r = waitHTTP(t, postAsync(t, e, "/hosts/db-1/enroll/check", tok, ""))
	if r.status != 200 || r.body != "OK=ny-owner\nEND=1\n" {
		t.Fatalf("check: %+v", r)
	}
	host.mu.Lock()
	cmds, ids := len(host.cmds), host.ids
	host.mu.Unlock()
	if cmds != 0 || len(ids) != 1 || !strings.HasPrefix(ids[0], "nyyrikki:chk_") {
		t.Fatalf("the check ran %d commands, logged in as %v", cmds, ids)
	}
	// Used up.
	if r := waitHTTP(t, postAsync(t, e, "/hosts/db-1/enroll/check", tok, "")); r.status != http.StatusUnauthorized {
		t.Fatalf("a second check: %+v", r)
	}

	kinds := map[string]int{}
	var serial string
	for _, rec := range e.Audit.Records() {
		kinds[rec["kind"].(string)]++
		if rec["kind"] == codes.KindHostCertIssued {
			serial, _ = rec["cert_serial"].(string)
			if rec["host_key"] != ssh.FingerprintSHA256(hostKey.PublicKey()) {
				t.Errorf("host_cert_issued %v", rec)
			}
		}
	}
	for _, k := range []string{codes.KindHostEnrollRequested, codes.KindHostEnrollApproved, codes.KindHostCertIssued} {
		if kinds[k] != 1 {
			t.Errorf("%d %s records", kinds[k], k)
		}
	}
	// The probe's certificate, the check's result, and the refused
	// second check.
	if serial != fmt.Sprint(cert.Serial) || kinds[codes.KindHostEnrollChecked] != 3 {
		t.Errorf("serial %q, checked %d", serial, kinds[codes.KindHostEnrollChecked])
	}
	// The token appears nowhere in the audit stream.
	if strings.Contains(e.Audit.String(), strings.TrimPrefix(tok, hostsetup.TokenPrefix)[:24]) {
		t.Fatal("the token reached the audit log")
	}
}

// lateSigner presents s once ready is closed; before that, it blocks the
// handshake: the host has no certificate until it installed one.
type lateSigner struct {
	ready chan struct{}
	s     *ssh.Signer
}

func (l *lateSigner) PublicKey() ssh.PublicKey {
	<-l.ready
	return (*l.s).PublicKey()
}

func (l *lateSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	<-l.ready
	return (*l.s).Sign(r, data)
}

// TestEnrollDeniedEndToEnd covers docs/08 G7: a denial returns no
// certificate, audits it, and the token can't be used for the check.
func TestEnrollDeniedEndToEnd(t *testing.T) {
	s := newEnrollSetup(t)
	e := servertest.Start(t, s.option("127.0.0.1:1"))
	tok := s.token(t, "db-1")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	ch := postAsync(t, e, "/hosts/db-1/enroll", tok, fmt.Sprintf("HOST_KEY=%s\nSESSION_KILL=false\nEND=2\n", sshca.AuthorizedKey(hk.PublicKey())))
	e.Tap(t, 1, "Deny")
	if r := waitHTTP(t, ch); r.status != http.StatusForbidden || strings.Contains(r.body, "CERT") {
		t.Fatalf("denied: %+v", r)
	}
	if r := waitHTTP(t, postAsync(t, e, "/hosts/db-1/enroll/check", tok, "")); r.status != http.StatusUnauthorized {
		t.Fatalf("check after a denial: %+v", r)
	}
	var denied int
	for _, rec := range e.Audit.Records() {
		if rec["kind"] == codes.KindHostCertIssued {
			t.Fatal("a certificate was issued")
		}
		if rec["kind"] == codes.KindHostEnrollDenied && rec["code"] == string(codes.Denied) {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("%d denials audited", denied)
	}
}

// TestHostsPathList covers docs/01 D10, revised by docs/08 (D4, D7):
// besides /mcp, /stream and the metadata, :8443 serves only GET
// /hosts/<target>/setup.sh and POST /hosts/<target>/enroll and
// /enroll/check. Every other path and method under /hosts/ is refused.
func TestHostsPathList(t *testing.T) {
	s := newEnrollSetup(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	e := servertest.Start(t, s.option(addr))
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/hosts/db-1/setup.sh", 200},
		{http.MethodPost, "/hosts/db-1/enroll", http.StatusUnauthorized},
		{http.MethodPost, "/hosts/db-1/enroll/check", http.StatusUnauthorized},
		{http.MethodGet, "/hosts/db-1/enroll", http.StatusNotFound},
		{http.MethodGet, "/hosts/db-1/enroll/check", http.StatusNotFound},
		{http.MethodPut, "/hosts/db-1/enroll", http.StatusMethodNotAllowed},
		{http.MethodPost, "/hosts/db-1/setup.sh", http.StatusMethodNotAllowed},
		{http.MethodPost, "/hosts/db-1/enroll/other", http.StatusMethodNotAllowed},
		{http.MethodPost, "/hosts/db-1", http.StatusMethodNotAllowed},
		{http.MethodGet, "/hosts/", http.StatusNotFound},
		{http.MethodGet, "/enroll", http.StatusNotFound},
		{http.MethodPost, "/hosts/prod/enroll", http.StatusNotFound},
	} {
		req, _ := http.NewRequest(c.method, e.URL()+c.path, nil)
		resp, err := e.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, resp.StatusCode, c.want)
		}
	}
}

// TestEnrollTelegramDown: the prompt can't be sent, so the enrollment is
// refused, with no certificate (fail closed).
func TestEnrollTelegramDown(t *testing.T) {
	s := newEnrollSetup(t)
	e := servertest.Start(t, s.option("127.0.0.1:1"))
	e.Telegram.FailNext("sendMessage", http.StatusInternalServerError)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	r := waitHTTP(t, postAsync(t, e, "/hosts/db-1/enroll", s.token(t, "db-1"), fmt.Sprintf("HOST_KEY=%s\nSESSION_KILL=true\nEND=2\n", sshca.AuthorizedKey(hk.PublicKey()))))
	if r.status != http.StatusServiceUnavailable || strings.Contains(r.body, "CERT") {
		t.Fatalf("telegram down: %+v", r)
	}
	for _, rec := range e.Audit.Records() {
		if rec["kind"] == codes.KindHostCertIssued {
			t.Fatal("a certificate was issued")
		}
	}
}
