package server_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	sshhost "github.com/Tuhis/Nyyrikki/deploy/ssh-host"
	"github.com/Tuhis/Nyyrikki/internal/api"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/server/servertest"
)

// sshHost is a minimal stand-in for a host's sshd: certificates from the
// user CA for nyyrikki:owner@db-1 log in to ny-owner, and "echo X" prints
// X. It records the commands it ran.
type sshHost struct {
	ln   net.Listener
	key  ssh.Signer
	mu   sync.Mutex
	cmds []string
	ids  []string
	// auths counts authentication attempts of any method.
	auths int
}

func startSSHHost(t *testing.T, ca ssh.PublicKey) *sshHost {
	t.Helper()
	return startSSHHostWith(t, ca, nil)
}

// startSSHHostWith is startSSHHost whose host key is presented as
// present(key) returns it, e.g. with a certificate.
func startSSHHostWith(t *testing.T, ca ssh.PublicKey, present func(ssh.Signer) ssh.Signer) *sshHost {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h := &sshHost{ln: ln, key: hk}
	cfg := &ssh.ServerConfig{AuthLogCallback: func(ssh.ConnMetadata, string, error) {
		h.mu.Lock()
		h.auths++
		h.mu.Unlock()
	}, PublicKeyCallback: func(md ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		cert, ok := k.(*ssh.Certificate)
		if !ok || md.User() != "ny-owner" {
			return nil, io.EOF
		}
		chk := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), ca.Marshal()) },
			SupportedCriticalOptions: []string{"source-address"}}
		if err := chk.CheckCert("nyyrikki:owner@db-1", cert); err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.ids = append(h.ids, cert.KeyId)
		h.mu.Unlock()
		return &ssh.Permissions{}, nil
	}}
	if present != nil {
		cfg.AddHostKey(present(hk))
	} else {
		cfg.AddHostKey(hk)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.serve(c, cfg)
		}
	}()
	return h
}

func (h *sshHost) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range creqs {
				if r.Type != "exec" {
					r.Reply(false, nil)
					continue
				}
				r.Reply(true, nil)
				n := binary.BigEndian.Uint32(r.Payload)
				cmd := string(r.Payload[4 : 4+n])
				h.mu.Lock()
				h.cmds = append(h.cmds, cmd)
				h.mu.Unlock()
				in, _ := io.ReadAll(ch)
				io.WriteString(ch, strings.TrimPrefix(cmd, "echo ")+"|"+string(in))
				ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				return
			}
		}()
	}
}

// withSSH adds the SSH target db-1, pinned to host, with a user CA key
// file written for it.
func withSSH(t *testing.T, host *sshHost, caPEM []byte, _ ssh.PublicKey) servertest.Option {
	file := filepath.Join(t.TempDir(), "user-ca")
	if err := os.WriteFile(file, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return func(c *config.Config) {
		// The CA's public key is derived from the key file (docs/08 D1).
		c.SSH = config.SSH{
			UserCAKeyFile:   file,
			SourceAddresses: []string{"127.0.0.1/32"},
			ConnectTimeout:  config.Duration(5e9),
		}
		c.Targets = append(c.Targets, config.Target{Name: "db-1", Humans: []string{"owner"}, SSH: &config.SSHTarget{
			Address:  host.ln.Addr().String(),
			HostKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.key.PublicKey())))},
			Sudo:     true,
		}})
	}
}

func newCA(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	return pem.EncodeToMemory(block), s.PublicKey()
}

// TestSSHRunMCP runs an SSH command end to end in process (docs/07 G10,
// and G7 short of a real host): list_targets says ssh, the approver sees
// the command, the account, the sudo marker and stdin's size only, and
// the command runs on the host as ny-owner with a certificate whose key
// ID names the run.
func TestSSHRunMCP(t *testing.T) {
	caPEM, caPub := newCA(t)
	host := startSSHHost(t, caPub)
	e := servertest.Start(t, withSSH(t, host, caPEM, caPub))
	cs := mcpAgent(t, e, "claude-code", "s1")

	var lt api.ListTargetsOut
	call(t, cs, api.ToolListTargets, map[string]any{}, &lt)
	found := false
	for _, tg := range lt.Targets {
		if tg.Name == "db-1" && tg.Type == codes.TypeSSH {
			found = true
		}
	}
	if !found {
		t.Fatalf("list_targets %+v", lt.Targets)
	}

	const marker = "stdin marker text"
	ch := runAsync(t, cs, api.RunIn{Target: "db-1", Args: []string{"echo", "hi"}, Stdin: marker, Reason: "check"})
	msg := e.Tap(t, 1, "Approve")
	for _, want := range []string{"<pre>echo hi</pre>", "<code>ny-owner</code> on <code>127.0.0.1:", "root via sudo",
		"stdin: 17 bytes", "stdin is not shown", "This host doesn't finish cuts"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("prompt lacks %q:\n%s", want, msg.Text)
		}
	}
	r := <-ch
	if r.eb != nil {
		t.Fatalf("run: %+v", r.eb)
	}
	if r.out.ExitCode == nil || *r.out.ExitCode != 0 || r.out.Stdout != "hi|"+marker {
		t.Fatalf("result %+v", r.out)
	}
	host.mu.Lock()
	cmds, ids := append([]string(nil), host.cmds...), append([]string(nil), host.ids...)
	host.mu.Unlock()
	if len(cmds) != 1 || cmds[0] != "echo hi" || len(ids) != 1 || ids[0] != "nyyrikki:"+r.out.RunID {
		t.Fatalf("host ran %v with key IDs %v", cmds, ids)
	}
	var started map[string]any
	for _, rec := range e.Audit.Records() {
		if rec["kind"] == codes.KindRunStarted {
			started = rec
		}
	}
	if started == nil || started["cert_serial"] == nil || started["run_as"].(map[string]any)["user"] != "ny-owner" {
		t.Fatalf("run_started %v", started)
	}
	// The marker on stdin is in no message and no audit record.
	for _, m := range e.Telegram.Sent() {
		if strings.Contains(m.Text, marker) {
			t.Fatal("stdin reached Telegram")
		}
	}
	for _, m := range e.Telegram.Edits() {
		if strings.Contains(m.Text, marker) {
			t.Fatal("stdin reached an edited message")
		}
	}
	if strings.Contains(e.Audit.String(), marker) {
		t.Fatal("stdin reached the audit log")
	}
}

// TestHostSetupServed covers docs/07 D16 on the live server: no token,
// the script as built in, 404 for a Kubernetes target, and the path
// absent when there is no SSH target.
func TestHostSetupServed(t *testing.T) {
	caPEM, caPub := newCA(t)
	host := startSSHHost(t, caPub)
	e := servertest.Start(t, withSSH(t, host, caPEM, caPub))
	resp, err := e.Client.Get(e.URL() + "/hosts/db-1/setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.HasPrefix(b, sshhost.Script) || !bytes.Contains(b, []byte("\nTARGET=db-1\nHUMAN=owner\n")) {
		t.Fatalf("status %d, body prefix ok %v", resp.StatusCode, bytes.HasPrefix(b, sshhost.Script))
	}
	for path, want := range map[string]int{"/hosts/prod/setup.sh": 404, "/hosts/db-1/setup.sh?x=1": 400} {
		resp, err := e.Client.Get(e.URL() + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
	}
	resp, err = e.Client.Post(e.URL()+"/hosts/db-1/setup.sh", "text/plain", nil)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST: %d", resp.StatusCode)
		}
	}

	plain := servertest.Start(t)
	resp, err = plain.Client.Get(plain.URL() + "/hosts/prod/setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("without SSH targets: %d", resp.StatusCode)
	}
}

// TestSSHHiddenTargetLooksUnknown covers docs/02 D5 for SSH (review round
// 1, finding 4): an SSH target the agent may not see answers exactly as a
// name that doesn't exist, so the shape of args can't probe for one.
func TestSSHHiddenTargetLooksUnknown(t *testing.T) {
	caPEM, caPub := newCA(t)
	host := startSSHHost(t, caPub)
	e := servertest.Start(t, withSSH(t, host, caPEM, caPub), func(c *config.Config) {
		c.Targets[len(c.Targets)-1].Clients = []string{"claude-code"}
	})
	cx := mcpAgent(t, e, "codex", "s2")
	for name, args := range map[string][]string{
		"login shell":  nil,
		"shell syntax": {"echo a && id"},
		"kubectl args": {"get", "pods"},
	} {
		in := api.RunIn{Args: args, Interactive: args == nil, Reason: "x"}
		var out api.RunOut
		in.Target = "db-1"
		hidden := call(t, cx, api.ToolRun, in, &out)
		in.Target = "no-such-target"
		unknown := call(t, cx, api.ToolRun, in, &out)
		if hidden == nil || unknown == nil || hidden.Code != unknown.Code || hidden.Message != unknown.Message {
			t.Errorf("%s: hidden %+v, unknown %+v", name, hidden, unknown)
		}
	}
	if n := len(e.Telegram.Sent()); n != 0 {
		t.Fatalf("%d prompts for a hidden target", n)
	}
}

// TestSSHGlobalHostCAs covers docs/08 D9 from the config file to the
// runner: a target with no pins and no host CAs of its own is verified
// by a certificate from the global ssh.host_cas, and a host whose key
// is in ssh.revoked_host_keys is refused with host_key_revoked, by the
// host check before anyone is asked (D10).
func TestSSHGlobalHostCAs(t *testing.T) {
	caPEM, caPub := newCA(t)
	_, hcaPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostCA, _ := ssh.NewSignerFromKey(hcaPriv)
	var hostKey ssh.PublicKey
	host := startSSHHostWith(t, caPub, func(hk ssh.Signer) ssh.Signer {
		hostKey = hk.PublicKey()
		c := &ssh.Certificate{Key: hk.PublicKey(), CertType: ssh.HostCert, KeyId: "db-1",
			ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity}
		if err := c.SignCert(rand.Reader, hostCA); err != nil {
			t.Fatal(err)
		}
		cs, err := ssh.NewCertSigner(c, hk)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	})
	authorized := func(k ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) }
	global := func(revoked ...ssh.PublicKey) servertest.Option {
		return func(c *config.Config) {
			db := c.Targets[len(c.Targets)-1].SSH
			db.HostKeys = nil
			c.SSH.HostCAs = []string{authorized(hostCA.PublicKey())}
			for _, k := range revoked {
				c.SSH.RevokedHostKeys = append(c.SSH.RevokedHostKeys, authorized(k))
			}
		}
	}
	for name, tc := range map[string]struct {
		revoked []ssh.PublicKey
		detail  string
	}{
		"accepted":        {nil, ""},
		"host revoked":    {[]ssh.PublicKey{hostKey}, "host_key_revoked"},
		"host CA revoked": {[]ssh.PublicKey{hostCA.PublicKey()}, "host_key_revoked"},
	} {
		t.Run(name, func(t *testing.T) {
			e := servertest.Start(t, withSSH(t, host, caPEM, caPub), global(tc.revoked...))
			cs := mcpAgent(t, e, "claude-code", "s1")
			ch := runAsync(t, cs, api.RunIn{Target: "db-1", Args: []string{"echo", "hi"}, Reason: "check"})
			if tc.detail == "" {
				e.Tap(t, 1, "Approve")
				r := <-ch
				if r.eb != nil || r.out.Stdout != "hi|" {
					t.Fatalf("run: %+v %+v", r.eb, r.out)
				}
				return
			}
			r := <-ch
			if r.eb == nil || r.eb.Code != codes.Unavailable || !hasDeny(e, tc.detail) {
				t.Fatalf("run: %+v; audit lacks a deny with %s", r.eb, tc.detail)
			}
			if n := len(e.Telegram.Sent()); n != 0 {
				t.Fatalf("%d prompts for a host that failed its check", n)
			}
		})
	}
}

// TestElevateGroupMCP covers docs/08 D11 (G10) through /mcp: list_targets
// returns each target's usable groups and, for SSH targets, sudo; elevate
// with a group name covers its members, which the message lists with the
// group's name; a group in run is refused like an unknown name.
func TestElevateGroupMCP(t *testing.T) {
	caPEM, caPub := newCA(t)
	host := startSSHHost(t, caPub)
	e := servertest.Start(t, withSSH(t, host, caPEM, caPub), func(c *config.Config) {
		c.Groups = []config.Group{
			{Name: "fleet", Targets: []string{"prod", "db-1"}},
			{Name: "claude", Targets: []string{"prod", "claude-only"}},
		}
	})
	cs := mcpAgent(t, e, "codex", "s1")
	var lt api.ListTargetsOut
	call(t, cs, api.ToolListTargets, map[string]any{}, &lt)
	info := map[string]api.TargetInfo{}
	for _, tg := range lt.Targets {
		info[tg.Name] = tg
	}
	// codex may not see claude-only, so "claude" is not offered on prod.
	if g := info["prod"].Groups; len(g) != 1 || g[0] != "fleet" || info["prod"].Sudo != nil {
		t.Fatalf("prod %+v", info["prod"])
	}
	if db := info["db-1"]; db.Sudo == nil || !*db.Sudo || len(db.Groups) != 1 || db.Groups[0] != "fleet" {
		t.Fatalf("db-1 %+v", db)
	}
	if g := info["lab"].Groups; len(g) != 0 {
		t.Fatalf("lab groups %v", g)
	}

	done := make(chan api.ElevateOut, 1)
	go func() {
		var out api.ElevateOut
		if eb := call(t, cs, api.ToolElevate, api.ElevateIn{Targets: []string{"fleet"}, Duration: "5m", Reason: "rollout"}, &out); eb != nil {
			t.Error(eb)
		}
		done <- out
	}()
	msg := e.Tap(t, 1, "Approve")
	for _, want := range []string{"<b>Targets:</b> <code>db-1</code>, <code>prod</code>\n", "<b>Group</b> <code>fleet</code> = <code>db-1</code>, <code>prod</code>"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("message lacks %q:\n%s", want, msg.Text)
		}
	}
	el := <-done
	if len(el.Targets) != 2 || el.Targets[0] != "db-1" || el.Targets[1] != "prod" {
		t.Fatalf("elevation targets %v", el.Targets)
	}
	var out api.RunOut
	if eb := call(t, cs, api.ToolRun, api.RunIn{Target: "db-1", Args: []string{"echo", "hi"}, Reason: "check", Elevation: el.Handle}, &out); eb != nil || out.CoveredBy != codes.CoveredElevation {
		t.Fatalf("db-1 under the group's elevation: %+v %+v", eb, out)
	}
	// A group the agent can't fully see, and a group in run.
	var eo api.ElevateOut
	if eb := call(t, cs, api.ToolElevate, api.ElevateIn{Targets: []string{"claude"}, Reason: "x"}, &eo); eb == nil || eb.Code != codes.InvalidRequest {
		t.Fatalf("group with a hidden member: %+v", eb)
	}
	grp := call(t, cs, api.ToolRun, api.RunIn{Target: "fleet", Args: []string{"get", "pods"}, Reason: "x"}, &out)
	unk := call(t, cs, api.ToolRun, api.RunIn{Target: "no-such", Args: []string{"get", "pods"}, Reason: "x"}, &out)
	if grp == nil || unk == nil || grp.Code != codes.TargetNotAllowed || grp.Message != unk.Message {
		t.Fatalf("group in run %+v, unknown %+v", grp, unk)
	}
	if n := len(e.Telegram.Sent()); n != 1 {
		t.Fatalf("%d prompts", n)
	}
	var rec map[string]any
	for _, r := range e.Audit.Records() {
		if r["kind"] == codes.KindDecision && r["decision"] == codes.Allow && r["elevation_id"] == el.ElevationID && r["run_id"] == nil {
			rec = r
		}
	}
	if rec == nil || fmt.Sprint(rec["targets"]) != "[db-1 prod]" || fmt.Sprint(rec["target_groups"]) != "[fleet]" {
		t.Fatalf("audit %v", rec)
	}
}

// TestSSHCAKeysFailClosed covers docs/08 D1 and D3 on the live server,
// for each way the CA keys can fail: a broken optional key file (here
// host-ca) and a revoked user-ca each make an SSH run unavailable, with
// the detail, denied by the host check before anyone is asked (D10)
// and audited, with no login on the host, and make setup.sh answer 503
// with that detail.
func TestSSHCAKeysFailClosed(t *testing.T) {
	for name, c := range map[string]struct {
		mod    func(t *testing.T, s *config.SSH, caPub ssh.PublicKey)
		detail string
	}{
		"broken host-ca": {func(t *testing.T, s *config.SSH, _ ssh.PublicKey) {
			s.HostCAKeyFile = filepath.Join(t.TempDir(), "host-ca")
			os.WriteFile(s.HostCAKeyFile, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nhalf written"), 0o600)
		}, "ca_key_unreadable"},
		"revoked user-ca": {func(_ *testing.T, s *config.SSH, caPub ssh.PublicKey) {
			s.RevokedUserCAKeys = []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caPub)))}
		}, "user_ca_revoked"},
	} {
		t.Run(name, func(t *testing.T) {
			caPEM, caPub := newCA(t)
			host := startSSHHost(t, caPub)
			e := servertest.Start(t, withSSH(t, host, caPEM, caPub), func(cfg *config.Config) { c.mod(t, &cfg.SSH, caPub) })

			resp, err := e.Client.Get(e.URL() + "/hosts/db-1/setup.sh")
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b), c.detail) || bytes.Contains(b, []byte("TARGET=")) {
				t.Fatalf("setup.sh: %d %q", resp.StatusCode, b)
			}

			cs := mcpAgent(t, e, "claude-code", "s1")
			ch := runAsync(t, cs, api.RunIn{Target: "db-1", Args: []string{"echo", "hi"}, Reason: "check"})
			r := <-ch
			if r.eb == nil || r.eb.Code != codes.Unavailable {
				t.Fatalf("run: %+v %+v", r.eb, r.out)
			}
			if n := len(e.Telegram.Sent()); n != 0 {
				t.Fatalf("%d prompts with broken CA keys", n)
			}
			host.mu.Lock()
			n := len(host.ids)
			host.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d logins on the host", n)
			}
			if !hasDeny(e, c.detail) {
				t.Fatalf("no deny with %s in the audit", c.detail)
			}
		})
	}
}

// TestSSHCAWarnsDerivedExtra covers docs/08 D14: an extra key in
// user_ca_public_keys equal to the derived user-ca is logged and audited
// once as a warning, and served once.
func TestSSHCAWarnsDerivedExtra(t *testing.T) {
	caPEM, caPub := newCA(t)
	host := startSSHHost(t, caPub)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caPub)))
	e := servertest.Start(t, withSSH(t, host, caPEM, caPub), func(c *config.Config) { c.SSH.UserCAPublicKeys = []string{line} })
	for range 2 {
		resp, err := e.Client.Get(e.URL() + "/hosts/db-1/setup.sh")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || bytes.Count(b, []byte("\nCA_KEY=")) != 1 {
			t.Fatalf("status %d, %d CA_KEY lines", resp.StatusCode, bytes.Count(b, []byte("\nCA_KEY=")))
		}
	}
	n := 0
	for _, rec := range e.Audit.Records() {
		if rec["kind"] == codes.KindSSHCAWarning {
			n++
			if !strings.Contains(rec["detail"].(string), ssh.FingerprintSHA256(caPub)) {
				t.Errorf("warning %v doesn't name the key", rec)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d ssh_ca_warning records, want 1", n)
	}
}

// hasDeny reports whether the audit holds a host_checked record and a
// denying decision, each with detail.
func hasDeny(e *servertest.Env, detail string) bool {
	checked, denied := false, false
	for _, rec := range e.Audit.Records() {
		if rec["detail"] != detail {
			continue
		}
		switch {
		case rec["kind"] == codes.KindHostChecked && rec["code"] == string(codes.Unavailable):
			checked = true
		case rec["kind"] == codes.KindDecision && rec["decision"] == codes.Deny:
			denied = true
		}
	}
	return checked && denied
}

// TestHostCheckMCP covers docs/08 D9 and D10 (G8, G9) from the config
// file to the message: with host-ca in the CA directory, a target with
// only an address is verified by the certificate Nyyrikki's host CA
// signed for it; the host check reads session_kill from that
// certificate (the config value is false) before the prompt, without
// authenticating; the run then logs in. An elevation naming that target
// and one whose host can't be reached shows the warning for the second
// only, and still asks.
func TestHostCheckMCP(t *testing.T) {
	caPEM, caPub := newCA(t)
	hostPEM, _ := newCA(t)
	hostSigner, err := ssh.ParsePrivateKey(hostPEM)
	if err != nil {
		t.Fatal(err)
	}
	host := startSSHHostWith(t, caPub, func(hk ssh.Signer) ssh.Signer {
		c := &ssh.Certificate{Key: hk.PublicKey(), CertType: ssh.HostCert, KeyId: "nyyrikki-host:db-1",
			ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity,
			Permissions: ssh.Permissions{Extensions: map[string]string{"session-kill@nyyrikki": ""}}}
		if err := c.SignCert(rand.Reader, hostSigner); err != nil {
			t.Fatal(err)
		}
		cs, err := ssh.NewCertSigner(c, hk)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	gone := ln.Addr().String()
	ln.Close()
	e := servertest.Start(t, withSSH(t, host, caPEM, caPub), func(c *config.Config) {
		c.SSH.HostCAKeyFile = filepath.Join(t.TempDir(), "host-ca")
		if err := os.WriteFile(c.SSH.HostCAKeyFile, hostPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		db := c.Targets[len(c.Targets)-1].SSH
		db.HostKeys = nil
		db.SessionKill = false
		c.Targets = append(c.Targets, config.Target{Name: "db-2", Humans: []string{"owner"}, SSH: &config.SSHTarget{Address: gone}})
	})
	cs := mcpAgent(t, e, "claude-code", "s1")
	ch := runAsync(t, cs, api.RunIn{Target: "db-1", Args: []string{"echo", "hi"}, Reason: "check"})
	msg := e.Telegram.WaitSent(t, 1)
	host.mu.Lock()
	auths := host.auths
	host.mu.Unlock()
	if auths != 0 {
		t.Fatalf("%d authentication attempts before the approval", auths)
	}
	if strings.Contains(msg[0].Text, "doesn't finish cuts") {
		t.Errorf("session_kill not read from the certificate:\n%s", msg[0].Text)
	}
	e.Tap(t, 1, "Approve")
	if r := <-ch; r.eb != nil || r.out.Stdout != "hi|" {
		t.Fatalf("run: %+v %+v", r.eb, r.out)
	}

	done := make(chan *api.ErrorBody, 1)
	go func() {
		var out api.ElevateOut
		done <- call(t, cs, api.ToolElevate, api.ElevateIn{Targets: []string{"db-1", "db-2"}, Duration: "5m", Reason: "x"}, &out)
	}()
	sent := e.Telegram.WaitSent(t, 2)
	text := sent[1].Text
	for _, want := range []string{
		"<code>db-2</code>: <code>ny-owner</code> on <code>" + gone + "</code>\n<b>not reachable now: treated as not finishing cuts</b>\n<b>This host doesn't finish cuts",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("elevation lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "doesn't finish cuts:") != 1 {
		t.Errorf("one warning, for db-2 only:\n%s", text)
	}
	e.Tap(t, 2, "Approve")
	if eb := <-done; eb != nil {
		t.Fatal(eb)
	}
	checked := 0
	for _, rec := range e.Audit.Records() {
		if rec["kind"] == codes.KindHostChecked {
			checked++
		}
	}
	if checked != 3 {
		t.Fatalf("%d host_checked records, want 3", checked)
	}
}
