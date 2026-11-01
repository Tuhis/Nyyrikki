//go:build sshhost

package sshhost_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

const (
	enrollToken  = "nye1.not-a-real-token"
	hostCertPath = "/etc/ssh/nyyrikki/ssh_host_ed25519_key-cert.pub"
)

// hostCert signs a host certificate for the container's ed25519 host key
// with a host CA of the test's own, as Nyyrikki's enrollment does
// (docs/08 D8), and returns the answer the enroll endpoint gives
// (docs/08 §10 SE5) and the host CA's public key line.
func (h *host) hostCert(t *testing.T) (answer, caLine string) {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.must("cat /etc/ssh/ssh_host_ed25519_key.pub")))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, n := range []string{"user-ca", "host-ca"} {
		b, _, err := sshca.GenerateKey("")
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, n), b, 0o600)
	}
	set, err := sshca.New(sshca.Options{Files: sshca.Files{UserCA: filepath.Join(dir, "user-ca"), HostCA: filepath.Join(dir, "host-ca")}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	c, err := set.SignHostCert(sshca.HostCert{Key: pub, Target: "db-1", Host: "127.0.0.1", Validity: 24 * time.Hour, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return "HOST_CERT=" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))) + "\nEND=1\n", sshca.AuthorizedKey(set.HostCA.PublicKey())
}

// verifiedLogin logs in as ny-owner trusting only certificates of the
// host CA caLine for 127.0.0.1, as Nyyrikki verifies an enrolled host
// (docs/08 D9): the host must present its certificate.
func (h *host) verifiedLogin(caLine string) (string, int) {
	h.t.Helper()
	h.put("/root/kh", "@cert-authority 127.0.0.1 "+caLine+"\n")
	h.sign("nyyrikki:owner@db-1")
	o, e, code := h.exec("ssh -n -i /root/u -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes "+
		"-o UserKnownHostsFile=/root/kh -o HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com -o ConnectTimeout=10 -o LogLevel=ERROR ny-owner@127.0.0.1 id -un", "")
	return o + e, code
}

// certBeforeMatch reports whether the drop-in names the host certificate
// among its global keywords, before any Match block (docs/08 D13).
func (h *host) certBeforeMatch() bool {
	h.t.Helper()
	d := h.must("cat /etc/ssh/sshd_config.d/50-nyyrikki.conf")
	i := strings.Index(d, "\nHostCertificate "+hostCertPath+"\n")
	m := strings.Index(d, "\nMatch ")
	return i >= 0 && (m < 0 || i < m)
}

// background runs the served script in a session of its own, as a
// terminal would, so that a test can send it what Ctrl-C sends. It is
// started with docker exec -d: a shell's "&" would start it with SIGINT
// ignored, which no trap can undo. Output and exit code go to
// /root/bg.out and /root/bg.rc.
func (h *host) background(script string, args ...string) {
	h.t.Helper()
	h.put("/root/setup.sh", script)
	full := "sh /root/setup.sh"
	for _, a := range args {
		full += " " + shellQuote(a)
	}
	h.must("rm -f /root/bg.out /root/bg.rc /root/bg.pid")
	// A handler, not an ignored signal: this shell lives on to record the
	// exit code, and the script, which execs, gets the default to trap.
	inner := "trap : INT; echo $$ > /root/bg.pid; " + full + " > /root/bg.out 2>&1; echo $? > /root/bg.rc"
	if out, err := exec.Command("docker", "exec", "-d", h.id, "setsid", "sh", "-c", inner).CombinedOutput(); err != nil {
		h.t.Fatalf("docker exec -d: %v\n%s", err, out)
	}
	waitFor(h.t, 30*time.Second, "the script to start", func() bool { return h.exists("/root/bg.pid") })
}

func (h *host) waitOutput(want string) string {
	h.t.Helper()
	var out string
	waitFor(h.t, 60*time.Second, "output "+want, func() bool {
		out, _, _ = h.exec("cat /root/bg.out", "")
		return strings.Contains(out, want)
	})
	return out
}

func (h *host) waitRC() (string, string) {
	h.t.Helper()
	var rc string
	waitFor(h.t, 120*time.Second, "the script to end", func() bool {
		rc, _, _ = h.exec("cat /root/bg.rc 2>/dev/null", "")
		return rc != ""
	})
	out, _, _ := h.exec("cat /root/bg.out", "")
	return strings.TrimSpace(rc), out
}

// TestEnroll covers the setup's side of docs/08 D7 and G13: a failed
// enrollment leaves the host set up and fail-closed, with no
// certificate; a failed sshd -t after installing the certificate removes
// it again; the fingerprint and "approve only if" are printed before the
// script waits; the request carries the token and D7's body; the
// certificate is installed with HostCertificate before any Match block,
// and the host then verifies by it; a re-run without --enroll keeps it
// so; a refused check prints the hint and exits non-zero; Ctrl-C while
// waiting, and a SIGKILL after installing the certificate, leave the host
// fail-closed.
func TestEnroll(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		h.startFake()
		v := h.values("owner")
		script := served(t, v.lines(), afterTerminator)
		enroll := []string{"--cacert", "/root/server-ca.pem", "--enroll", enrollToken}
		answer, caLine := h.hostCert(t)
		pub := strings.Fields(h.must("cat /etc/ssh/ssh_host_ed25519_key.pub"))
		hk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(strings.Join(pub[:2], " ")))
		fp := ssh.FingerprintSHA256(hk)

		// Denied: the host is set up, without a certificate.
		h.answer("enroll", 403, []byte("Forbidden: denied: approver_denied\n"))
		r := h.run(script, enroll...)
		if r.code == 0 || !strings.Contains(r.err, "approver_denied") || !strings.Contains(r.err, "Run the setup again with a new token") {
			t.Fatalf("a denied enrollment: %s", r)
		}
		if h.exists(hostCertPath) || strings.Contains(h.must("cat /etc/ssh/sshd_config.d/50-nyyrikki.conf"), "HostCertificate") {
			t.Fatal("a denied enrollment left a certificate")
		}
		if out, code := h.certLogin("owner", "db-1", "sudo -n id -u"); code != 0 || out != "0\n" {
			t.Fatalf("after a denied enrollment the host isn't set up: exit %d %q", code, out)
		}
		if out, code := h.verifiedLogin(caLine); code == 0 {
			t.Fatalf("an unenrolled host passed verification by certificate: %q", out)
		}
		if h.exists("/root/after-terminator") {
			t.Fatal("code after the terminator ran")
		}

		// sshd -t refuses the drop-in with the certificate: both go again.
		h.answer("enroll", 0, []byte(answer))
		h.answer("check", 0, []byte("OK=ny-owner\nEND=1\n"))
		h.installShim("sshd", "-t", "fail", 2, false)
		r = h.run(script, enroll...)
		if !h.shimHit("sshd") {
			t.Fatalf("the sshd shim never fired: %s", r)
		}
		h.clearShim("sshd")
		if r.code == 0 || !strings.Contains(r.err, "removing the host certificate") {
			t.Fatalf("a failed sshd -t: %s", r)
		}
		if h.exists(hostCertPath) || strings.Contains(h.must("cat /etc/ssh/sshd_config.d/50-nyyrikki.conf"), "HostCertificate") {
			t.Fatal("a certificate sshd refused was left")
		}
		if out, code := h.certLogin("owner", "db-1", "id -un"); code != 0 {
			t.Fatalf("after removing the certificate: exit %d %q", code, out)
		}

		// Enrolled: the fingerprint is printed before the script waits.
		h.must(": > /srv/ny/enroll.hold")
		h.background(script, enroll...)
		out := h.waitOutput("Waiting for the approval")
		if !strings.Contains(out, "ED25519 "+fp) || !strings.Contains(out, "Approve on Telegram only if the message shows this same fingerprint") {
			t.Fatalf("the fingerprint isn't printed before waiting:\n%s", out)
		}
		if rc, _, _ := h.exec("cat /root/bg.rc 2>/dev/null", ""); rc != "" {
			t.Fatal("the script didn't wait for the approval")
		}
		h.must("rm /srv/ny/enroll.hold")
		rc, out := h.waitRC()
		if rc != "0" || !strings.Contains(out, "check: ny-owner: ok") || !strings.Contains(out, "Enrolled") {
			t.Fatalf("enrollment: exit %s\n%s", rc, out)
		}
		if got := h.must("cat /srv/ny/enroll.auth"); got != "Nyyrikki-Enroll "+enrollToken {
			t.Fatalf("the enrollment's Authorization: %q", got)
		}
		if got := h.must("cat /srv/ny/enroll.body"); got != "HOST_KEY="+strings.Join(pub[:2], " ")+"\nSESSION_KILL=false\nEND=2\n" {
			t.Fatalf("the enrollment's body: %q", got)
		}
		if got := h.must("cat /srv/ny/check.auth"); got != "Nyyrikki-Enroll "+enrollToken {
			t.Fatalf("the check's Authorization: %q", got)
		}
		if strings.Contains(out, enrollToken) {
			t.Fatal("the script printed the token")
		}
		if !h.certBeforeMatch() {
			t.Fatalf("HostCertificate isn't among the global keywords:\n%s", h.must("cat /etc/ssh/sshd_config.d/50-nyyrikki.conf"))
		}
		if got := h.must("stat -c '%a %u' " + hostCertPath); got != "644 0\n" {
			t.Fatalf("the certificate's mode: %s", got)
		}
		if out, code := h.verifiedLogin(caLine); code != 0 || out != "ny-owner\n" {
			t.Fatalf("the enrolled host doesn't verify by its certificate: exit %d %q", code, out)
		}

		// A re-run without --enroll keeps it, and is idempotent.
		h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		once := h.snapshot()
		h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		h.sameAs(once, "a re-run of an enrolled host")
		if !h.certBeforeMatch() {
			t.Fatal("a re-run without --enroll lost HostCertificate")
		}
		if out, code := h.verifiedLogin(caLine); code != 0 {
			t.Fatalf("after a re-run, the host doesn't verify: %q", out)
		}
		st := h.setup(v, "--status")
		if st.code != 0 || !strings.Contains(st.out, "nyyrikki-host:db-1") {
			t.Fatalf("--status doesn't show the certificate: %s", st)
		}

		// A refused check: the certificate stays, the hint is printed.
		h.answer("check", 0, []byte("REFUSED=ny-owner\nHINT=the host refused Nyyrikki's login as ny-owner; check that ssh.source_addresses holds the address Nyyrikki connects from\nEND=2\n"))
		r = h.run(script, enroll...)
		if r.code == 0 || !strings.Contains(r.out, "check: ny-owner: refused") || !strings.Contains(r.out, "hint: the host refused") {
			t.Fatalf("a refused check: %s", r)
		}
		if !h.exists(hostCertPath) || !h.certBeforeMatch() {
			t.Fatal("a refused check removed the certificate")
		}

		// A re-enrollment whose new certificate sshd refuses puts the
		// earlier, working one back instead of deleting it (round 1 of #50).
		h.answer("check", 0, []byte("OK=ny-owner\nEND=1\n"))
		prev := h.must("cat " + hostCertPath)
		h.installShim("sshd", "-t", "fail", 2, false)
		r = h.run(script, enroll...)
		if !h.shimHit("sshd") {
			t.Fatalf("the sshd shim never fired: %s", r)
		}
		h.clearShim("sshd")
		if r.code == 0 || !strings.Contains(r.err, "restoring the earlier host certificate") {
			t.Fatalf("a failed re-enrollment: %s", r)
		}
		if !h.exists(hostCertPath) || h.must("cat "+hostCertPath) != prev || !h.certBeforeMatch() {
			t.Fatal("a failed re-enrollment didn't put the earlier certificate back")
		}
		if out, code := h.verifiedLogin(caLine); code != 0 {
			t.Fatalf("after a failed re-enrollment, the host doesn't verify: %q", out)
		}

		// Ctrl-C while waiting: no certificate change, the host stays set up.
		h.answer("check", 0, []byte("OK=ny-owner\nEND=1\n"))
		before := h.snapshot()
		h.must(": > /srv/ny/enroll.hold")
		h.background(script, enroll...)
		h.waitOutput("Waiting for the approval")
		// Ctrl-C: INT to the whole process group (dash's kill needs the
		// "--", BusyBox's refuses it).
		h.must(`p=$(cat /root/bg.pid); kill -s INT -- "-$p" 2>/dev/null || kill -s INT "-$p"`)
		rc, out = h.waitRC()
		h.must("rm -f /srv/ny/enroll.hold")
		if rc == "0" || !strings.Contains(out, "interrupted by SIGINT") || !strings.Contains(out, "The enrollment failed") {
			t.Fatalf("Ctrl-C while waiting: exit %s\n%s", rc, out)
		}
		h.sameAs(before, "Ctrl-C while waiting for the approval")

		// SIGKILL after the certificate is installed, before sshd checks
		// it: fail-closed, and a re-run brings the host to a defined state.
		h.must("rm -f " + hostCertPath)
		h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		h.installShim("sshd", "-t", "KILL", 2, false)
		r = h.run(script, enroll...)
		if !h.shimHit("sshd") || r.code == 0 {
			t.Fatalf("the kill: %s", r)
		}
		h.clearShim("sshd")
		h.assertFailsClosed()
		h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		if out, code := h.verifiedLogin(caLine); code != 0 {
			t.Fatalf("after the kill and a re-run: %q", out)
		}
		if out, code := h.certLogin("owner", "db-1", "sudo -n id -u"); code != 0 || out != "0\n" {
			t.Fatalf("after the kill and a re-run: exit %d %q", code, out)
		}
	})
}
