//go:build sshhost

package sshhost_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/hostsetup"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// The fake Nyyrikki (fakeserver/) runs inside each container that needs
// one, at fakeURL, with a TLS certificate from a CA of the test's own,
// which the container has as /root/server-ca.pem.
var (
	fakeOnce sync.Once
	fakeDir  string
	fakeErr  error
)

func buildFake(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		fakeDir, fakeErr = os.MkdirTemp("", "nyyrikki-sshhost-fake")
		if fakeErr != nil {
			return
		}
		cmd := exec.Command("go", "build", "-tags", "sshhost", "-o", filepath.Join(fakeDir, "fakeserver"), "./fakeserver")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
		if out, err := cmd.CombinedOutput(); err != nil {
			fakeErr = fmt.Errorf("go build fakeserver: %v\n%s", err, out)
			return
		}
		fakeErr = writeTLS(fakeDir)
	})
	if fakeErr != nil {
		t.Fatal(fakeErr)
	}
	return fakeDir
}

// writeTLS writes ca.pem, and tls.crt and tls.key for 127.0.0.1.
func writeTLS(dir string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nyyrikki-sshhost-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	for name, b := range map[string][]byte{
		"ca.pem":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// startFake runs the fake Nyyrikki in the container, answering from
// /srv/ny, and waits for it.
func (h *host) startFake() {
	h.t.Helper()
	dir := buildFake(h.t)
	h.must("mkdir -p /nyfake /srv/ny")
	for _, f := range []string{"fakeserver", "tls.crt", "tls.key", "ca.pem"} {
		if out, err := exec.Command("docker", "cp", filepath.Join(dir, f), h.id+":/nyfake/"+f).CombinedOutput(); err != nil {
			h.t.Fatalf("docker cp %s: %v\n%s", f, err, out)
		}
	}
	h.must("cp /nyfake/ca.pem /root/server-ca.pem && chmod 0755 /nyfake/fakeserver")
	if out, err := exec.Command("docker", "exec", "-d", h.id, "/nyfake/fakeserver",
		"-cert", "/nyfake/tls.crt", "-key", "/nyfake/tls.key", "-dir", "/srv/ny").CombinedOutput(); err != nil {
		h.t.Fatalf("start fakeserver: %v\n%s", err, out)
	}
	for i := 0; ; i++ {
		o, _, _ := h.exec("curl -s -o /dev/null -w '%{http_code}' --cacert /root/server-ca.pem "+fakeURL+"/hosts/db-1/trust", "")
		if o == "404" || o == "200" {
			return
		}
		if i > 50 {
			h.t.Fatalf("the fake server didn't come up: %q", o)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// answer sets what the fake server answers: name is trust, enroll or
// check; status 0 leaves the default (200).
func (h *host) answer(name string, status int, body []byte) {
	h.t.Helper()
	h.put("/srv/ny/"+name+".answer", string(body))
	if status != 0 {
		h.put("/srv/ny/"+name+".status", strconv.Itoa(status))
	} else {
		h.must("rm -f /srv/ny/" + name + ".status")
	}
}

// recordLogger replaces logger with a recorder of its arguments in
// /root/logger.log: a container has no syslog to read them back from.
func (h *host) recordLogger() {
	h.t.Helper()
	h.must(`p=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v logger) && rm -f "$p" && printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> /root/logger.log\n' > "$p" && chmod 0755 "$p" && : > /root/logger.log`)
}

func (h *host) logged() string {
	h.t.Helper()
	o, _, _ := h.exec("cat /root/logger.log", "")
	return o
}

// caKey is a user CA key made in the test, with its private half in the
// container at path, for ssh-keygen -s.
type caKey struct {
	signer ssh.Signer
	line   string // "ssh-ed25519 <base64>"
	pem    []byte
	path   string
}

func (h *host) newCAKey(name string) caKey {
	h.t.Helper()
	b, pub, err := sshca.GenerateKey("")
	if err != nil {
		h.t.Fatal(err)
	}
	s, err := sshca.ParsePrivateKey(b)
	if err != nil {
		h.t.Fatal(err)
	}
	k := caKey{signer: s, line: sshca.AuthorizedKey(pub), pem: b, path: "/root/ca-" + name}
	h.put(k.path, string(b))
	h.put(k.path+".pub", k.line+"\n")
	h.must("chmod 0600 " + k.path)
	return k
}

// defaultCA is the host's own test CA (/root/ca) as a caKey.
func (h *host) defaultCA() caKey {
	h.t.Helper()
	b := []byte(h.must("cat /root/ca"))
	s, err := sshca.ParsePrivateKey(b)
	if err != nil {
		h.t.Fatalf("/root/ca: %v", err)
	}
	return caKey{signer: s, line: sshca.AuthorizedKey(s.PublicKey()), pem: b, path: "/root/ca"}
}

// loginWith signs a certificate for human@db-1 with k and runs cmd as
// ny-human.
func (h *host) loginWith(k caKey, human, cmd string) (string, int) {
	h.t.Helper()
	h.must(fmt.Sprintf("rm -f /root/u-cert.pub && ssh-keygen -q -s %s -I nyyrikki:run-1 -z 1 -n nyyrikki:%s@db-1 -V -1m:+2m /root/u.pub", k.path, human))
	return h.ssh("ny-"+human, "/root/u", cmd)
}

// bundle is a trust bundle (docs/08 D4) as the test builds it: the
// lines, in D4's order, signed by signer with SSHSIG. extra lines go
// before END.
type bundle struct {
	target  string
	ca      []string
	signers []string
	revoked []string
	humans  []string
	sudo    bool
	issued  int64
	extra   []string
	signer  ssh.Signer
}

func (b bundle) data() []byte {
	l := []string{"TARGET=" + b.target}
	for _, k := range b.ca {
		l = append(l, "CA_KEY="+k)
	}
	for _, k := range b.signers {
		l = append(l, "SIGNER_KEY="+k)
	}
	for _, k := range b.revoked {
		l = append(l, "REVOKED_CA_KEY="+k)
	}
	for _, h := range b.humans {
		l = append(l, "HUMAN="+h)
	}
	l = append(l, "SUDO="+strconv.FormatBool(b.sudo), "ISSUED="+strconv.FormatInt(b.issued, 10))
	l = append(l, b.extra...)
	l = append(l, "END="+strconv.Itoa(len(l)))
	return []byte(strings.Join(l, "\n") + "\n")
}

func (b bundle) bytes(t *testing.T) []byte {
	t.Helper()
	d := b.data()
	sig, err := sshca.SignSSHSIG(b.signer, sshca.TrustNamespace, d)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(d, hostsetup.SignatureLine+"\n"...), sig...)
}

// pull runs the installed trust pull.
func (h *host) pull() result {
	h.t.Helper()
	o, e, code := h.exec("/etc/ssh/nyyrikki/pull.sh", "")
	return result{o, e, code}
}

// serveAndPull serves b and runs the pull.
func (h *host) serveAndPull(b []byte) result {
	h.t.Helper()
	h.answer("trust", 0, b)
	return h.pull()
}

// mark is pull.state's ISSUED line.
func (h *host) mark() string {
	h.t.Helper()
	o, _, _ := h.exec("sed -n 's/^ISSUED=//p' /etc/ssh/nyyrikki/pull.state", "")
	return strings.TrimSpace(o)
}

func millis(t time.Time) int64 { return t.UnixMilli() }
