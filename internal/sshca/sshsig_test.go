package sshca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshKeygenVerify runs ssh-keygen -Y verify on msg and sig with allowed
// as the allowed signers for identity "nyyrikki", and reports whether it
// accepted, with its output.
func sshKeygenVerify(t *testing.T, allowed []ssh.PublicKey, namespace string, msg, sig []byte) (bool, string) {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed: the SSHSIG signature can't be checked with OpenSSH (docs/08 M1)")
	}
	dir := t.TempDir()
	var as strings.Builder
	for _, p := range allowed {
		as.WriteString("nyyrikki " + AuthorizedKey(p) + "\n")
	}
	af, sf := filepath.Join(dir, "allowed_signers"), filepath.Join(dir, "sig")
	if err := os.WriteFile(af, []byte(as.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sf, sig, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-Y", "verify", "-f", af, "-I", "nyyrikki", "-n", namespace, "-s", sf)
	cmd.Stdin = bytes.NewReader(msg)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

// TestSSHSIG covers docs/08 M1: a signature made here is accepted by
// ssh-keygen -Y verify, and refused for another namespace, a changed
// byte, and a signer not in the allowed list. The armor is 70 columns.
func TestSSHSIG(t *testing.T) {
	_, pub, _ := GenerateKey("")
	b, pub2, err := GenerateKey("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("TARGET=db-1\nSUDO=true\nEND=2\n")
	sig, err := SignSSHSIG(s, TrustNamespace, msg)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	if lines[0] != SSHSIGBegin || lines[len(lines)-1] != SSHSIGEnd || len(lines) < 3 {
		t.Fatalf("armor:\n%s", sig)
	}
	for i, l := range lines[1 : len(lines)-1] {
		if len(l) > 70 || (i < len(lines)-3 && len(l) != 70) {
			t.Fatalf("line %d is %d columns", i, len(l))
		}
	}
	if ok, out := sshKeygenVerify(t, []ssh.PublicKey{pub2}, TrustNamespace, msg, sig); !ok {
		t.Fatalf("ssh-keygen refused it: %s", out)
	}
	if ok, out := sshKeygenVerify(t, []ssh.PublicKey{pub2}, "file", msg, sig); ok || !strings.Contains(out, "namespace") {
		t.Fatalf("accepted for another namespace: %s", out)
	}
	changed := bytes.Clone(msg)
	changed[len(changed)-2] = '3'
	if ok, out := sshKeygenVerify(t, []ssh.PublicKey{pub2}, TrustNamespace, changed, sig); ok {
		t.Fatalf("accepted a changed byte: %s", out)
	}
	if ok, out := sshKeygenVerify(t, []ssh.PublicKey{pub}, TrustNamespace, msg, sig); ok {
		t.Fatalf("accepted a signer not allowed: %s", out)
	}
}

// TestSSHSIGRefuses: only an ed25519 key, and only with a namespace.
func TestSSHSIGRefuses(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es, err := ssh.NewSignerFromKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignSSHSIG(es, TrustNamespace, nil); err == nil {
		t.Error("signed with an ECDSA key")
	}
	b, _, _ := GenerateKey("")
	s, _ := ParsePrivateKey(b)
	if _, err := SignSSHSIG(s, "", nil); err == nil {
		t.Error("signed without a namespace")
	}
	if _, err := SignSSHSIG(nil, TrustNamespace, nil); err == nil {
		t.Error("signed without a key")
	}
}
