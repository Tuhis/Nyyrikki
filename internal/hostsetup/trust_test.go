package hostsetup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// The extra trusted key in ../config/testdata/valid.yaml.
const validExtra = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y"

var issuedAt = time.UnixMilli(1793450000123)

// splitBundle splits a served bundle at the SignatureLine: the signed
// bytes (everything before that line) and the armored signature.
func splitBundle(t *testing.T, b []byte) (msg, sig []byte) {
	t.Helper()
	sep := []byte("\n" + SignatureLine + "\n")
	if bytes.Count(b, sep) != 1 {
		t.Fatalf("not one signature line:\n%s", b)
	}
	i := bytes.Index(b, sep)
	return b[:i+1], b[i+len(sep):]
}

// valuesOf returns the values of the data lines named name, in order.
func valuesOf(msg []byte, name string) []string {
	var out []string
	for _, l := range strings.Split(string(msg), "\n") {
		if v, ok := strings.CutPrefix(l, name+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

// verify runs the host's check of docs/08 D5 with OpenSSH: ssh-keygen -Y
// verify, the allowed signers being signers, identity nyyrikki.
func verify(t *testing.T, signers []string, namespace string, msg, sig []byte) (bool, string) {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed: the bundle's signature can't be checked with OpenSSH (docs/08 G3)")
	}
	dir := t.TempDir()
	var as strings.Builder
	for _, k := range signers {
		as.WriteString("nyyrikki " + k + "\n")
	}
	af, sf := filepath.Join(dir, "allowed_signers"), filepath.Join(dir, "sig")
	os.WriteFile(af, []byte(as.String()), 0o600)
	os.WriteFile(sf, sig, 0o600)
	cmd := exec.Command(bin, "-Y", "verify", "-f", af, "-I", "nyyrikki", "-n", namespace, "-s", sf)
	cmd.Stdin = bytes.NewReader(msg)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

func trustHandler(t *testing.T, c *config.Config, f sshca.Files) (*Handler, *recAudit) {
	t.Helper()
	a := &recAudit{}
	h, err := New(c, []byte(body), keysFor(t, c, f), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return issuedAt }
	return h, a
}

// TestTrustBundle covers docs/08 D4 and G3: D4's lines in D4's order,
// ISSUED in Unix milliseconds, SIGNER_KEY a subset of CA_KEY, and a
// signature over every byte before the signature line that ssh-keygen
// accepts with the SIGNER_KEYs as allowed signers; the fetch audited.
func TestTrustBundle(t *testing.T) {
	dir := t.TempDir()
	user, userLine := keyFile(t, dir, "user-ca")
	next, nextLine := keyFile(t, dir, "user-ca-next")
	_, revokedLine := keyFile(t, dir, "old")
	cfg := testConfig(t)
	c := *cfg
	c.SSH.RevokedUserCAKeys = []string{revokedLine}
	h, a := trustHandler(t, &c, sshca.Files{UserCA: user, NextUserCA: next})
	w := get(t, h, http.MethodGet, "/hosts/db-1/trust")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	msg, sig := splitBundle(t, w.Body.Bytes())
	want := "TARGET=db-1\n" +
		"CA_KEY=" + userLine + "\n" +
		"CA_KEY=" + nextLine + "\n" +
		"CA_KEY=" + validExtra + "\n" +
		"SIGNER_KEY=" + userLine + "\n" +
		"SIGNER_KEY=" + nextLine + "\n" +
		"REVOKED_CA_KEY=" + revokedLine + "\n" +
		"HUMAN=owner\n" +
		"SUDO=true\n" +
		"ISSUED=1793450000123\n" +
		"END=10\n"
	if string(msg) != want {
		t.Fatalf("data lines:\n%s\nwant:\n%s", msg, want)
	}
	if !bytes.HasPrefix(sig, []byte(sshca.SSHSIGBegin+"\n")) || !bytes.HasSuffix(sig, []byte("\n"+sshca.SSHSIGEnd+"\n")) {
		t.Fatalf("signature armor:\n%s", sig)
	}
	signers := valuesOf(msg, "SIGNER_KEY")
	if ok, out := verify(t, signers, sshca.TrustNamespace, msg, sig); !ok {
		t.Fatalf("ssh-keygen refused the bundle: %s", out)
	}
	// Signed by user-ca: pub(user-ca) alone verifies it.
	if ok, out := verify(t, []string{userLine}, sshca.TrustNamespace, msg, sig); !ok {
		t.Fatalf("not signed by user-ca: %s", out)
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", w.Header())
	}
	if len(a.recs) != 1 {
		t.Fatalf("audit %+v", a.recs)
	}
	r := a.recs[0]
	pub := func(l string) string {
		pk, _ := config.ParseUserCAKey(l)
		return ssh.FingerprintSHA256(pk)
	}
	wantDetail := "client 192.0.2.1 issued 1793450000123 ca_keys " + pub(userLine) + "," + pub(nextLine) + "," + pub(validExtra) +
		" signer_keys " + pub(userLine) + "," + pub(nextLine)
	if r.Kind != codes.KindHostTrustServed || len(r.Targets) != 1 || r.Targets[0] != "db-1" || r.Detail != wantDetail {
		t.Fatalf("audit %+v\nwant detail %s", r, wantDetail)
	}
}

// TestTrustBundleIssuedNow: ISSUED is the server's time of this fetch,
// in milliseconds, and each fetch is signed and audited anew.
func TestTrustBundleIssuedNow(t *testing.T) {
	cfg := testConfig(t)
	keys, _ := testKeys(t, cfg)
	a := &recAudit{}
	h, err := New(cfg, []byte(body), keys, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UnixMilli()
	w1 := get(t, h, http.MethodGet, "/hosts/db-1/trust")
	time.Sleep(3 * time.Millisecond)
	w2 := get(t, h, http.MethodGet, "/hosts/db-1/trust")
	after := time.Now().UnixMilli()
	m1, _ := splitBundle(t, w1.Body.Bytes())
	m2, _ := splitBundle(t, w2.Body.Bytes())
	i1, err1 := strconv.ParseInt(valuesOf(m1, "ISSUED")[0], 10, 64)
	i2, err2 := strconv.ParseInt(valuesOf(m2, "ISSUED")[0], 10, 64)
	if err1 != nil || err2 != nil || i1 < before || i2 > after || i2 <= i1 {
		t.Fatalf("ISSUED %d, %d not in [%d, %d] and increasing", i1, i2, before, after)
	}
	if len(a.recs) != 2 || !strings.Contains(a.recs[1].Detail, " issued "+strconv.FormatInt(i2, 10)+" ") {
		t.Fatalf("audit %+v", a.recs)
	}
}

// TestTrustBundleSignerRefusals covers G3: with the SIGNER_KEYs as
// allowed signers, ssh-keygen refuses another namespace, a changed byte,
// and a bundle signed by an extra trusted key, which is in CA_KEY but
// never in SIGNER_KEY.
func TestTrustBundleSignerRefusals(t *testing.T) {
	dir := t.TempDir()
	user, _ := keyFile(t, dir, "user-ca")
	extraFile, extraLine := keyFile(t, dir, "extra")
	cfg := testConfig(t)
	c := *cfg
	c.SSH.UserCAPublicKeys = []string{extraLine}
	h, _ := trustHandler(t, &c, sshca.Files{UserCA: user})
	w := get(t, h, http.MethodGet, "/hosts/db-1/trust")
	msg, sig := splitBundle(t, w.Body.Bytes())
	signers := valuesOf(msg, "SIGNER_KEY")
	if strings.Join(valuesOf(msg, "CA_KEY"), "|") != valuesOf(msg, "CA_KEY")[0]+"|"+extraLine || len(signers) != 1 || signers[0] == extraLine {
		t.Fatalf("CA_KEY %v, SIGNER_KEY %v", valuesOf(msg, "CA_KEY"), signers)
	}
	if ok, out := verify(t, signers, "file", msg, sig); ok || !strings.Contains(out, "namespace") {
		t.Fatalf("accepted for another namespace: %s", out)
	}
	// A changed byte at the start, in the middle, in END's count and the
	// final newline; and a line appended.
	for _, i := range []int{0, len(msg) / 2, len(msg) - 2, len(msg) - 1} {
		changed := bytes.Clone(msg)
		changed[i] ^= 0x01
		if ok, _ := verify(t, signers, sshca.TrustNamespace, changed, sig); ok {
			t.Fatalf("accepted with byte %d changed", i)
		}
	}
	if ok, _ := verify(t, signers, sshca.TrustNamespace, append(bytes.Clone(msg), "HUMAN=mallory\n"...), sig); ok {
		t.Fatal("accepted with a line appended")
	}
	// The holder of an extra key signs the same lines: refused.
	b, _ := os.ReadFile(extraFile)
	es, err := sshca.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := sshca.SignSSHSIG(es, sshca.TrustNamespace, msg)
	if err != nil {
		t.Fatal(err)
	}
	if ok, out := verify(t, signers, sshca.TrustNamespace, msg, forged); ok {
		t.Fatalf("accepted a bundle signed by an extra trusted key: %s", out)
	}
}

// TestTrustBundleRevokedStaged covers D4 and D3: a revoked staged key is
// neither a CA_KEY nor a SIGNER_KEY, and is a REVOKED_CA_KEY; the bundle
// is still served, signed by user-ca.
func TestTrustBundleRevokedStaged(t *testing.T) {
	dir := t.TempDir()
	user, userLine := keyFile(t, dir, "user-ca")
	next, nextLine := keyFile(t, dir, "user-ca-next")
	cfg := testConfig(t)
	c := *cfg
	c.SSH.RevokedUserCAKeys = []string{nextLine}
	h, _ := trustHandler(t, &c, sshca.Files{UserCA: user, NextUserCA: next})
	w := get(t, h, http.MethodGet, "/hosts/db-1/trust")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	msg, sig := splitBundle(t, w.Body.Bytes())
	if got := valuesOf(msg, "SIGNER_KEY"); len(got) != 1 || got[0] != userLine {
		t.Fatalf("SIGNER_KEY %v", got)
	}
	if got := strings.Join(valuesOf(msg, "CA_KEY"), "|"); got != userLine+"|"+validExtra {
		t.Fatalf("CA_KEY %v", got)
	}
	if got := valuesOf(msg, "REVOKED_CA_KEY"); len(got) != 1 || got[0] != nextLine {
		t.Fatalf("REVOKED_CA_KEY %v", got)
	}
	if ok, out := verify(t, valuesOf(msg, "SIGNER_KEY"), sshca.TrustNamespace, msg, sig); !ok {
		t.Fatalf("refused: %s", out)
	}
	if ok, _ := verify(t, []string{nextLine}, sshca.TrustNamespace, msg, sig); ok {
		t.Fatal("signed by the revoked staged key")
	}
}

// TestTrustBundleSubset: SIGNER_KEY is a subset of CA_KEY in every
// combination of a staged key, revocations and extra keys.
func TestTrustBundleSubset(t *testing.T) {
	dir := t.TempDir()
	user, _ := keyFile(t, dir, "user-ca")
	next, nextLine := keyFile(t, dir, "user-ca-next")
	_, extraLine := keyFile(t, dir, "extra")
	cfg := testConfig(t)
	for _, f := range []sshca.Files{{UserCA: user}, {UserCA: user, NextUserCA: next}} {
		for _, extra := range [][]string{nil, {extraLine}, {nextLine, extraLine}} {
			for _, rev := range [][]string{nil, {nextLine}, {extraLine}, {nextLine, extraLine}} {
				c := *cfg
				c.SSH.UserCAPublicKeys, c.SSH.RevokedUserCAKeys = extra, rev
				h, _ := trustHandler(t, &c, f)
				w := get(t, h, http.MethodGet, "/hosts/db-1/trust")
				if w.Code != 200 {
					t.Fatalf("%v %v %v: %d", f, extra, rev, w.Code)
				}
				msg, _ := splitBundle(t, w.Body.Bytes())
				ca := valuesOf(msg, "CA_KEY")
				for _, s := range valuesOf(msg, "SIGNER_KEY") {
					if !strings.Contains("|"+strings.Join(ca, "|")+"|", "|"+s+"|") {
						t.Fatalf("SIGNER_KEY %s not a CA_KEY %v", s, ca)
					}
					if s == extraLine {
						t.Fatal("an extra key is a signer")
					}
				}
				trusted := "|" + strings.Join(append(ca, valuesOf(msg, "SIGNER_KEY")...), "|") + "|"
				for _, r := range valuesOf(msg, "REVOKED_CA_KEY") {
					if strings.Contains(trusted, "|"+r+"|") {
						t.Fatalf("revoked key %s still trusted:\n%s", r, msg)
					}
				}
			}
		}
	}
}

// TestTrustBundleUnavailable covers D1 and D3 at the trust endpoint: a
// revoked user-ca, a broken or missing key file answer 503 with the
// detail, serve and sign nothing, and audit no fetch; so does a failed
// audit write.
func TestTrustBundleUnavailable(t *testing.T) {
	dir := t.TempDir()
	user, userLine := keyFile(t, dir, "user-ca")
	next, _ := keyFile(t, dir, "user-ca-next")
	garbage := filepath.Join(dir, "garbage")
	os.WriteFile(garbage, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n"), 0o600)
	cfg := testConfig(t)
	revUser := *cfg
	revUser.SSH.RevokedUserCAKeys = []string{userLine}
	for name, c := range map[string]struct {
		cfg    *config.Config
		files  sshca.Files
		detail string
	}{
		"revoked user-ca":   {&revUser, sshca.Files{UserCA: user, NextUserCA: next}, sshca.DetailUserCARevoked},
		"missing user-ca":   {cfg, sshca.Files{UserCA: filepath.Join(dir, "none")}, sshca.DetailUnreadable},
		"broken user-ca":    {cfg, sshca.Files{UserCA: garbage}, sshca.DetailUnreadable},
		"broken next":       {cfg, sshca.Files{UserCA: user, NextUserCA: garbage}, sshca.DetailUnreadable},
		"broken host-ca":    {cfg, sshca.Files{UserCA: user, HostCA: garbage}, sshca.DetailUnreadable},
		"directory host-ca": {cfg, sshca.Files{UserCA: user, HostCA: dir}, sshca.DetailUnreadable},
	} {
		t.Run(name, func(t *testing.T) {
			h, a := trustHandler(t, c.cfg, c.files)
			w := get(t, h, http.MethodGet, "/hosts/db-1/trust")
			if w.Code != http.StatusServiceUnavailable || w.Body.String() != "unavailable: "+c.detail+"\n" {
				t.Fatalf("status %d body %q", w.Code, w.Body.String())
			}
			if len(a.recs) != 0 {
				t.Fatalf("audited as served: %+v", a.recs)
			}
		})
	}
	h, a := trustHandler(t, cfg, sshca.Files{UserCA: user})
	a.fail = true
	if w := get(t, h, http.MethodGet, "/hosts/db-1/trust"); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "SIGNATURE") || strings.Contains(w.Body.String(), "TARGET") {
		t.Fatalf("served without an audit record: %d %q", w.Code, w.Body.String())
	}
}

// TestTrustBundleRefusals covers G3: the trust path follows docs/07
// D16's rules exactly as setup.sh does: only GET; any query string 400;
// the same 404, with the same body as setup.sh's, for an unknown, a
// Kubernetes and a malformed target; nothing audited.
func TestTrustBundleRefusals(t *testing.T) {
	cfg := testConfig(t)
	keys, _ := testKeys(t, cfg)
	a := &recAudit{}
	h, _ := New(cfg, []byte(body), keys, a, nil)
	for _, m := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions, "PROPFIND"} {
		w, s := get(t, h, m, "/hosts/db-1/trust"), get(t, h, m, "/hosts/db-1/setup.sh")
		if w.Code != http.StatusMethodNotAllowed || w.Body.String() != s.Body.String() || w.Header().Get("Allow") != "GET" {
			t.Errorf("%s: %d %q", m, w.Code, w.Body.String())
		}
	}
	for _, q := range []string{"?", "?sig=x", "?x", "?issued=1"} {
		w, s := get(t, h, http.MethodGet, "/hosts/db-1/trust"+q), get(t, h, http.MethodGet, "/hosts/db-1/setup.sh"+q)
		if w.Code != http.StatusBadRequest || w.Body.String() != s.Body.String() {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	notFound := get(t, h, http.MethodGet, "/hosts/ghost/setup.sh").Body.String()
	for _, p := range []string{"/hosts/ghost/trust", "/hosts/prod-k8s/trust", "/hosts/DB-1/trust",
		"/hosts/db-1/../db-1/trust", "/hosts/db-1/trust/", "/hosts/db-1/trust.sig", "/hosts/db-1/Trust",
		"/hosts//trust", "/hosts/db-1%2fx/trust", "/hosts/db-1/setup.sh/trust", "/hosts/db-1/trust/setup.sh", "/hosts/trust"} {
		w := get(t, h, http.MethodGet, p)
		if w.Code != http.StatusNotFound || w.Body.String() != notFound {
			t.Errorf("%s: %d %q", p, w.Code, w.Body.String())
		}
	}
	if len(a.recs) != 0 {
		t.Errorf("a refused fetch was audited as served: %+v", a.recs)
	}
}

// TestTrustBundleNoPrivateKey: nothing of any CA private key is in the
// bundle, nor in the decoded signature blob: no PEM marker, no OpenSSH
// private key magic, no ed25519 seed.
func TestTrustBundleNoPrivateKey(t *testing.T) {
	dir := t.TempDir()
	files := sshca.Files{}
	files.UserCA, _ = keyFile(t, dir, "user-ca")
	files.NextUserCA, _ = keyFile(t, dir, "user-ca-next")
	files.HostCA, _ = keyFile(t, dir, "host-ca")
	cfg := testConfig(t)
	h, _ := trustHandler(t, cfg, files)
	w := get(t, h, http.MethodGet, "/hosts/db-1/trust")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	served := w.Body.Bytes()
	_, sig := splitBundle(t, served)
	armored := strings.TrimSpace(string(sig))
	armored = strings.TrimSuffix(strings.TrimPrefix(armored, sshca.SSHSIGBegin), sshca.SSHSIGEnd)
	blob, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(armored), ""))
	if err != nil || !bytes.HasPrefix(blob, []byte("SSHSIG")) {
		t.Fatalf("signature blob: %v", err)
	}
	for _, hay := range [][]byte{served, blob} {
		if bytes.Contains(hay, []byte("PRIVATE KEY")) || bytes.Contains(hay, []byte("openssh-key-v1")) || bytes.Contains(hay, []byte("b3BlbnNzaC1rZXktdjE")) {
			t.Fatal("a private key reached the bundle")
		}
	}
	for _, f := range []string{files.UserCA, files.NextUserCA, files.HostCA} {
		b, _ := os.ReadFile(f)
		raw, err := ssh.ParseRawPrivateKey(b)
		if err != nil {
			t.Fatal(err)
		}
		seed := raw.(*ed25519.PrivateKey).Seed()
		for _, hay := range [][]byte{served, blob} {
			if bytes.Contains(hay, seed) || bytes.Contains(hay, []byte(base64.StdEncoding.EncodeToString(seed)[:40])) {
				t.Fatalf("the seed of %s reached the bundle", filepath.Base(f))
			}
		}
	}
	// host-ca is no user CA: it is in no line.
	hb, _ := os.ReadFile(files.HostCA)
	hs, _ := sshca.ParsePrivateKey(hb)
	if bytes.Contains(served, []byte(sshca.AuthorizedKey(hs.PublicKey()))) {
		t.Fatal("host-ca's public key is in the bundle")
	}
}

// TestTrustBundleSetupUnchanged: adding the trust path left setup.sh a
// script, unsigned. Its SIGNER_KEY lines are docs/08 D13's, since SE6.
func TestTrustBundleSetupUnchanged(t *testing.T) {
	cfg := testConfig(t)
	keys, _ := testKeys(t, cfg)
	h, _ := New(cfg, []byte(body), keys, &recAudit{}, nil)
	w := get(t, h, http.MethodGet, "/hosts/db-1/setup.sh")
	if w.Code != 200 || strings.Contains(w.Body.String(), SignatureLine) ||
		w.Header().Get("Content-Type") != "text/x-shellscript; charset=utf-8" {
		t.Fatalf("setup.sh changed: %d %v", w.Code, w.Header())
	}
}
