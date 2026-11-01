//go:build sshhost

package sshhost_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/hostsetup"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

type nopAudit struct{}

func (nopAudit) Append(context.Context, audit.Record) error { return nil }

// TestTrustBundleOnHost covers the host side of docs/08 G3: a bundle
// served by the trust endpoint verifies with each distribution's own
// ssh-keygen, with the bundle's SIGNER_KEYs as allowed signers, and is
// refused for another namespace, a changed byte, and a signature by an
// extra trusted key (M1).
func TestTrustBundleOnHost(t *testing.T) {
	t.Parallel()
	cfgBytes, err := os.ReadFile("../../internal/config/testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(cfgBytes)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeKey := func(name string) string {
		b, _, err := sshca.GenerateKey("")
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	user, next := writeKey("user-ca"), writeKey("user-ca-next")
	eb, _, err := sshca.GenerateKey("")
	if err != nil {
		t.Fatal(err)
	}
	extra, err := sshca.ParsePrivateKey(eb)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshca.New(sshca.Options{Files: sshca.Files{UserCA: user, NextUserCA: next}, Extra: []ssh.PublicKey{extra.PublicKey()}})
	h, err := hostsetup.New(cfg, []byte("#!/bin/sh\n"+hostsetup.MainLine+"\n"), keys, nopAudit{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/hosts/db-1/trust", nil))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	served := w.Body.Bytes()
	sep := []byte("\n" + hostsetup.SignatureLine + "\n")
	i := bytes.Index(served, sep)
	if i < 0 {
		t.Fatal("no signature line")
	}
	msg, sig := served[:i+1], served[i+len(sep):]
	var signers strings.Builder
	for _, l := range strings.Split(string(msg), "\n") {
		if v, ok := strings.CutPrefix(l, "SIGNER_KEY="); ok {
			signers.WriteString("nyyrikki " + v + "\n")
		}
	}
	forged, err := sshca.SignSSHSIG(extra, sshca.TrustNamespace, msg)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(msg)
	changed[len(changed)-2] ^= 0x01

	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		h.put("/root/allowed_signers", signers.String())
		h.put("/root/bundle.sig", string(sig))
		h.put("/root/forged.sig", string(forged))
		verify := func(namespace, sigFile, data string) (string, int) {
			o, e, code := h.exec("ssh-keygen -Y verify -f /root/allowed_signers -I nyyrikki -n "+namespace+" -s "+sigFile, data)
			return o + e, code
		}
		if out, code := verify(sshca.TrustNamespace, "/root/bundle.sig", string(msg)); code != 0 {
			t.Fatalf("the host's ssh-keygen refused the bundle: %s", out)
		}
		if out, code := verify("file", "/root/bundle.sig", string(msg)); code == 0 || !strings.Contains(out, "namespace") {
			t.Fatalf("accepted for another namespace: %s", out)
		}
		if out, code := verify(sshca.TrustNamespace, "/root/bundle.sig", string(changed)); code == 0 {
			t.Fatalf("accepted a changed byte: %s", out)
		}
		if out, code := verify(sshca.TrustNamespace, "/root/forged.sig", string(msg)); code == 0 {
			t.Fatalf("accepted a bundle signed by an extra trusted key: %s", out)
		}
	})
}
