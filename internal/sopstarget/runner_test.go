package sopstarget

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getsops/sops/v3/logging"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
	"github.com/Tuhis/Nyyrikki/internal/sopstarget/sopstest"
)

const wantReason = "nyyrikki run=run_01TEST human=owner covered_by=approval:apr_01TEST"

// readBack decrypts a file Nyyrikki returned, with Nyyrikki.
func (e *env) readBack(t *testing.T, file []byte) string {
	t.Helper()
	out, err := e.run(t, mustParse(t, file, append([]string{"decrypt"}, yamlFlags()...)...))
	if err != nil {
		t.Fatalf("reading a returned file back: %v", err)
	}
	return string(out)
}

// nyyrikkiCalls are the calls the runner made: the sops program's own,
// in the tests that use it, carry its token.
func nyyrikkiCalls(f *sopstest.Fake) []sopstest.Call {
	var out []sopstest.Call
	for _, c := range f.Calls() {
		if c.Token != "the-sops-program" {
			out = append(out, c)
		}
	}
	return out
}

// docs/10 G6: decrypt returns the file's plaintext, with one KMS call
// that carries the reason and the target's token, and the audit record
// names the key.
func TestDecrypt(t *testing.T) {
	// A credential in the environment is never used (docs/10 D6, M7).
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "from-the-environment")
	t.Setenv("GOOGLE_CREDENTIALS", `{"type":"authorized_user"}`)
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	got, err := e.run(t, mustParse(t, enc, append([]string{"decrypt"}, yamlFlags()...)...))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secretYAML {
		t.Fatalf("decrypt returned %q", got)
	}
	calls := nyyrikkiCalls(e.fake)
	if len(calls) != 1 || calls[0].Op != "decrypt" || calls[0].Key != sopstest.KeyProd {
		t.Fatalf("KMS calls: %+v", calls)
	}
	if calls[0].Reason != wantReason {
		t.Fatalf("request reason %q; want %q", calls[0].Reason, wantReason)
	}
	if !strings.HasPrefix(calls[0].Token, "fake-access-token-") {
		t.Fatalf("the call's token is %q, not the target's", calls[0].Token)
	}
	if k := e.audit.kinds(); strings.Join(k, ",") != "run_started,run_finished" {
		t.Fatalf("audit kinds: %v", k)
	}
	fin := e.audit.last(codes.KindRunFinished)
	if fin.ExitCode == nil || *fin.ExitCode != 0 || fin.StdoutBytes != int64(len(got)) || len(fin.KMSKeys) != 1 || fin.KMSKeys[0] != sopstest.KeyProd {
		t.Fatalf("run_finished: %+v", fin)
	}
	if fin.RunAs == nil || fin.RunID != "run_01TEST" || fin.ApprovalID != "apr_01TEST" || fin.Human != "owner" {
		t.Fatalf("run_finished: %+v", fin)
	}
	noLibraryText(t, "the audit log", e.audit.text())
	noLibraryText(t, "the log", e.log.String())

	// The token is kept: a second run exchanges none.
	if _, err := e.run(t, mustParse(t, enc, append([]string{"decrypt"}, yamlFlags()...)...)); err != nil {
		t.Fatal(err)
	}
	if n := e.fake.TokenExchanges(); n != 1 {
		t.Fatalf("%d token exchanges for two runs", n)
	}
}

func TestDecryptExtractAndTypes(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	run := func(args ...string) string {
		t.Helper()
		out, err := e.run(t, mustParse(t, enc, append([]string{"decrypt"}, yamlFlags(args...)...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	leaf, branch := `["stringData"]["password"]`, `["stringData"]`
	if got := run("--extract", leaf); got != "hunter2" {
		t.Fatalf("extract of a value: %q", got)
	}
	if got := run("--extract", branch); got != "password: hunter2\nuser: app\n" {
		t.Fatalf("extract of a branch: %q", got)
	}
	if got := run("--extract", `["kind"]`); got != "Secret" {
		t.Fatalf("extract of a cleartext value: %q", got)
	}
	if got := run("--output-type", "json"); !strings.Contains(got, `"password": "hunter2"`) || !strings.HasPrefix(got, "{") {
		t.Fatalf("JSON output: %q", got)
	}

	// JSON and dotenv files.
	for typ, c := range map[string][2]string{"json": {`{"a": "one", "b": {"c": 2}}`, "{\n\t\"a\": \"one\",\n\t\"b\": {\n\t\t\"c\": 2\n\t}\n}\n"}, "dotenv": {"A=one\nB=two\n", "A=one\nB=two\n"}} {
		encd := e.fake.Encrypt(t, typ, c[0], sopstest.KeyOther, nil)
		got, err := e.run(t, mustParse(t, encd, "decrypt", "--input-type", typ, "--filename-override", "f."+typ))
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if string(got) != c[1] {
			t.Fatalf("%s: decrypt returned %q; want %q", typ, got, c[1])
		}
	}
}

// docs/10 M6: set and unset return a file that decrypts to the change,
// with the same wrapped data key, after one decrypt and no encrypt.
func TestSetAndUnset(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	wrapped := func(b []byte) string {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "enc: ") {
				return strings.TrimSpace(l)
			}
		}
		t.Fatal("no wrapped key")
		return ""
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"set", `["stringData"]["password"]`, `"new-password-1"`}, strings.Replace(secretYAML, "hunter2", "new-password-1", 1)},
		{[]string{"set", `["stringData"]["token"]`, `"new-token-2"`}, secretYAML + "    token: new-token-2\n"},
		{[]string{"set", `["stringData"]`, `{"only": "this"}`}, strings.Split(secretYAML, "stringData:")[0] + "stringData:\n    only: this\n"},
		{[]string{"set", "--", `["stringData"]["count"]`, "-1"}, secretYAML + "    count: -1\n"},
		{[]string{"unset", `["stringData"]["user"]`}, strings.Replace(secretYAML, "    user: app\n", "", 1)},
	}
	for _, c := range cases {
		before := len(nyyrikkiCalls(e.fake))
		out, err := e.run(t, mustParse(t, enc, append(c.args[:1:1], append(yamlFlags(), c.args[1:]...)...)...))
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		calls := nyyrikkiCalls(e.fake)[before:]
		if got := e.readBack(t, out); got != c.want {
			t.Errorf("%v: the result reads %q; want %q", c.args, got, c.want)
		}
		if wrapped(out) != wrapped(enc) {
			t.Errorf("%v: the wrapped data key changed", c.args)
		}
		// The values hold "-", which base64 never does, so no ciphertext
		// can contain them by chance.
		if strings.Contains(string(out), "new-password-1") || strings.Contains(string(out), "new-token-2") {
			t.Errorf("%v: the new value is in cleartext: %s", c.args, out)
		}
		if len(calls) != 1 || calls[0].Op != "decrypt" || calls[0].Reason != wantReason {
			t.Errorf("%v: KMS calls %+v", c.args, calls)
		}
	}
	// A value set outside the encrypted part stays in cleartext, as the
	// file's own rule says.
	out, err := e.run(t, mustParse(t, enc, append([]string{"set"}, yamlFlags(`["metadata"]["labels"]`, `{"tier": "db"}`)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "tier: db") {
		t.Fatalf("a cleartext value was encrypted: %s", out)
	}
}

// docs/10 D5: encrypt returns a file wrapped with the key the request
// names, with only the values its rule names encrypted.
func TestEncrypt(t *testing.T) {
	e := newEnv(t)
	out, err := e.run(t, mustParse(t, []byte(secretYAML), append([]string{"encrypt", "--gcp-kms", sopstest.KeyOther, "--encrypted-regex", secretRegex}, yamlFlags()...)...))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "hunter2") || !strings.Contains(s, "name: db-creds") || !strings.Contains(s, "resource_id: "+sopstest.KeyOther) || !strings.Contains(s, "encrypted_regex: "+secretRegex) {
		t.Fatalf("the encrypted file: %s", s)
	}
	calls := nyyrikkiCalls(e.fake)
	if len(calls) != 1 || calls[0].Op != "encrypt" || calls[0].Key != sopstest.KeyOther || calls[0].Reason != wantReason {
		t.Fatalf("KMS calls: %+v", calls)
	}
	if fin := e.audit.last(codes.KindRunFinished); len(fin.KMSKeys) != 1 || fin.KMSKeys[0] != sopstest.KeyOther {
		t.Fatalf("run_finished: %+v", fin)
	}
	// And Nyyrikki reads its own file back.
	back, err := e.run(t, mustParse(t, out, append([]string{"decrypt"}, yamlFlags()...)...))
	if err != nil || string(back) != secretYAML {
		t.Fatalf("decrypt of an encrypt: %q %v", back, err)
	}
	// The other rules, each read back.
	for _, rule := range [][]string{{"--unencrypted-regex", "^(apiVersion|kind|metadata)$"}, {"--encrypted-suffix", "Data"}, {"--unencrypted-suffix", "ata"}, nil} {
		out, err := e.run(t, mustParse(t, []byte(secretYAML), append(append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd}, rule...), yamlFlags()...)...))
		if err != nil {
			t.Fatalf("%v: %v", rule, err)
		}
		if strings.Contains(string(out), "hunter2") != (len(rule) == 2 && rule[0] == "--unencrypted-suffix") {
			t.Errorf("%v: password in cleartext is wrong: %s", rule, out)
		}
		if got := e.readBack(t, out); got != secretYAML {
			t.Errorf("%v: the result reads %q", rule, got)
		}
	}
}

// encLines returns the line of key in an encrypted file.
func lineOf(t *testing.T, enc []byte, key string) string {
	t.Helper()
	for _, l := range strings.Split(string(enc), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), key+":") {
			return l
		}
	}
	t.Fatalf("no line for %q", key)
	return ""
}

// docs/10 G4: a file that was tampered with ends in a fixed code, with
// no output and nothing of SOPS's or Google's text anywhere.
func TestTamperedFiles(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	pw, user := lineOf(t, enc, "password"), lineOf(t, enc, "user")
	pwValue, userValue := strings.SplitN(pw, ": ", 2)[1], strings.SplitN(user, ": ", 2)[1]
	swapped := strings.Replace(strings.Replace(string(enc), pw, "    password: "+userValue, 1), user, "    user: "+pwValue, 1)
	// Some other secret encrypted with the same Cloud KMS key, where the
	// wrapped data key goes (docs/10 §6, "KMS as an oracle").
	otherSecret := sopstest.Base64(e.fake.Wrap(sopstest.KeyProd, []byte("some-other-secret-under-this-key!")))
	encLine := lineOf(t, enc, "enc")
	cases := []struct {
		name   string
		file   string
		detail string
		calls  int
	}{
		{"two values swapped", swapped, DetailValueNotDecryptable, 1},
		{"a key renamed", strings.Replace(string(enc), "    password:", "    harmless:", 1), DetailValueNotDecryptable, 1},
		{"a value dropped", strings.Replace(string(enc), user+"\n", "", 1), DetailMACMismatch, 1},
		{"a cleartext value changed", strings.Replace(string(enc), "name: db-creds", "name: test-creds", 1), DetailMACMismatch, 1},
		{"a cleartext value dropped", strings.Replace(string(enc), "    namespace: shop\n", "", 1), DetailMACMismatch, 1},
		{"the rule changed", strings.Replace(string(enc), "encrypted_regex: "+secretRegex, "encrypted_regex: ^(data)$", 1), DetailMACMismatch, 1},
		{"mac_only_encrypted added", strings.Replace(string(enc), "    lastmodified:", "    mac_only_encrypted: true\n    lastmodified:", 1), DetailMACMismatch, 1},
		{"another secret as the data key", strings.Replace(string(enc), encLine, "          enc: "+otherSecret, 1), DetailValueNotDecryptable, 1},
		{"junk as the data key", strings.Replace(string(enc), encLine, "          enc: anVuaw==", 1), DetailValueNotDecryptable, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.file == string(enc) {
				t.Fatal("the fixture was not changed")
			}
			req, err := Parse(append([]string{"decrypt"}, yamlFlags()...), []byte(c.file), false, testKeys)
			if err != nil {
				t.Fatalf("the file should pass the check before approval: %v", err)
			}
			before := len(nyyrikkiCalls(e.fake))
			out, err := e.run(t, req)
			if out != nil {
				t.Fatalf("output: %q", out)
			}
			wantCode(t, err, codes.InvalidRequest, c.detail)
			if !strings.HasPrefix(err.Error(), "invalid_request: "+c.detail+": ") {
				t.Fatalf("the agent isn't told the detail: %v", err)
			}
			if n := len(nyyrikkiCalls(e.fake)) - before; n != c.calls {
				t.Fatalf("%d KMS calls", n)
			}
			fin := e.audit.last(codes.KindRunFinished)
			if fin.Code != string(codes.InvalidRequest) || fin.Detail != c.detail || fin.ExitCode == nil || *fin.ExitCode != 1 || fin.StdoutBytes != 0 {
				t.Fatalf("run_finished: %+v", fin)
			}
			noLibraryText(t, "the error", err.Error())
		})
	}
	noLibraryText(t, "the audit log", e.audit.text())
	noLibraryText(t, "the log", e.log.String())

	// set and unset fail the same way: nothing is re-encrypted.
	for _, args := range [][]string{{"set", `["stringData"]["x"]`, `"y"`}, {"unset", `["stringData"]["user"]`}} {
		req := mustParse(t, []byte(cases[3].file), append(args[:1:1], append(yamlFlags(), args[1:]...)...)...)
		out, err := e.run(t, req)
		if out != nil {
			t.Fatalf("%v: output %q", args, out)
		}
		wantCode(t, err, codes.InvalidRequest, DetailMACMismatch)
	}
}

// docs/10 G7, D12: every dependency failure ends in unavailable, with a
// fixed detail, audited, and nothing of Google's text.
func TestDependencyFailures(t *testing.T) {
	decrypt := append([]string{"decrypt"}, yamlFlags()...)
	t.Run("KMS denies", func(t *testing.T) {
		e := newEnv(t)
		enc := encrypted(t, e.fake)
		for status, detail := range map[int]string{http.StatusForbidden: DetailKMSDenied, http.StatusUnauthorized: DetailKMSDenied,
			http.StatusNotFound: DetailKMSDenied, http.StatusInternalServerError: DetailKMSUnavailable, http.StatusTooManyRequests: DetailKMSUnavailable} {
			e.fake.FailKey(sopstest.KeyProd, status)
			out, err := e.run(t, mustParse(t, enc, decrypt...))
			if out != nil {
				t.Fatalf("%d: output", status)
			}
			wantCode(t, err, codes.Unavailable, detail)
			noLibraryText(t, "the error", err.Error())
			dep := e.audit.last(codes.KindDependencyFailed)
			if dep == nil || dep.Detail != detail || dep.Code != string(codes.Unavailable) || len(dep.KMSKeys) != 1 || dep.KMSKeys[0] != sopstest.KeyProd {
				t.Fatalf("%d: dependency_failed: %+v", status, dep)
			}
			if fin := e.audit.last(codes.KindRunFinished); fin.Detail != detail || *fin.ExitCode != 1 {
				t.Fatalf("%d: run_finished: %+v", status, fin)
			}
		}
		noLibraryText(t, "the audit log", e.audit.text())
		noLibraryText(t, "the log", e.log.String())
		// An encrypt fails the same way.
		e.fake.FailKey(sopstest.KeyProd, http.StatusInternalServerError)
		out, err := e.run(t, mustParse(t, []byte(secretYAML), append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd}, yamlFlags()...)...))
		if out != nil {
			t.Fatal("output")
		}
		wantCode(t, err, codes.Unavailable, DetailKMSUnavailable)
	})
	t.Run("KMS unreachable", func(t *testing.T) {
		f := sopstest.New(t)
		enc := encrypted(t, f)
		e := newEnvWith(t, f, f.ServiceAccountFile(t, t.TempDir()))
		// A first run gets the token; then the fake goes away.
		if _, err := e.run(t, mustParse(t, enc, decrypt...)); err != nil {
			t.Fatal(err)
		}
		f.Close()
		out, err := e.run(t, mustParse(t, enc, decrypt...))
		if out != nil {
			t.Fatal("output")
		}
		wantCode(t, err, codes.Unavailable, DetailKMSUnavailable)
	})
	t.Run("no token", func(t *testing.T) {
		e := newEnv(t)
		enc := encrypted(t, e.fake)
		e.fake.FailTokens(http.StatusBadRequest)
		out, err := e.run(t, mustParse(t, enc, decrypt...))
		if out != nil {
			t.Fatal("output")
		}
		wantCode(t, err, codes.Unavailable, DetailKMSUnavailable)
		noLibraryText(t, "the error", err.Error())
		noLibraryText(t, "the audit log", e.audit.text())
		noLibraryText(t, "the log", e.log.String())
		if n := len(nyyrikkiCalls(e.fake)); n != 0 {
			t.Fatalf("%d KMS calls without a token", n)
		}
	})
	t.Run("the credential file", func(t *testing.T) {
		e := newEnv(t)
		enc := encrypted(t, e.fake)
		for name, content := range map[string]*string{"missing": nil, "not JSON": ptr("private-key-material"), "another type": ptr(`{"type":"authorized_user","refresh_token":"SECRET-REFRESH"}`)} {
			if content == nil {
				os.Remove(e.creds)
			} else if err := os.WriteFile(e.creds, []byte(*content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := e.run(t, mustParse(t, enc, decrypt...))
			if out != nil {
				t.Fatalf("%s: output", name)
			}
			wantCode(t, err, codes.Unavailable, DetailCredentials)
			if dep := e.audit.last(codes.KindDependencyFailed); dep == nil || dep.Detail != DetailCredentials {
				t.Fatalf("%s: dependency_failed: %+v", name, dep)
			}
		}
		if s := e.log.String() + e.audit.text(); strings.Contains(s, "SECRET-REFRESH") || strings.Contains(s, "private-key-material") {
			t.Fatalf("the credential file's contents were logged: %s", s)
		}
		if n := len(nyyrikkiCalls(e.fake)); n != 0 {
			t.Fatalf("%d KMS calls without a credential", n)
		}
		if k := e.audit.kinds(); strings.Contains(strings.Join(k, ","), "run_started") {
			t.Fatalf("a run started without a credential: %v", k)
		}
	})
	t.Run("the audit log", func(t *testing.T) {
		e := newEnv(t)
		enc := encrypted(t, e.fake)
		e.audit.fail = true
		out, err := e.run(t, mustParse(t, enc, decrypt...))
		if out != nil {
			t.Fatal("output")
		}
		if codes.Of(err) != codes.Unavailable {
			t.Fatalf("a failed audit write: %v", err)
		}
		if n := len(nyyrikkiCalls(e.fake)); n != 0 {
			t.Fatalf("%d KMS calls with no audit record of the start", n)
		}
	})
	t.Run("an unknown target", func(t *testing.T) {
		e := newEnv(t)
		enc := encrypted(t, e.fake)
		req := mustParse(t, enc, decrypt...)
		g := decisiontest.Grant(context.Background(), decisiontest.Spec{RunID: "r", Target: "elsewhere", Digest: req.Digest("elsewhere", ""), Human: "owner"})
		_, err := e.runner.Run(g, req, 0)
		wantCode(t, err, codes.Unavailable, DetailUnknownTarget)
	})
}

func ptr(s string) *string { return &s }

// docs/10 D5: the runner's own check that the Grant covers the request.
func TestGrantMustCoverTheRequest(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	asked := mustParse(t, enc, append([]string{"decrypt", "--extract", `["kind"]`}, yamlFlags()...)...)
	other := mustParse(t, enc, append([]string{"decrypt"}, yamlFlags()...)...)
	res, err := e.runner.Run(grantFor(context.Background(), asked), other, 0)
	if res != nil {
		t.Fatal("a run the Grant doesn't cover returned a result")
	}
	wantCode(t, err, codes.Internal, DetailDigestMismatch)
	g := decisiontest.Grant(context.Background(), decisiontest.Spec{RunID: "r", Target: testTarget, Digest: other.Digest(testTarget, ""), Interactive: true})
	_, err = e.runner.Run(g, other, 0)
	wantCode(t, err, codes.Internal, DetailInteractiveMismatch)
	if n := len(nyyrikkiCalls(e.fake)); n != 0 {
		t.Fatalf("%d KMS calls", n)
	}
	if _, err := e.runner.Run(nil, other, 0); codes.Of(err) != codes.Internal {
		t.Fatal(err)
	}
}

// docs/10 D5, D11, G2: a file that names a key twice, handed to the
// runner past the check of D4, costs one KMS call, and the run fails
// although a later entry would have decrypted the file (M15).
func TestOneCallPerKey(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	good := lineOf(t, enc, "enc")
	// The valid entry last, after one with junk for the same key.
	file := strings.Replace(string(enc), "    gcp_kms:\n", "    gcp_kms:\n"+gcpEntry(sopstest.KeyProd, "anVuaw=="), 1)
	if !strings.Contains(file, good) {
		t.Fatal("the valid entry is gone")
	}
	if _, err := Parse(append([]string{"decrypt"}, yamlFlags()...), []byte(file), false, testKeys); codes.DetailOf(err) != DetailDuplicateKey {
		t.Fatalf("the check before approval lets a repeated key through: %v", err)
	}
	// Past D4: the request is built from the good file and given the
	// bad one, and the runner's own check is left out.
	req := mustParse(t, enc, append([]string{"decrypt"}, yamlFlags()...)...)
	req.stdin = []byte(file)
	e.runner.skipFileCheck = true
	out, err := e.run(t, req)
	if out != nil {
		t.Fatalf("output: %q", out)
	}
	wantCode(t, err, codes.InvalidRequest, DetailKMSCallLimit)
	calls := nyyrikkiCalls(e.fake)
	if len(calls) != 1 || calls[0].Key != sopstest.KeyProd {
		t.Fatalf("KMS calls: %+v", calls)
	}
	if fin := e.audit.last(codes.KindRunFinished); fin.Detail != DetailKMSCallLimit || len(fin.KMSKeys) != 1 {
		t.Fatalf("run_finished: %+v", fin)
	}
	if dec := e.audit.last(codes.KindDecision); dec == nil || dec.Detail != DetailKMSCallLimit || dec.Decision != codes.Deny {
		t.Fatalf("the refused call isn't audited: %+v", dec)
	}

	// With the runner's check in place, the same file is refused before
	// anything is called.
	e.runner.skipFileCheck = false
	_, err = e.run(t, req)
	wantCode(t, err, codes.InvalidRequest, DetailDuplicateKey)
	if n := len(nyyrikkiCalls(e.fake)); n != 1 {
		t.Fatalf("%d KMS calls after a refused file", n)
	}
}

// docs/10 D5: the key service answers only for the target's keys, and a
// refusal fails the run whatever SOPS does next.
func TestKeyServiceRefusesOtherKeys(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	e.runner.skipFileCheck = true
	req := mustParse(t, enc, append([]string{"decrypt"}, yamlFlags()...)...)

	// A key outside the target, before the valid one.
	req.stdin = []byte(strings.Replace(string(enc), "    gcp_kms:\n", "    gcp_kms:\n"+gcpEntry(sopstest.KeyForeign, "anVuaw=="), 1))
	out, err := e.run(t, req)
	if out != nil {
		t.Fatalf("output: %q", out)
	}
	wantCode(t, err, codes.InvalidRequest, DetailKeyNotAllowed)
	for _, c := range nyyrikkiCalls(e.fake) {
		if c.Key == sopstest.KeyForeign {
			t.Fatal("a key outside the target was called")
		}
	}

	// A Vault key: no address the file names is ever called (M13).
	before := len(nyyrikkiCalls(e.fake))
	vault := "    hc_vault:\n        - vault_address: " + e.fake.URL() + "/vault\n          engine_path: sops\n          key_name: k\n          created_at: \"2026-11-13T00:00:00Z\"\n          enc: vault:v1:x\n"
	req.stdin = []byte(strings.Replace(removeGCPString(t, string(enc)), "    lastmodified:", vault+"    lastmodified:", 1))
	out, err = e.run(t, req)
	if out != nil {
		t.Fatalf("output: %q", out)
	}
	wantCode(t, err, codes.InvalidRequest, DetailKeyNotAllowed)
	if n := len(nyyrikkiCalls(e.fake)) - before; n != 0 {
		t.Fatalf("%d calls for a file with only a Vault key", n)
	}
	if e.fake.OtherRequests() != 0 {
		t.Fatal("the address a file named was called")
	}
}

func removeGCPString(t *testing.T, s string) string { return string(removeGCP(t, []byte(s))) }

// docs/10 D11, G6: a cut ends the KMS call, and a cut run returns
// nothing.
func TestCut(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	req := mustParse(t, enc, append([]string{"decrypt"}, yamlFlags()...)...)

	release := e.fake.Hold()
	defer release()
	g := grantFor(context.Background(), req)
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := e.runner.Run(g, req, 0)
		var out []byte
		if res != nil {
			out = res.Stdout
		}
		done <- result{out, err}
	}()
	select {
	case <-e.fake.Entered():
	case <-time.After(10 * time.Second):
		t.Fatal("the KMS call never arrived")
	}
	decisiontest.End(g, decision.ErrEndedByApprover)
	select {
	case r := <-done:
		if r.out != nil {
			t.Fatalf("a cut run returned %q", r.out)
		}
		wantCode(t, r.err, codes.Expired, decision.DetailEndedByApprover)
	case <-time.After(10 * time.Second):
		t.Fatal("the run didn't end when its Grant did")
	}
	if cut := e.audit.last(codes.KindRunCut); cut == nil || cut.Detail != decision.DetailEndedByApprover || cut.StdoutBytes != 0 {
		t.Fatalf("run_cut: %+v", cut)
	}

	// The time limit cuts the same way.
	g2 := grantFor(context.Background(), req)
	res, err := e.runner.Run(g2, req, 200*time.Millisecond)
	if res != nil {
		t.Fatal("a timed-out run returned a result")
	}
	wantCode(t, err, codes.Expired, DetailTimeout)

	// A Grant that has already ended starts nothing.
	release()
	before := len(nyyrikkiCalls(e.fake))
	g3 := grantFor(context.Background(), req)
	g3.Release()
	_, err = e.runner.Run(g3, req, 0)
	wantCode(t, err, codes.Expired, DetailGrantEnded)
	if n := len(nyyrikkiCalls(e.fake)) - before; n != 0 {
		t.Fatalf("%d KMS calls for an ended Grant", n)
	}

	// Under an elevation, never past its expiry, and the reason names it.
	release()
	g4 := decisiontest.Grant(context.Background(), decisiontest.Spec{
		RunID: "run_02", Target: testTarget, Digest: req.Digest(testTarget, ""),
		CoveredBy: codes.CoveredElevation, ElevationID: "elv_01", Human: "owner", NotAfter: time.Now().Add(time.Minute),
	})
	if _, err := e.runner.Run(g4, req, 0); err != nil {
		t.Fatal(err)
	}
	calls := nyyrikkiCalls(e.fake)
	if got := calls[len(calls)-1].Reason; got != "nyyrikki run=run_02 human=owner covered_by=elevation:elv_01" {
		t.Fatalf("an elevation's reason: %q", got)
	}
}

func TestOutputLimit(t *testing.T) {
	e := newEnv(t)
	enc := encrypted(t, e.fake)
	e.runner.limits.MaxOutput = 16
	out, err := e.run(t, mustParse(t, enc, append([]string{"decrypt"}, yamlFlags()...)...))
	if out != nil {
		t.Fatal("part of a result was returned")
	}
	wantCode(t, err, codes.InvalidRequest, DetailOutputTooLarge)
	// A result within the limit is whole.
	out, err = e.run(t, mustParse(t, enc, append([]string{"decrypt", "--extract", `["stringData"]["user"]`}, yamlFlags()...)...))
	if err != nil || string(out) != "app" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestNewRunner(t *testing.T) {
	a := &memAudit{}
	ok := RunnerConfig{
		Targets: map[string]Target{"s": {Name: "s", CredentialsFile: "/x", Keys: testKeys}},
		Limits:  Limits{DefaultTimeout: time.Second, MaxTimeout: time.Second, MaxOutput: 1},
		Audit:   a, Getenv: func(string) string { return "" },
	}
	if _, err := NewRunner(ok); err != nil {
		t.Fatal(err)
	}
	// SOPS takes its Cloud KMS endpoint from the environment whatever
	// credential it is given: a call sent there would carry the token.
	for _, name := range []string{"SOPS_GCP_KMS_ENDPOINT", "SOPS_GCP_KMS_UNIVERSE_DOMAIN"} {
		c := ok
		c.Getenv = func(n string) string {
			if n == name {
				return "evil.example"
			}
			return ""
		}
		if _, err := NewRunner(c); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s set: %v", name, err)
		}
	}
	for name, mod := range map[string]func(*RunnerConfig){
		"no audit":       func(c *RunnerConfig) { c.Audit = nil },
		"no limits":      func(c *RunnerConfig) { c.Limits = Limits{} },
		"no keys":        func(c *RunnerConfig) { c.Targets = map[string]Target{"s": {Name: "s", CredentialsFile: "/x"}} },
		"no credentials": func(c *RunnerConfig) { c.Targets = map[string]Target{"s": {Name: "s", Keys: testKeys}} },
		"a misnamed entry": func(c *RunnerConfig) {
			c.Targets = map[string]Target{"s": {Name: "t", CredentialsFile: "/x", Keys: testKeys}}
		},
	} {
		c := ok
		mod(&c)
		if _, err := NewRunner(c); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// docs/10 D9: SOPS's own loggers write nowhere. They name keys and
// files, and Nyyrikki's log is agent-readable.
func TestSOPSLoggingIsDiscarded(t *testing.T) {
	if len(logging.Loggers) == 0 {
		t.Fatal("the SOPS library registered no logger: this test checks nothing")
	}
	for name, lg := range logging.Loggers {
		if lg.Out != io.Discard {
			t.Errorf("SOPS logger %q still writes somewhere", name)
		}
	}
}

// A failure after the data key was there, a panic of the library's
// included, is the result's fault, never Cloud KMS's (docs/10 D9).
func TestFailuresAfterTheDataKey(t *testing.T) {
	e := newEnv(t)
	plain := "list:\n    - a\n    - b\nsecret: x\n"
	enc := regexFile(t, e.fake, plain, "")
	// A key into a list: SOPS's Set asserts an index and panics.
	req := mustParse(t, enc, append([]string{"set"}, yamlFlags(`["list"]["k"]`, `"v"`)...)...)
	out, err := e.run(t, req)
	if out != nil {
		t.Fatalf("output: %q", out)
	}
	wantCode(t, err, codes.InvalidRequest, DetailNotWritable)
	if fin := e.audit.last(codes.KindRunFinished); fin.Detail != DetailNotWritable || len(fin.KMSKeys) != 1 {
		t.Fatalf("run_finished: %+v", fin)
	}
	// A dotenv file can't hold a branch.
	env := e.fake.Encrypt(t, "dotenv", "A=one\n", sopstest.KeyProd, nil)
	req = mustParse(t, env, "set", "--input-type", "dotenv", "--filename-override", "f.env", `["B"]`, `{"c": 1}`)
	out, err = e.run(t, req)
	if out != nil {
		t.Fatalf("output: %q", out)
	}
	wantCode(t, err, codes.InvalidRequest, DetailNotWritable)

	// A value set through another replaces it, as the message said.
	sec := encrypted(t, e.fake)
	out, err = e.run(t, mustParse(t, sec, append([]string{"set"}, yamlFlags(`["stringData"]["user"]["name"]`, `"app"`)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.readBack(t, out); !strings.Contains(got, "    user:\n        name: app\n") {
		t.Fatalf("set through a value: %q", got)
	}
}
