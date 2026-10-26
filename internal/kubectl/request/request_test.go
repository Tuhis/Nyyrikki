package request

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

func mustParse(t *testing.T, args []string, stdin []byte, interactive bool) *Canonical {
	t.Helper()
	c, err := Parse(args, stdin, interactive)
	if err != nil {
		t.Fatalf("Parse(%q) = %v, want success", args, err)
	}
	return c
}

func wantRefused(t *testing.T, args []string, stdin []byte, interactive bool, detail string) {
	t.Helper()
	c, err := Parse(args, stdin, interactive)
	if err == nil {
		t.Fatalf("Parse(%q) = %q, want refusal %s", args, c.Argv(), detail)
	}
	if codes.Of(err) != codes.InvalidRequest {
		t.Fatalf("Parse(%q) code = %s, want invalid_request", args, codes.Of(err))
	}
	if detail != "" && codes.DetailOf(err) != detail {
		t.Fatalf("Parse(%q) detail = %q (%v), want %q", args, codes.DetailOf(err), err, detail)
	}
}

// spellings returns the ways pflag accepts to set a flag: long with "=",
// long with a separate value, shorthand forms, before and after the
// command. base is the command path plus a positional; the flag is
// inserted around it.
func spellings(long, short, value string, isBool bool) [][]string {
	var forms [][]string
	if isBool {
		forms = append(forms, []string{"--" + long}, []string{"--" + long + "=true"}, []string{"--" + long + "=1"})
		// pflag normalises "_" to "-" through kubectl's normaliser.
		forms = append(forms, []string{"--" + strings.ReplaceAll(long, "-", "_")})
		if short != "" {
			forms = append(forms, []string{"-" + short})
		}
		return forms
	}
	forms = append(forms,
		[]string{"--" + long + "=" + value},
		[]string{"--" + long, value},
		[]string{"--" + strings.ReplaceAll(long, "-", "_") + "=" + value},
	)
	if short != "" {
		forms = append(forms,
			[]string{"-" + short + value},
			[]string{"-" + short, value},
			[]string{"-" + short + "=" + value},
		)
	}
	return forms
}

// TestParseDenied covers docs/04 G1: every denied flag of D4, in every
// spelling pflag accepts, before and after the command.
func TestParseDenied(t *testing.T) {
	type tc struct {
		long, short string
		cmd         []string // command path and positionals
		value       string
		isBool      bool
		global      bool // may also appear before the command
	}
	get := []string{"get", "pods"}
	cases := []tc{
		{long: "kubeconfig", cmd: get, value: "/etc/x", global: true},
		{long: "context", cmd: get, value: "other", global: true},
		{long: "cluster", cmd: get, value: "other", global: true},
		{long: "user", cmd: get, value: "admin", global: true},
		{long: "server", short: "s", cmd: get, value: "https://evil.example", global: true},
		{long: "token", cmd: get, value: "abc", global: true},
		{long: "username", cmd: get, value: "admin", global: true},
		{long: "password", cmd: get, value: "pw", global: true},
		{long: "client-certificate", cmd: get, value: "/etc/x", global: true},
		{long: "client-key", cmd: get, value: "/etc/x", global: true},
		{long: "certificate-authority", cmd: get, value: "/etc/x", global: true},
		{long: "insecure-skip-tls-verify", cmd: get, isBool: true, global: true},
		{long: "tls-server-name", cmd: get, value: "x", global: true},
		{long: "as", cmd: get, value: "system:admin", global: true},
		{long: "as-group", cmd: get, value: "system:masters", global: true},
		{long: "as-uid", cmd: get, value: "0", global: true},
		{long: "cache-dir", cmd: get, value: "/tmp/x", global: true},
		{long: "kuberc", cmd: get, value: "/tmp/kuberc", global: true},
		{long: "profile", cmd: get, value: "cpu", global: true},
		{long: "profile-output", cmd: get, value: "/tmp/x", global: true},
		{long: "filename", short: "f", cmd: []string{"apply"}, value: "/etc/nyyrikki/tls/tls.key"},
		{long: "filename", short: "f", cmd: []string{"apply"}, value: "https://evil.example/x.yaml"},
		{long: "filename", short: "f", cmd: []string{"delete"}, value: "./dir"},
		{long: "kustomize", short: "k", cmd: []string{"apply"}, value: "/etc"},
		{long: "from-file", cmd: []string{"create", "secret", "generic", "s"}, value: "/etc/nyyrikki/tls/tls.key"},
		{long: "from-file", cmd: []string{"create", "configmap", "c"}, value: "k=/etc/passwd"},
		{long: "from-env-file", cmd: []string{"create", "configmap", "c"}, value: "/etc/x"},
		{long: "custom", cmd: []string{"debug", "pod/x"}, value: "/etc/x"},
		{long: "edit", cmd: []string{"create", "-f", "-"}, isBool: true},
		{long: "patch-file", cmd: []string{"patch", "deploy", "d"}, value: "/etc/x"},
		{long: "cert", cmd: []string{"create", "secret", "tls", "t", "--key=/k"}, value: "/etc/nyyrikki/tls/tls.crt"},
		{long: "key", cmd: []string{"create", "secret", "tls", "t", "--cert=/c"}, value: "/etc/nyyrikki/tls/tls.key"},
	}
	for _, c := range cases {
		for _, form := range spellings(c.long, c.short, c.value, c.isBool) {
			after := append(slices.Clone(c.cmd), form...)
			wantRefused(t, after, nil, false, DetailFlagDenied)
			// In the middle of the command line, between positionals.
			if len(c.cmd) > 1 {
				mid := append(append(slices.Clone(c.cmd[:1]), form...), c.cmd[1:]...)
				wantRefused(t, mid, nil, false, DetailFlagDenied)
			}
			if c.global {
				before := append(slices.Clone(form), c.cmd...)
				wantRefused(t, before, nil, false, DetailFlagDenied)
			}
		}
	}

	// Combined shorthands: -s hidden after -i in one word.
	wantRefused(t, []string{"exec", "-is", "https://evil.example", "web", "--", "sh"}, nil, false, DetailFlagDenied)
	wantRefused(t, []string{"exec", "-ishttps://evil.example", "web", "--", "sh"}, nil, false, DetailFlagDenied)
	// A filename that is "-" once, then something else.
	wantRefused(t, []string{"apply", "-f", "-", "-f", "/etc/x"}, nil, false, DetailFlagDenied)
	wantRefused(t, []string{"apply", "-f", "-", "-f", "-"}, nil, false, DetailFlagDenied)
	wantRefused(t, []string{"apply", "--filename=-,/etc/x"}, nil, false, DetailFlagDenied)

	// Output formats that read a local template file, with the path in
	// --output or in --template.
	for _, out := range [][]string{
		{"-o", "jsonpath-file=/etc/x"},
		{"-ojsonpath-file=/etc/x"},
		{"--output=go-template-file=/etc/x"},
		{"-o", "go-template-file", "--template", "/etc/nyyrikki/tls/tls.key"},
		{"-o", "templatefile", "--template=/etc/x"},
		{"-o", "custom-columns-file=/etc/x"},
		{"-o", "Custom-Columns-File=/etc/x"},
		{"--output", " JSONPATH-FILE=/etc/x"},
	} {
		wantRefused(t, append([]string{"get", "pods"}, out...), nil, false, DetailFlagDenied)
		wantRefused(t, append(slices.Clone(out), "get", "pods"), nil, false, "")
	}
}

// TestParseDeniedCommands covers docs/04 D5 and §5.4: commands outside the
// allowlist are refused, wherever the global flags put them.
func TestParseDeniedCommands(t *testing.T) {
	for _, args := range [][]string{
		{"config", "view", "--raw"},
		{"-n", "x", "config", "view"},
		{"--namespace=x", "config", "view"},
		{"proxy"},
		{"port-forward", "pod/x", "8080:80"},
		{"cp", "x:/etc/passwd", "/tmp/x"},
		{"edit", "deploy/x"},
		{"apply", "edit-last-applied", "deploy/x"},
		{"diff", "-f", "-"},
		{"plugin", "list"},
		{"kuberc", "view"},
		{"completion", "bash"},
		{"kustomize", "."},
		{"alpha"},
		{"cluster-info", "dump"},
		{"options"},
		{"help", "get"},
		{"rollout"},
		{"set"},
		{"nosuchcommand"},
		{"-n", "shop"},
		{"--", "get", "pods"},
	} {
		wantRefused(t, args, nil, false, "")
	}
	for _, args := range [][]string{
		{"config", "view"},
		{"cluster-info", "dump"},
		{"apply", "edit-last-applied", "x"},
	} {
		wantRefused(t, args, nil, false, DetailCommandNotAllowed)
	}
}

// TestParseUnknownFlags covers docs/04 M1: klog's -v and anything kubectl
// doesn't define are parse errors.
func TestParseUnknownFlags(t *testing.T) {
	for _, args := range [][]string{
		{"get", "pods", "-v", "9"},
		{"get", "pods", "--v=9"},
		{"-v9", "get", "pods"},
		{"get", "pods", "--help"},
		{"get", "pods", "--log-file=/tmp/x"},
		{"get", "pods", "--nonsense"},
	} {
		wantRefused(t, args, nil, false, DetailParse)
	}
	wantRefused(t, nil, nil, false, DetailEmpty)
}

// TestRenderRoundTrip covers docs/04 G2.
func TestRenderRoundTrip(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
		cmd  string
	}{
		{[]string{"-n", "shop", "get", "pods"}, []string{"get", "--namespace=shop", "pods"}, "get"},
		{[]string{"-nshop", "exec", "-it", "web", "--", "sh", "-c", "ls -l"},
			[]string{"exec", "--namespace=shop", "--stdin=true", "--tty=true", "web", "--", "sh", "-c", "ls -l"}, "exec"},
		{[]string{"get", "pods", "-L", "a,b", "-L", "c"},
			[]string{"get", "--label-columns=a", "--label-columns=b", "--label-columns=c", "pods"}, "get"},
		{[]string{"rollout", "restart", "deploy/x", "-n", "shop"},
			[]string{"rollout", "restart", "--namespace=shop", "deploy/x"}, "rollout restart"},
		{[]string{"get", "--", "pods"}, []string{"get", "--", "pods"}, "get"},
		{[]string{"exec", "web", "--", "--kubeconfig=/etc/x", "-s", "x"},
			[]string{"exec", "web", "--", "--kubeconfig=/etc/x", "-s", "x"}, "exec"},
		{[]string{"get", "pods", "--watch=false", "-o=json"},
			[]string{"get", "--output=json", "--watch=false", "pods"}, "get"},
		{[]string{"run", "x", "--image=busybox", "--env=A=B,C", "--", "sh"},
			[]string{"run", "--env=A=B,C", "--image=busybox", "x", "--", "sh"}, "run"},
		{[]string{"apply", "-f", "-"}, []string{"apply", "--filename=-"}, "apply"},
		{[]string{"apply", "-f=-"}, []string{"apply", "--filename=-"}, "apply"},
		{[]string{"top", "pod", "-A"}, []string{"top", "pod", "--all-namespaces=true"}, "top pod"},
		{[]string{"get", "pods", "-n", "a", "-n", "b"}, []string{"get", "--namespace=b", "pods"}, "get"},
	}
	for _, c := range cases {
		got := mustParse(t, c.in, nil, false)
		if !slices.Equal(got.Argv(), c.want) {
			t.Errorf("Parse(%q).Argv() = %q, want %q", c.in, got.Argv(), c.want)
		}
		if got.Command() != c.cmd {
			t.Errorf("Parse(%q).Command() = %q, want %q", c.in, got.Command(), c.cmd)
		}
		again := mustParse(t, got.Argv(), nil, false)
		if !slices.Equal(again.Argv(), got.Argv()) {
			t.Errorf("re-parse of %q = %q", got.Argv(), again.Argv())
		}
	}

	// A slice element with a comma (CSV-quoted) can't be rendered
	// faithfully: --label-columns=a,b would mean two columns.
	wantRefused(t, []string{"get", "pods", "-L", `"a,b"`}, nil, false, DetailCanonicalMismatch)
}

// TestArgvIsACopy checks that a caller can't change what runs.
func TestArgvIsACopy(t *testing.T) {
	c := mustParse(t, []string{"get", "pods"}, nil, false)
	a := c.Argv()
	a[0] = "delete"
	if c.Argv()[0] != "get" {
		t.Fatal("Argv returned the internal slice")
	}
	s := mustParse(t, []string{"apply", "-f", "-"}, []byte("x"), false)
	b := s.Stdin()
	b[0] = 'y'
	if string(s.Stdin()) != "x" {
		t.Fatal("Stdin returned the internal slice")
	}
}

func TestParseStdinAndInteractive(t *testing.T) {
	// Stdin only where kubectl reads it.
	wantRefused(t, []string{"get", "pods"}, []byte("x"), false, DetailStdinNotRead)
	wantRefused(t, []string{"exec", "web", "--", "cat"}, []byte("x"), false, DetailStdinNotRead)
	wantRefused(t, []string{"exec", "-i=false", "web", "--", "cat"}, []byte("x"), false, DetailStdinNotRead)
	for _, args := range [][]string{
		{"apply", "-f", "-"},
		{"exec", "-i", "web", "--", "cat"},
		{"attach", "-i", "web"},
	} {
		c := mustParse(t, args, []byte("data"), false)
		if !c.ReadsStdin() {
			t.Errorf("ReadsStdin(%q) = false", args)
		}
	}
	if mustParse(t, []string{"get", "pods"}, nil, false).ReadsStdin() {
		t.Error("get reads stdin")
	}

	// docs/04 D12: interactive only for exec and attach with -i and -t.
	for _, args := range [][]string{
		{"exec", "-it", "web", "--", "sh"},
		{"exec", "-ti", "web", "--", "sh"},
		{"exec", "--stdin", "--tty", "web", "--", "sh"},
		{"attach", "-it", "web"},
	} {
		if c := mustParse(t, args, nil, true); !c.Interactive() {
			t.Errorf("Interactive(%q) = false", args)
		}
	}
	for _, args := range [][]string{
		{"exec", "-i", "web", "--", "sh"},
		{"exec", "-t", "web", "--", "sh"},
		{"exec", "-it=false", "web", "--", "sh"},
		{"exec", "-i", "--tty=false", "web", "--", "sh"},
		{"get", "pods"},
		{"run", "-it", "x", "--image=busybox"},
		{"debug", "-it", "pod/x", "--image=busybox"},
	} {
		wantRefused(t, args, nil, true, DetailInteractiveNotAllowed)
	}
	wantRefused(t, []string{"exec", "-it", "web", "--", "sh"}, []byte("x"), true, DetailInteractiveStdin)
}

// TestDisplayRedaction covers docs/04 G9: secret-bearing values are
// redacted in the display and the audit record, and still run as sent.
func TestDisplayRedaction(t *testing.T) {
	marker := func(v string) string { return redactedMarker([]byte(v)) }

	c := mustParse(t, []string{"create", "secret", "generic", "s", "--from-literal=user=admin", "--from-literal", "pw=hunter2,x"}, nil, false)
	if !slices.Contains(c.Argv(), "--from-literal=pw=hunter2,x") {
		t.Fatalf("Argv lost the value that runs: %q", c.Argv())
	}
	disp := c.DisplayArgv()
	for _, secret := range []string{"admin", "hunter2"} {
		if strings.Contains(disp, secret) {
			t.Errorf("DisplayArgv shows %q: %s", secret, disp)
		}
		for _, a := range c.Audit().Argv {
			if strings.Contains(a, secret) {
				t.Errorf("Audit argv shows %q: %q", secret, c.Audit().Argv)
			}
		}
	}
	if !strings.Contains(disp, "--from-literal=pw="+marker("hunter2,x")) {
		t.Errorf("DisplayArgv = %s, want the redaction marker with the key", disp)
	}
	if !strings.HasPrefix(marker("hunter2,x"), "‹redacted: 9 bytes, sha256:") {
		t.Errorf("marker = %s", marker("hunter2,x"))
	}

	d := mustParse(t, []string{"create", "secret", "docker-registry", "r", "--docker-server=x", "--docker-username=u", "--docker-password=s3cret!"}, nil, false)
	if strings.Contains(d.DisplayArgv(), "s3cret") || strings.Contains(strings.Join(d.Audit().Argv, " "), "s3cret") {
		t.Errorf("docker-password shown: %s / %q", d.DisplayArgv(), d.Audit().Argv)
	}

	// Secrets in stdin: YAML, JSON, a List, and last-applied.
	stdin := `apiVersion: v1
kind: ConfigMap
metadata:
  name: plain
data:
  visible: "yes"
---
apiVersion: v1
kind: Secret
metadata:
  name: s
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"data":{"pw":"aHVudGVyMg=="}}'
data:
  pw: aHVudGVyMg==
stringData:
  token: tok-hunter2
---
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: secret
  metadata: {name: s2}
  stringData: {k: listed-hunter2}
`
	a := mustParse(t, []string{"apply", "-f", "-"}, []byte(stdin), false)
	shown := a.DisplayStdin()
	for _, secret := range []string{"aHVudGVyMg==", "tok-hunter2", "listed-hunter2"} {
		if strings.Contains(shown, secret) {
			t.Errorf("DisplayStdin shows %q:\n%s", secret, shown)
		}
	}
	for _, want := range []string{"visible", marker("aHVudGVyMg=="), marker("tok-hunter2"), "name: s2"} {
		if !strings.Contains(shown, want) {
			t.Errorf("DisplayStdin lacks %q:\n%s", want, shown)
		}
	}
	if string(a.Stdin()) != stdin {
		t.Error("stdin that runs was changed")
	}
	au := a.Audit()
	sum := sha256.Sum256([]byte(stdin))
	if au.StdinBytes != len(stdin) || au.StdinSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("Audit stdin = %d %s", au.StdinBytes, au.StdinSHA256)
	}

	j := mustParse(t, []string{"apply", "-f", "-"}, []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"j"},"data":{"pw":"czNjcmV0"}}`), false)
	if strings.Contains(j.DisplayStdin(), "czNjcmV0") {
		t.Errorf("JSON secret shown: %s", j.DisplayStdin())
	}

	// No Secret: shown exactly as sent.
	plain := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n# a comment\n"
	if got := mustParse(t, []string{"apply", "-f", "-"}, []byte(plain), false).DisplayStdin(); got != plain {
		t.Errorf("DisplayStdin = %q, want as sent", got)
	}
	// Doesn't decode but mentions a Secret: not shown as text.
	broken := "kind: Secret\ndata:\n  pw: [unclosed\n"
	if got := mustParse(t, []string{"apply", "-f", "-"}, []byte(broken), false).DisplayStdin(); strings.Contains(got, "unclosed") || !strings.HasPrefix(got, "‹binary:") {
		t.Errorf("DisplayStdin of an undecodable Secret = %q", got)
	}
}

func TestDisplayEscaping(t *testing.T) {
	c := mustParse(t, []string{"exec", "web", "--", "sh", "-c", "echo 'hi'", "", "a\u202eb", "x\x1by", "zero\u200bwidth", "ok-chars_@%+=:,./"}, nil, false)
	got := c.DisplayArgv()
	want := `kubectl exec web -- sh -c 'echo '\''hi'\''' '' 'a\u{202e}b' 'x\u{1b}y' 'zero\u{200b}width' ok-chars_@%+=:,./`
	if got != want {
		t.Errorf("DisplayArgv =\n%s\nwant\n%s", got, want)
	}

	if got := mustParse(t, []string{"exec", "-i", "web", "--", "cat"}, []byte("line\r\nnext\ttab\n"), false).DisplayStdin(); got != "line\r\nnext\ttab\n" {
		t.Errorf("text stdin = %q", got)
	}
	for _, in := range []string{"\x00\x01binary", "esc\x1b[31m", "bidi\u202e", "bad\xff"} {
		got := mustParse(t, []string{"exec", "-i", "web", "--", "cat"}, []byte(in), false).DisplayStdin()
		if !strings.HasPrefix(got, "‹binary: ") {
			t.Errorf("DisplayStdin(%q) = %q, want binary form", in, got)
		}
	}
	if got := mustParse(t, []string{"get", "pods"}, nil, false).DisplayStdin(); got != "" {
		t.Errorf("DisplayStdin without stdin = %q", got)
	}
}

func TestDigest(t *testing.T) {
	base := mustParse(t, []string{"apply", "-f", "-"}, []byte("a"), false)
	d := Digest("prod", base)
	if d != Digest("prod", mustParse(t, []string{"apply", "--filename=-"}, []byte("a"), false)) {
		t.Error("the same canonical request has two digests")
	}
	for name, other := range map[string][32]byte{
		"target": Digest("lab", base),
		"stdin":  Digest("prod", mustParse(t, []string{"apply", "-f", "-"}, []byte("b"), false)),
		"argv":   Digest("prod", mustParse(t, []string{"apply", "-f", "-", "-n", "x"}, []byte("a"), false)),
	} {
		if other == d {
			t.Errorf("digest ignores the %s", name)
		}
	}
	// The boundary between argv and stdin is unambiguous.
	x := &Canonical{argv: []string{"a"}, stdin: []byte("\x00\x00\x00\x00\x00\x00\x00\x01z\x00")}
	y := &Canonical{argv: []string{"a", "z"}}
	if Digest("t", x) == Digest("t", y) {
		t.Error("argv/stdin boundary collision")
	}
}

// TestParseConcurrent checks that building kubectl's tree from several
// goroutines is safe (run with -race).
func TestParseConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := Parse([]string{"get", "pods", "-n", "x"}, nil, false); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

// FuzzParse covers docs/04 G1/G2: Parse never panics, a request it accepts
// re-parses to the same canonical argv, and nothing it accepts carries a
// denied flag.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"get\x00pods", "-n\x00shop\x00get\x00pods", "-nshop\x00exec\x00-it\x00web\x00--\x00sh",
		"apply\x00-f\x00-", "get\x00pods\x00-L\x00a,b", "create\x00secret\x00generic\x00s\x00--from-literal=a=b",
		"exec\x00-is\x00x\x00web", "get\x00pods\x00-o\x00jsonpath-file=/x", "rollout\x00restart\x00deploy/x",
		"get\x00--\x00pods", "run\x00x\x00--image=y\x00--\x00--kubeconfig=z",
	} {
		f.Add(s, []byte(nil), false)
	}
	f.Fuzz(func(t *testing.T, joined string, stdin []byte, interactive bool) {
		args := strings.Split(joined, "\x00")
		if len(args) > 64 {
			return
		}
		c, err := Parse(args, stdin, interactive)
		if err != nil {
			if codes.Of(err) != codes.InvalidRequest {
				t.Fatalf("refusal with code %s", codes.Of(err))
			}
			return
		}
		again, err := Parse(c.Argv(), stdin, interactive)
		if err != nil {
			t.Fatalf("canonical %q doesn't re-parse: %v", c.Argv(), err)
		}
		if !slices.Equal(again.Argv(), c.Argv()) {
			t.Fatalf("round trip %q -> %q", c.Argv(), again.Argv())
		}
		for _, fv := range c.flags {
			if flagDenied(fv) != "" {
				t.Fatalf("accepted denied flag %s in %q", fv.name, c.Argv())
			}
		}
		if !commandAllowed(c.path) {
			t.Fatalf("accepted command %q", c.Command())
		}
		_ = c.DisplayArgv()
		_ = c.DisplayStdin()
	})
}

// TestDisplayRedactsSecretPatch: a patch to a Secret carries its values
// in --patch, which must not reach Telegram or the audit log (docs/04
// D14, found in review of the docs PR). Patches to anything else stay
// visible in full.
func TestDisplayRedactsSecretPatch(t *testing.T) {
	const value = "c3VwZXJzZWNyZXQ="
	for _, args := range [][]string{
		{"patch", "secret", "db", "-p", `{"data":{"pw":"` + value + `"}}`},
		{"patch", "secrets", "db", "--type=json", "-p", `[{"op":"replace","path":"/data/pw","value":"` + value + `"}]`},
		{"patch", "secret/db", "-n", "shop", "--patch", `{"stringData":{"pw":"` + value + `"}}`},
		{"patch", "secrets/db", "-p", `{"data":{"pw":"` + value + `"}}`},
		{"patch", "Secret", "db", "-p", `{"data":{"pw":"` + value + `"}}`},
		{"patch", "secrets.v1.", "db", "-p", `{"data":{"pw":"` + value + `"}}`},
		{"patch", "-f", "-", "-p", `{"data":{"pw":"` + value + `"}}`},
	} {
		var stdin []byte
		if args[1] == "-f" {
			stdin = []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n")
		}
		c, err := Parse(args, stdin, false)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		shown := c.DisplayArgv() + " " + strings.Join(c.Audit().Argv, " ")
		if strings.Contains(shown, value) {
			t.Errorf("%v: secret value shown: %s", args, shown)
		}
		if !strings.Contains(c.DisplayArgv(), "redacted") {
			t.Errorf("%v: no redaction marker: %s", args, c.DisplayArgv())
		}
		// What runs is unchanged.
		if !strings.Contains(strings.Join(c.Argv(), " "), value) {
			t.Errorf("%v: the forwarded argv lost the value", args)
		}
	}
	c, err := Parse([]string{"patch", "deployment", "api", "-p", `{"spec":{"replicas":3}}`}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.DisplayArgv(), "replicas") {
		t.Errorf("a non-Secret patch was redacted: %s", c.DisplayArgv())
	}
}
