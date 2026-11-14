package sopstarget

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getsops/sops/v3"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/sopstarget/sopstest"
)

// docs/10 G1: only the offered commands, flags and types parse; every
// other request is refused before any approval, with a fixed detail.
func TestParseRefusesWhatIsNotOffered(t *testing.T) {
	f := sopstest.New(t)
	enc := encrypted(t, f)
	plain := []byte(secretYAML)
	path := `["stringData"]["password"]`
	long := strings.Repeat("a", MaxFileName+1)
	cases := []struct {
		name   string
		args   []string
		stdin  []byte
		detail string
	}{
		{"no command", nil, enc, DetailNoCommand},
		{"rotate", append([]string{"rotate"}, yamlFlags()...), enc, DetailUnknownCommand},
		{"updatekeys", append([]string{"updatekeys"}, yamlFlags()...), enc, DetailUnknownCommand},
		{"edit", append([]string{"edit"}, yamlFlags()...), enc, DetailUnknownCommand},
		{"exec-env", append([]string{"exec-env"}, yamlFlags("env")...), enc, DetailUnknownCommand},
		{"publish", append([]string{"publish"}, yamlFlags()...), enc, DetailUnknownCommand},
		{"keyservice", []string{"keyservice"}, enc, DetailUnknownCommand},
		{"a flag first", append([]string{"--input-type=yaml", "decrypt"}, yamlFlags()...), enc, DetailUnknownCommand},
		{"ignore-mac", append([]string{"decrypt", "--ignore-mac"}, yamlFlags()...), enc, DetailUnknownFlag},
		{"ignore-mac on set", append([]string{"set", "--ignore-mac=true"}, yamlFlags(path, `"x"`)...), enc, DetailUnknownFlag},
		{"output file", append([]string{"decrypt", "--output", "/tmp/x"}, yamlFlags()...), enc, DetailUnknownFlag},
		{"in place", append([]string{"encrypt", "--in-place"}, yamlFlags("--gcp-kms", sopstest.KeyProd)...), plain, DetailUnknownFlag},
		{"an age key", append([]string{"encrypt", "--age", "age1x"}, yamlFlags("--gcp-kms", sopstest.KeyProd)...), plain, DetailUnknownFlag},
		{"an AWS key", append([]string{"encrypt", "--kms", "arn:aws:kms:x"}, yamlFlags("--gcp-kms", sopstest.KeyProd)...), plain, DetailUnknownFlag},
		{"a key service", append([]string{"decrypt", "--keyservice", "tcp://evil:1"}, yamlFlags()...), enc, DetailUnknownFlag},
		{"a config file", append([]string{"decrypt", "--config", "/etc/x"}, yamlFlags()...), enc, DetailUnknownFlag},
		{"a short flag", append([]string{"decrypt", "-d"}, yamlFlags()...), enc, DetailUnknownFlag},
		{"extract on set", append([]string{"set", "--extract", path}, yamlFlags(path, `"x"`)...), enc, DetailUnknownFlag},
		{"output-type on encrypt", append([]string{"encrypt", "--output-type", "json"}, yamlFlags("--gcp-kms", sopstest.KeyProd)...), plain, DetailUnknownFlag},
		{"gcp-kms on decrypt", append([]string{"decrypt", "--gcp-kms", sopstest.KeyProd}, yamlFlags()...), enc, DetailUnknownFlag},
		{"no input type", []string{"decrypt", "--filename-override", "a.yaml"}, enc, DetailMissingFlag},
		{"no file name", []string{"decrypt", "--input-type", "yaml"}, enc, DetailMissingFlag},
		{"ini", []string{"decrypt", "--input-type", "ini", "--filename-override", "a"}, enc, DetailFlagValue},
		{"binary", []string{"decrypt", "--input-type", "binary", "--filename-override", "a"}, enc, DetailFlagValue},
		{"binary output", append([]string{"decrypt", "--output-type", "binary"}, yamlFlags()...), enc, DetailFlagValue},
		{"a flag twice", append([]string{"decrypt", "--input-type", "json"}, yamlFlags()...), enc, DetailDuplicateFlag},
		{"a flag without a value", []string{"decrypt", "--filename-override", "a", "--input-type"}, enc, DetailFlagValue},
		{"a file argument", append([]string{"decrypt"}, yamlFlags("secret.yaml")...), enc, DetailArguments},
		{"set without a value", append([]string{"set"}, yamlFlags(path)...), enc, DetailArguments},
		{"unset with a value", append([]string{"unset"}, yamlFlags(path, "x")...), enc, DetailArguments},
		{"a long name", []string{"decrypt", "--input-type", "yaml", "--filename-override", long}, enc, DetailFlagValue},
		{"an empty name", []string{"decrypt", "--input-type", "yaml", "--filename-override", ""}, enc, DetailFlagValue},
		{"a name with a newline", []string{"decrypt", "--input-type", "yaml", "--filename-override", "a\nRuns as: root"}, enc, DetailFlagValue},
		{"a name with a bidi control", []string{"decrypt", "--input-type", "yaml", "--filename-override", "a\u202eb"}, enc, DetailFlagValue},
		{"a dotted path", append([]string{"unset"}, yamlFlags("stringData.password")...), enc, DetailPath},
		{"an open path", append([]string{"unset"}, yamlFlags(`["stringData"`)...), enc, DetailPath},
		{"a key holding a bracket", append([]string{"unset"}, yamlFlags(`["a[b"]`)...), enc, DetailPath},
		{"a key holding its quote", append([]string{"unset"}, yamlFlags(`["a"b"]`)...), enc, DetailPath},
		{"a negative index", append([]string{"unset"}, yamlFlags("--", `[-1]`)...), enc, DetailPath},
		{"an empty path", append([]string{"decrypt", "--extract", ""}, yamlFlags()...), enc, DetailPath},
		{"a value that isn't JSON", append([]string{"set"}, yamlFlags(path, "hunter3")...), enc, DetailFlagValue},
		{"no key for encrypt", append([]string{"encrypt"}, yamlFlags()...), plain, DetailMissingFlag},
		{"two keys for encrypt", append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd + "," + sopstest.KeyOther}, yamlFlags()...), plain, DetailFlagValue},
		{"a key version", append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd + "/cryptoKeyVersions/1"}, yamlFlags()...), plain, DetailFlagValue},
		{"a key outside the target", append([]string{"encrypt", "--gcp-kms", sopstest.KeyForeign}, yamlFlags()...), plain, DetailKeyNotAllowed},
		{"two rules", append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd, "--encrypted-regex", "a", "--unencrypted-suffix", "b"}, yamlFlags()...), plain, DetailArguments},
		{"a bad regex", append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd, "--encrypted-regex", "("}, yamlFlags()...), plain, DetailFlagValue},
		{"no file", append([]string{"decrypt"}, yamlFlags()...), nil, DetailNoFile},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Parse(c.args, c.stdin, false, testKeys)
			if r != nil {
				t.Fatalf("parsed: %v", r.Argv())
			}
			wantCode(t, err, codes.InvalidRequest, c.detail)
		})
	}
	if _, err := Parse(append([]string{"decrypt"}, yamlFlags()...), enc, true, testKeys); codes.DetailOf(err) != DetailInteractive {
		t.Fatalf("an interactive run: %v", err)
	}
	if calls := f.Calls(); len(calls) != 0 {
		t.Fatalf("Parse called Cloud KMS: %+v", calls)
	}
}

// docs/10 D3: the canonical argv parses back to itself, whatever form
// the flags were given in, and the digest follows it.
func TestCanonicalForm(t *testing.T) {
	f := sopstest.New(t)
	enc := encrypted(t, f)
	a := mustParse(t, enc, "decrypt", "--input-type", "yaml", "--filename-override=a.yaml", "--extract", `["stringData"]["user"]`)
	b := mustParse(t, enc, "decrypt", `--extract=["stringData"]["user"]`, "--filename-override", "a.yaml", "--input-type=yaml")
	want := []string{"decrypt", `--extract=["stringData"]["user"]`, "--filename-override=a.yaml", "--input-type=yaml"}
	if got := a.Argv(); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("canonical argv: %q", got)
	}
	if a.Digest("t", "") != b.Digest("t", "") {
		t.Fatal("two spellings of one request have different digests")
	}
	again := mustParse(t, enc, a.Argv()...)
	if strings.Join(again.Argv(), "\x00") != strings.Join(want, "\x00") || again.Digest("t", "") != a.Digest("t", "") {
		t.Fatalf("the canonical argv doesn't parse back to itself: %q", again.Argv())
	}

	// A value that starts with "-" goes after "--", and stays there.
	s := mustParse(t, enc, append([]string{"set"}, yamlFlags("--", `["stringData"]["n"]`, "-1")...)...)
	if got := s.Argv(); got[len(got)-3] != "--" || got[len(got)-1] != "-1" {
		t.Fatalf("canonical argv of a set: %q", got)
	}
	if again := mustParse(t, enc, s.Argv()...); again.Digest("t", "") != s.Digest("t", "") {
		t.Fatal("the canonical argv of a set doesn't parse back to itself")
	}

	// The digest covers the target, the argv and the file.
	other := mustParse(t, enc, "decrypt", "--input-type", "yaml", "--filename-override=b.yaml", "--extract", `["stringData"]["user"]`)
	enc2 := encrypted(t, f)
	file2 := mustParse(t, enc2, a.Argv()...)
	for name, d := range map[string][32]byte{"target": a.Digest("u", ""), "argv": other.Digest("t", ""), "file": file2.Digest("t", "")} {
		if d == a.Digest("t", "") {
			t.Fatalf("the digest doesn't cover the %s", name)
		}
	}
	if a.Digest("t", "x") != a.Digest("t", "y") {
		t.Fatal("the digest depends on who it runs as")
	}
	if a.Type() != codes.TypeSOPS || a.Interactive() {
		t.Fatal("type or interactive")
	}
}

// editYAML replaces old with new in an encrypted file, once.
func editYAML(t *testing.T, enc []byte, old, new string) []byte {
	t.Helper()
	if !bytes.Contains(enc, []byte(old)) {
		t.Fatalf("the file has no %q", old)
	}
	return bytes.Replace(enc, []byte(old), []byte(new), 1)
}

// gcpEntry is a gcp_kms entry of an encrypted file's metadata.
func gcpEntry(key, enc string) string {
	return "        - created_at: \"2026-11-13T00:00:00Z\"\n          enc: " + enc + "\n          resource_id: " + key + "\n"
}

// docs/10 G2: a file the target can't take is refused before the
// approval, and nothing is called.
func TestParseRefusesFiles(t *testing.T) {
	f := sopstest.New(t)
	enc := encrypted(t, f)
	before := len(f.Calls())
	decrypt := append([]string{"decrypt"}, yamlFlags()...)
	vault := "    hc_vault:\n        - vault_address: http://127.0.0.1:1\n          engine_path: sops\n          key_name: k\n          created_at: \"2026-11-13T00:00:00Z\"\n          enc: vault:v1:x\n"
	groups := "    key_groups:\n        - gcp_kms:\n" + gcpEntryIndented(sopstest.KeyProd) + "        - gcp_kms:\n" + gcpEntryIndented(sopstest.KeyOther) + "    shamir_threshold: 2\n"
	cases := []struct {
		name   string
		args   []string
		stdin  []byte
		detail string
	}{
		{"not YAML", decrypt, []byte("a: [1, 2\n"), DetailFileNotParsed},
		{"no metadata", decrypt, []byte(secretYAML), DetailNotEncrypted},
		{"JSON read as YAML with no metadata", decrypt, []byte(`{"a": 1}`), DetailNotEncrypted},
		{"a key outside the target", decrypt, editYAML(t, enc, "resource_id: "+sopstest.KeyProd, "resource_id: "+sopstest.KeyForeign), DetailKeyNotAllowed},
		{"a key twice", decrypt, editYAML(t, enc, "    lastmodified:", gcpEntry(sopstest.KeyProd, "anVuaw==")+"    lastmodified:"), DetailDuplicateKey},
		{"a Vault key as well", decrypt, editYAML(t, enc, "    lastmodified:", vault+"    lastmodified:"), DetailKeyType},
		{"only a Vault key", decrypt, editYAML(t, removeGCP(t, enc), "    lastmodified:", vault+"    lastmodified:"), DetailKeyType},
		{"no key", decrypt, removeGCP(t, enc), DetailFileNotParsed},
		{"two key groups", decrypt, editYAML(t, removeGCP(t, enc), "    lastmodified:", groups+"    lastmodified:"), DetailKeyGroups},
		{"two documents", decrypt, append(append([]byte{}, enc...), []byte("---\nb: 1\n")...), DetailDocuments},
		{"extract of nothing", append([]string{"decrypt", "--extract", `["stringData"]["nope"]`}, yamlFlags()...), enc, DetailPathNotFound},
		{"extract through a scalar", append([]string{"decrypt", "--extract", `["kind"]["x"]`}, yamlFlags()...), enc, DetailPathNotFound},
		{"unset of nothing", append([]string{"unset"}, yamlFlags(`["data"]`)...), enc, DetailPathNotFound},
		{"encrypt of an encrypted file", append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd}, yamlFlags()...), enc, DetailAlreadyEncrypted},
		{"encrypt of what isn't YAML", append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd}, yamlFlags()...), []byte("a: [1\n"), DetailFileNotParsed},
		{"a file nested too deep", decrypt, deepFile(t, enc), DetailTooDeep},
		{"a rule that isn't a regular expression", decrypt, editYAML(t, enc, "encrypted_regex: "+secretRegex, "encrypted_regex: (("), DetailFileRules},
		{"a very long rule", decrypt, editYAML(t, enc, "encrypted_regex: "+secretRegex, "encrypted_regex: ^("+strings.Repeat("a|", maxRule)+"b)$"), DetailFileRules},
		{"a very long suffix", decrypt, editYAML(t, enc, "encrypted_regex: "+secretRegex, "unencrypted_suffix: "+strings.Repeat("x", maxRule+1)), DetailFileRules},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Parse(c.args, c.stdin, false, testKeys)
			if r != nil {
				t.Fatalf("parsed: %v", r.Argv())
			}
			wantCode(t, err, codes.InvalidRequest, c.detail)
			noLibraryText(t, "the refusal", err.Error())
		})
	}
	if n := len(f.Calls()); n != before {
		t.Fatalf("Parse called Cloud KMS %d times", n-before)
	}
}

func gcpEntryIndented(key string) string {
	return "            - created_at: \"2026-11-13T00:00:00Z\"\n              enc: anVuaw==\n              resource_id: " + key + "\n"
}

// removeGCP drops the gcp_kms block of an encrypted file's metadata.
func removeGCP(t *testing.T, enc []byte) []byte {
	t.Helper()
	s := string(enc)
	i := strings.Index(s, "    gcp_kms:\n")
	j := strings.Index(s, "    lastmodified:")
	if i < 0 || j < i {
		t.Fatal("the file has no gcp_kms block")
	}
	return []byte(s[:i] + s[j:])
}

// deepFile puts a value nested deeper than maxDepth into a file.
func deepFile(t *testing.T, enc []byte) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString("deep: ")
	for i := 0; i <= maxDepth+2; i++ {
		b.WriteString("{a: ")
	}
	b.WriteString("1")
	for i := 0; i <= maxDepth+2; i++ {
		b.WriteString("}")
	}
	b.WriteString("\n")
	return append([]byte(b.String()), enc...)
}

// docs/10 D8, G5: what the message says of a request.
func TestAsks(t *testing.T) {
	f := sopstest.New(t)
	enc := encrypted(t, f)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"decrypt"}, "Decrypt and return the whole file (2 encrypted values)"},
		{[]string{"decrypt", "--extract", `["stringData"]["password"]`}, `Decrypt and return one value: ["stringData"]["password"]`},
		{[]string{"decrypt", "--extract", `['stringData']`}, `Decrypt and return everything under: ["stringData"] (2 values)`},
		{[]string{"set", `["stringData"]["password"]`, `"n3w-pass"`}, `Change one value: ["stringData"]["password"] (new value not shown)`},
		{[]string{"set", `["stringData"]["token"]`, `"t"`}, `Add a value: ["stringData"]["token"] (new value not shown)`},
		{[]string{"set", `["stringData"]`, `{"only":"this"}`}, `Replace everything under: ["stringData"] (2 values; new value not shown)`},
		{[]string{"set", `["kind"]["x"]`, `"y"`}, `Replace the value at ["kind"] with a branch, to add: ["kind"]["x"] (new value not shown)`},
		{[]string{"set", `["stringData"]["user"]["a"]["b"]`, `1`}, `Replace the value at ["stringData"]["user"] with a branch, to add: ["stringData"]["user"]["a"]["b"] (new value not shown)`},
		{[]string{"unset", `["stringData"]["user"]`}, `Remove one value: ["stringData"]["user"]`},
		{[]string{"unset", `["metadata"]`}, `Remove everything under: ["metadata"] (2 values)`},
	}
	for _, c := range cases {
		r := mustParse(t, enc, append(c.args[:1:1], append(yamlFlags(), c.args[1:]...)...)...)
		p := r.Prompt()
		if p.Asks != c.want {
			t.Errorf("%v asks %q; want %q", c.args, p.Asks, c.want)
		}
		if p.FileName != "clusters/prod/shop/db-creds.enc.yaml" || !p.ShowSays || len(p.KMSKeys) != 1 || p.KMSKeys[0] != sopstest.KeyProd {
			t.Errorf("%v: prompt %+v", c.args, p)
		}
		want := []string{`["apiVersion"] = "v1"`, `["kind"] = "Secret"`, `["metadata"]["name"] = "db-creds"`, `["metadata"]["namespace"] = "shop"`}
		if strings.Join(p.Says, "\n") != strings.Join(want, "\n") {
			t.Errorf("%v: the file says %q", c.args, p.Says)
		}
		// No encrypted path the request doesn't name, and no ciphertext.
		all := p.Asks + strings.Join(p.Says, "\n") + r.DisplayCommand() + r.DisplayStdin()
		if strings.Contains(all, "ENC[") || (!strings.Contains(strings.Join(c.args, " "), "user") && strings.Contains(all, "user")) {
			t.Errorf("%v shows more of the file than was asked: %s", c.args, all)
		}
	}

	e := mustParse(t, []byte(secretYAML), append([]string{"encrypt", "--gcp-kms", sopstest.KeyOther, "--encrypted-regex", secretRegex}, yamlFlags()...)...)
	p := e.Prompt()
	if p.Asks != "Encrypt a new file: 2 values encrypted, 4 left in cleartext" || p.ShowSays || p.Says != nil || p.SaysNote != "" {
		t.Fatalf("encrypt: %+v", p)
	}
	if len(p.KMSKeys) != 1 || p.KMSKeys[0] != sopstest.KeyOther {
		t.Fatalf("encrypt's key: %v", p.KMSKeys)
	}
	// Without a rule SOPS encrypts every value.
	all := mustParse(t, []byte(secretYAML), append([]string{"encrypt", "--gcp-kms", sopstest.KeyProd}, yamlFlags()...)...)
	if got := all.Prompt().Asks; got != "Encrypt a new file: 6 values encrypted, 0 left in cleartext" {
		t.Fatalf("encrypt without a rule: %q", got)
	}
	// docs/10 D8: nothing of a plaintext file is shown, wherever its
	// values would end up.
	for _, r := range []*Request{e, all} {
		shown := r.Prompt().Asks + r.DisplayCommand() + r.DisplayStdin() + mustJSON(t, r.Audit())
		for _, v := range []string{"hunter2", "Secret", "namespace", "stringData:"} {
			if strings.Contains(shown, v) {
				t.Fatalf("an encrypt shows %q of its plaintext: %s", v, shown)
			}
		}
		if !strings.HasPrefix(r.DisplayStdin(), "‹plaintext yaml, ") || strings.Contains(r.DisplayStdin(), "last modified") {
			t.Fatalf("encrypt's file: %s", r.DisplayStdin())
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// docs/10 D8, G5: the cleartext values are quoted so that no key or
// value can pass as another line, capped, and left out when the MAC
// doesn't cover them.
func TestFileSays(t *testing.T) {
	f := sopstest.New(t)
	says := func(plain, regex string) (*Request, []string, string) {
		t.Helper()
		r := mustParse(t, regexFile(t, f, plain, regex), append([]string{"decrypt"}, yamlFlags()...)...)
		return r, r.Prompt().Says, r.Prompt().SaysNote
	}

	// A key the agent renamed to look like a second value (docs/10 §6).
	hostile := "\"name=\\\"staging-db\\\", [\\\"metadata\\\"][\\\"old\\\"] = \\\"x\\\"\\n[\\\"kind\\\"] = \\\"ConfigMap\\\" \\u202e\": db-creds\nsecret: s3cr3t\n"
	_, lines, _ := says(hostile, "^secret$")
	if len(lines) != 1 {
		t.Fatalf("one cleartext value, %d lines: %q", len(lines), lines)
	}
	line := lines[0]
	if strings.ContainsAny(line, "\n\u202e") || !strings.HasPrefix(line, `["name=\"staging-db\", [\"metadata\"]`) || !strings.HasSuffix(line, `] = "db-creds"`) {
		t.Fatalf("a hostile key isn't quoted: %q", line)
	}
	if !strings.Contains(line, `\n`) || !strings.Contains(line, `\u{202e}`) {
		t.Fatalf("the newline or the bidi control isn't escaped: %q", line)
	}

	// Values of every scalar kind, and of a list.
	_, lines, _ = says("n: 3\nb: true\nf: 1.5\nz: null\nl: [a, b]\nsecret: x\n", "^secret$")
	want := []string{`["n"] = 3`, `["b"] = true`, `["f"] = 1.5`, `["z"] = null`, `["l"][0] = "a"`, `["l"][1] = "b"`}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("scalars: %q", lines)
	}

	// More than twelve values, or more than 400 characters: a count.
	var many strings.Builder
	for i := 0; i < maxSaysValues+1; i++ {
		many.WriteString("k" + string(rune('a'+i)) + ": v\n")
	}
	_, lines, note := says(many.String()+"secret: x\n", "^secret$")
	if lines != nil || note != "13 cleartext values, not shown" {
		t.Fatalf("over the cap: %q %q", lines, note)
	}
	_, lines, note = says("long: "+strings.Repeat("x", maxSaysChars)+"\nsecret: x\n", "^secret$")
	if lines != nil || note != "1 cleartext value, not shown" {
		t.Fatalf("over the length: %q %q", lines, note)
	}

	// A file encrypted in full has nothing to say.
	_, lines, note = says("a: 1\nb: two\n", "")
	if lines != nil || note != "nothing in cleartext" {
		t.Fatalf("a file encrypted in full: %q %q", lines, note)
	}

	// mac_only_encrypted: the MAC doesn't cover the cleartext (M4).
	macOnly := libEncrypt(t, f, "name: db-creds\nsecret: x\n", func(m *sops.Metadata) { m.EncryptedRegex, m.MACOnlyEncrypted = "^secret$", true })
	p := mustParse(t, macOnly, append([]string{"decrypt"}, yamlFlags()...)...).Prompt()
	if p.Says != nil || p.SaysNote != "cleartext not verifiable, not shown" {
		t.Fatalf("mac_only_encrypted: %q %q", p.Says, p.SaysNote)
	}
}

// docs/10 D8, D10, G5: set's value is in neither the message nor the
// audit record, and the approval still binds to it.
func TestSetValueIsRedacted(t *testing.T) {
	f := sopstest.New(t)
	enc := encrypted(t, f)
	const secret = "n3w-s3cret-value"
	r := mustParse(t, enc, append([]string{"set"}, yamlFlags(`["stringData"]["password"]`, `"`+secret+`"`)...)...)
	shown := r.DisplayCommand() + r.DisplayStdin() + r.Prompt().Asks + strings.Join(r.Prompt().Says, "") + mustJSON(t, r.Audit())
	if strings.Contains(shown, secret) {
		t.Fatalf("set's value is shown: %s", shown)
	}
	if !strings.Contains(r.DisplayCommand(), "‹redacted: 18 bytes, sha256:") || !strings.Contains(mustJSON(t, r.Audit()), "‹redacted: 18 bytes, sha256:") {
		t.Fatalf("no redaction marker: %s", r.DisplayCommand())
	}
	if !strings.HasPrefix(r.DisplayCommand(), "sops set --filename-override=clusters/prod/shop/db-creds.enc.yaml --input-type=yaml '[\"stringData\"][\"password\"]' ") {
		t.Fatalf("the command: %s", r.DisplayCommand())
	}
	other := mustParse(t, enc, append([]string{"set"}, yamlFlags(`["stringData"]["password"]`, `"n3w-s3cret-valuE"`)...)...)
	if r.Digest("t", "") == other.Digest("t", "") {
		t.Fatal("the digest doesn't cover set's value")
	}
	a := r.Audit()
	if a.StdinBytes != len(enc) || len(a.StdinSHA256) != 64 || a.Command != "" {
		t.Fatalf("audit: %+v", a)
	}
}
