package sopstarget

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/sopstarget/sopstest"
)

// The comparisons of docs/10 G3 against the sops program this module
// pins as a tool, at the library's version. They need the program built
// (NYYRIKKI_SOPS_PROGRAM), which the test gate does; the program reaches
// the same fake Cloud KMS through its own environment.

// TestSOPSProgramFilesAreRead: for files the sops program encrypted,
// decrypt returns exactly what the program's own decrypt returns.
func TestSOPSProgramFilesAreRead(t *testing.T) {
	sopsProgram(t)
	e := newEnv(t)
	enc := mustSops(t, e.fake, "secret.yaml", []byte(secretYAML), "encrypt", "--gcp-kms", sopstest.KeyProd, "--encrypted-regex", secretRegex)
	for _, args := range [][]string{nil, {"--extract", `["stringData"]["password"]`}, {"--extract", `["stringData"]`}, {"--extract", `["kind"]`}, {"--output-type", "json"}} {
		want := mustSops(t, e.fake, "secret.yaml", enc, append([]string{"decrypt"}, args...)...)
		got, err := e.run(t, mustParse(t, enc, append([]string{"decrypt"}, yamlFlags(args...)...)...))
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%v: decrypt returned %q; the sops program returns %q", args, got, want)
		}
	}
	// The program reads a file's type from its name: .env is dotenv.
	for typ, c := range map[string][2]string{"json": {"f.json", `{"a": "one", "b": {"c": 2}}`}, "dotenv": {"f.env", "A=one\nB=two\n"}, "yaml": {"f.yaml", "a: 1\nb:\n    - x\n    - y\n# a comment\nc: text\n"}} {
		encd := mustSops(t, e.fake, c[0], []byte(c[1]), "encrypt", "--gcp-kms", sopstest.KeyOther)
		want := mustSops(t, e.fake, c[0], encd, "decrypt")
		got, err := e.run(t, mustParse(t, encd, "decrypt", "--input-type", typ, "--filename-override", c[0]))
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: decrypt returned %q; the sops program returns %q", typ, got, want)
		}
	}
}

// TestSOPSProgramReadsWhatIsReturned: the files set, unset and encrypt
// return are read by the sops program, and say what was asked.
func TestSOPSProgramReadsWhatIsReturned(t *testing.T) {
	sopsProgram(t)
	e := newEnv(t)
	enc := mustSops(t, e.fake, "secret.yaml", []byte(secretYAML), "encrypt", "--gcp-kms", sopstest.KeyProd, "--encrypted-regex", secretRegex)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"set", `["stringData"]["password"]`, `"new-password-1"`}, strings.Replace(secretYAML, "hunter2", "new-password-1", 1)},
		{[]string{"set", `["stringData"]["token"]`, `"new-token-2"`}, secretYAML + "    token: new-token-2\n"},
		{[]string{"set", `["stringData"]`, `{"only": "this"}`}, strings.Split(secretYAML, "stringData:")[0] + "stringData:\n    only: this\n"},
		{[]string{"unset", `["stringData"]["user"]`}, strings.Replace(secretYAML, "    user: app\n", "", 1)},
	}
	for _, c := range cases {
		out, err := e.run(t, mustParse(t, enc, append(c.args[:1:1], append(yamlFlags(), c.args[1:]...)...)...))
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if got := string(mustSops(t, e.fake, "secret.yaml", out, "decrypt")); got != c.want {
			t.Errorf("%v: the sops program reads %q; want %q", c.args, got, c.want)
		}
	}
	for _, rule := range [][]string{{"--encrypted-regex", secretRegex}, {"--unencrypted-regex", "^(apiVersion|kind|metadata)$"}, {"--encrypted-suffix", "Data"}, {"--unencrypted-suffix", "ata"}, nil} {
		out, err := e.run(t, mustParse(t, []byte(secretYAML), append(append([]string{"encrypt", "--gcp-kms", sopstest.KeyOther}, rule...), yamlFlags()...)...))
		if err != nil {
			t.Fatalf("encrypt %v: %v", rule, err)
		}
		if got := string(mustSops(t, e.fake, "secret.yaml", out, "decrypt")); got != secretYAML {
			t.Errorf("encrypt %v: the sops program reads %q", rule, got)
		}
		// And what the program encrypts with the same rule holds the same
		// values in cleartext.
		theirs := mustSops(t, e.fake, "secret.yaml", []byte(secretYAML), append([]string{"encrypt", "--gcp-kms", sopstest.KeyOther}, rule...)...)
		for _, v := range []string{"name: db-creds", "kind: Secret", "hunter2"} {
			if strings.Contains(string(out), v) != strings.Contains(string(theirs), v) {
				t.Errorf("encrypt %v: %q is in cleartext in one of the two files only", rule, v)
			}
		}
	}
}
