package hostsetup

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// tokenConfig writes a config whose key files are in dir and returns its
// path. hostCA is the host-ca path written into it.
func tokenConfig(t *testing.T, dir, userCA, hostCA string) string {
	t.Helper()
	b, err := os.ReadFile("../config/testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := strings.Replace(string(b), "  user_ca_key_file: /etc/nyyrikki/ssh/user-ca\n",
		"  user_ca_key_file: "+userCA+"\n  host_ca_key_file: "+hostCA+"\n", 1)
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var tokenPattern = regexp.MustCompile(`nye1\.[A-Za-z0-9_-]+`)

// TestEnrollTokenCommand covers docs/08 D6 (G6): the command prints a
// token the server accepts, for that target, valid 15 minutes, and the
// full host command, on stdout only.
func TestEnrollTokenCommand(t *testing.T) {
	dir := t.TempDir()
	user, _ := keyFile(t, dir, "user-ca")
	host, _ := keyFile(t, dir, "host-ca")
	cfgPath := tokenConfig(t, dir, user, host)
	now := time.Date(2026, 11, 1, 12, 1, 0, 0, time.UTC)
	var out, errOut bytes.Buffer
	if code := (TokenCommand{Stdout: &out, Stderr: &errOut, Now: func() time.Time { return now }}).Main([]string{"--config", cfgPath, "db-1"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr %q", errOut.String())
	}
	toks := tokenPattern.FindAllString(out.String(), -1)
	if len(toks) != 1 {
		t.Fatalf("output %q", out.String())
	}
	want := "  curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh -s -- --enroll " + toks[0] + "\n"
	if !strings.Contains(out.String(), want) || !strings.Contains(out.String(), "valid until 12:16:00 UTC") {
		t.Fatalf("output %q", out.String())
	}
	// The server, reading the same files, accepts it.
	env := newEnrollEnv(t)
	env.keys = keysFor(t, env.cfg, filesOf(user, host))
	set, _ := env.keys.Load()
	key, _ := set.EnrollTokenKey()
	tok, err := ParseToken(key, toks[0])
	if err != nil || tok.Target != "db-1" || !tok.Expires.Equal(now.Add(15*time.Minute)) || !tok.Issued().Equal(now) {
		t.Fatalf("token %+v %v", tok, err)
	}
	// Two runs, two tokens.
	out.Reset()
	(TokenCommand{Stdout: &out, Stderr: &errOut, Now: func() time.Time { return now }}).Main([]string{"--config", cfgPath, "db-1"})
	if tokenPattern.FindString(out.String()) == toks[0] {
		t.Fatal("the same token twice")
	}
}

// TestEnrollTokenCommandRefuses covers docs/08 D6 and D16 (G6, G15): no
// host-ca prints the remedy and no token; a broken key file, a target
// that isn't SSH, an unknown one and a bad config print no token either.
func TestEnrollTokenCommandRefuses(t *testing.T) {
	dir := t.TempDir()
	user, _ := keyFile(t, dir, "user-ca")
	garbage := filepath.Join(dir, "garbage")
	os.WriteFile(garbage, []byte("junk"), 0o600)
	for name, c := range map[string]struct {
		hostCA string
		args   []string
		want   string
	}{
		"no host-ca":     {filepath.Join(dir, "absent"), []string{"db-1"}, "cronjob/RELEASE-ssh-ca-add-host-ca"},
		"broken host-ca": {garbage, []string{"db-1"}, "ca_key_unreadable"},
		"kubernetes":     {filepath.Join(dir, "absent"), []string{"prod-k8s"}, "not an SSH target"},
		"unknown":        {filepath.Join(dir, "absent"), []string{"ghost"}, "not an SSH target"},
		"no target":      {filepath.Join(dir, "absent"), nil, "usage"},
		"two targets":    {filepath.Join(dir, "absent"), []string{"db-1", "db-1"}, "usage"},
	} {
		t.Run(name, func(t *testing.T) {
			cfgPath := tokenConfig(t, t.TempDir(), user, c.hostCA)
			var out, errOut bytes.Buffer
			code := (TokenCommand{Stdout: &out, Stderr: &errOut}).Main(append([]string{"--config", cfgPath}, c.args...))
			if code == 0 || out.Len() != 0 || !strings.Contains(errOut.String(), c.want) || tokenPattern.MatchString(errOut.String()) {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
			}
		})
	}
	// Both remedies are printed without host-ca.
	var out, errOut bytes.Buffer
	(TokenCommand{Stdout: &out, Stderr: &errOut}).Main([]string{"--config", tokenConfig(t, t.TempDir(), user, filepath.Join(dir, "absent")), "db-1"})
	if !strings.Contains(errOut.String(), "nyyrikkid ssh-ca add-host-ca | kubectl replace -f -") {
		t.Fatalf("remedy %q", errOut.String())
	}
	if (TokenCommand{Stdout: &out, Stderr: &errOut}).Main([]string{"--config", filepath.Join(dir, "none.yaml"), "db-1"}) == 0 {
		t.Fatal("a missing config was accepted")
	}
}

func filesOf(user, host string) sshca.Files { return sshca.Files{UserCA: user, HostCA: host} }
