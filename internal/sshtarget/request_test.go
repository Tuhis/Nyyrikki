package sshtarget

import (
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
)

// TestSSHRequestJoin covers docs/07 D1 (G1): args are joined with single
// spaces, as ssh does, and that string is what runs.
func TestSSHRequestJoin(t *testing.T) {
	r := build(t, []string{"sudo", "systemctl", "restart", "nginx"}, nil, false)
	if r.Command() != "sudo systemctl restart nginx" {
		t.Fatalf("command %q", r.Command())
	}
	// No quoting is added: what the agent typed is what the shell reads.
	r = build(t, []string{"echo", "a b", "$(id)"}, nil, false)
	if r.Command() != "echo a b $(id)" || r.DisplayCommand() != "echo a b $(id)" {
		t.Fatalf("command %q", r.Command())
	}
	r = build(t, []string{"cat <<'EOF' > /tmp/x\nline\tone\nEOF"}, nil, false)
	if !strings.Contains(r.Command(), "\n") || !strings.Contains(r.DisplayCommand(), "line\tone\n") {
		t.Fatalf("multi-line command %q", r.DisplayCommand())
	}
}

// TestSSHRequestRefused covers docs/07 D1 (G1).
func TestSSHRequestRefused(t *testing.T) {
	cases := map[string]struct {
		args        []string
		stdin       string
		interactive bool
		detail      string
	}{
		"empty":                 {nil, "", false, DetailEmpty},
		"blank":                 {[]string{" ", ""}, "", false, DetailEmpty},
		"blank interactive":     {[]string{""}, "", true, DetailEmpty},
		"NUL":                   {[]string{"echo a\x00b"}, "", false, DetailControlChar},
		"CR":                    {[]string{"echo a\rb"}, "", false, DetailControlChar},
		"ESC":                   {[]string{"echo \x1b[2J"}, "", false, DetailControlChar},
		"DEL":                   {[]string{"echo \x7f"}, "", false, DetailControlChar},
		"C1":                    {[]string{"echo \u0085"}, "", false, DetailControlChar},
		"invalid UTF-8":         {[]string{"echo \xff"}, "", false, DetailInvalidUTF8},
		"too long":              {[]string{strings.Repeat("a", MaxCommand+1)}, "", false, DetailTooLong},
		"interactive and stdin": {[]string{"sh"}, "x", true, DetailInteractiveStdin},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Build(c.args, []byte(c.stdin), c.interactive)
			wantCode(t, err, codes.InvalidRequest, c.detail)
		})
	}
	if _, err := Build([]string{strings.Repeat("a", MaxCommand)}, nil, false); err != nil {
		t.Errorf("a command of exactly MaxCommand bytes: %v", err)
	}
}

// TestSSHRequestLoginShell: an empty args list is a login shell, and only
// for an interactive run (docs/07 D1, D13).
func TestSSHRequestLoginShell(t *testing.T) {
	r := build(t, nil, nil, true)
	if r.Command() != "" || r.DisplayCommand() != "(login shell)" || !r.Interactive() {
		t.Fatalf("%q %q", r.Command(), r.DisplayCommand())
	}
}

// TestSSHDisplayHostile covers docs/07 D2 (G1): characters that could
// hide or reorder text are shown escaped; nothing else is changed.
func TestSSHDisplayHostile(t *testing.T) {
	cases := map[string]string{
		"echo safe\u202e;rm -rf /":                   `echo safe\u{202e};rm -rf /`,
		"rm\u200b -rf /tmp/x":                        `rm\u{200b} -rf /tmp/x`,
		"echo \u2066x\u2069":                         `echo \u{2066}x\u{2069}`,
		"echo \ufeffbom":                             `echo \u{feff}bom`,
		"echo a\u2028b":                              `echo a\u{2028}b`,
		"echo \U000E0041tag":                         `echo \u{e0041}tag`,
		"echo e\u0301\u0301\u0301\u0301\u0301\u0301": "echo e\u0301\u0301\u0301\u0301" + `\u{301}\u{301}`,
		"echo \u3164x":                               `echo \u{3164}x`,
	}
	for in, want := range cases {
		r := build(t, []string{in}, nil, false)
		if got := r.DisplayCommand(); got != want {
			t.Errorf("display of %q = %q, want %q", in, got, want)
		}
		if r.Command() != in {
			t.Errorf("the command itself was changed: %q", r.Command())
		}
	}
}

// TestSSHDisplayStdin covers docs/07 OD6: stdin is only its size and
// hash.
func TestSSHDisplayStdin(t *testing.T) {
	r := build(t, []string{"sudo", "tee", "/etc/app/env"}, []byte("PASSWORD=hunter2-marker\n"), false)
	d := r.DisplayStdin()
	if strings.Contains(d, "hunter2") || !strings.HasPrefix(d, "‹stdin: 24 bytes, sha256:") || !strings.HasSuffix(d, ", not shown›") {
		t.Fatalf("stdin display %q", d)
	}
	a := r.Audit()
	if a.StdinBytes != 24 || len(a.StdinSHA256) != 64 || a.Command != "sudo tee /etc/app/env" || len(a.Argv) != 0 {
		t.Fatalf("audit %+v", a)
	}
	if build(t, []string{"true"}, nil, false).DisplayStdin() != "" {
		t.Fatal("no stdin should display as nothing")
	}
}

// TestSSHDigestFields covers docs/07 D2 (G2): the digest changes with
// each of target, account, command, stdin and the interactive flag.
func TestSSHDigestFields(t *testing.T) {
	base := build(t, []string{"ls"}, nil, false)
	d := base.Digest("db-1", "ny-owner")
	if d != build(t, []string{"ls"}, nil, false).Digest("db-1", "ny-owner") {
		t.Fatal("the digest isn't deterministic")
	}
	others := map[string][32]byte{
		"target":      base.Digest("db-2", "ny-owner"),
		"account":     base.Digest("db-1", "ny-other"),
		"command":     build(t, []string{"ls", "-l"}, nil, false).Digest("db-1", "ny-owner"),
		"stdin":       build(t, []string{"ls"}, []byte("x"), false).Digest("db-1", "ny-owner"),
		"interactive": build(t, []string{"ls"}, nil, true).Digest("db-1", "ny-owner"),
	}
	for name, o := range others {
		if o == d {
			t.Errorf("changing the %s doesn't change the digest", name)
		}
	}
	// Length prefixes: moving bytes between fields changes the digest.
	a := build(t, []string{"ab"}, []byte("c"), false).Digest("db-1", "ny-owner")
	b := build(t, []string{"a"}, []byte("bc"), false).Digest("db-1", "ny-owner")
	if a == b {
		t.Error("command and stdin boundary is ambiguous")
	}
	if base.Digest("db-1ny", "-owner") == d {
		t.Error("target and account boundary is ambiguous")
	}
}

// TestSSHDigestDistinctFromKubectl: a kubectl request and an SSH request
// never share a digest, so an approval for one can't cover the other.
func TestSSHDigestDistinctFromKubectl(t *testing.T) {
	k, err := request.Parse([]string{"get", "pods"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	s := build(t, []string{"get", "pods"}, nil, false)
	if k.Digest("db-1", "ny-owner") == s.Digest("db-1", "ny-owner") {
		t.Fatal("same digest across types")
	}
	if s.Type() != codes.TypeSSH || k.Type() != codes.TypeKubernetes {
		t.Fatal("types")
	}
}
