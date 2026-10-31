package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/api"
	"github.com/Tuhis/Nyyrikki/internal/client"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

func TestExitCodes(t *testing.T) {
	cases := map[error]int{
		client.ErrNotSignedIn:                                                                     exitNotSignedIn,
		&client.ToolError{Code: codes.InvalidRequest}:                                             exitUsage,
		&client.ToolError{Code: codes.Unauthenticated}:                                            exitNotSignedIn,
		&client.ToolError{Code: codes.Expired}:                                                    exitNoAnswer,
		&client.ToolError{Code: codes.Withdrawn}:                                                  exitNoAnswer,
		&client.ToolError{Code: codes.Denied, Message: "denied: the approver denied the request"}: exitDenied,
		&client.ToolError{Code: codes.TargetNotAllowed}:                                           exitDenied,
		&client.ToolError{Code: codes.HandleUnknown}:                                              exitDenied,
		&client.ToolError{Code: codes.SessionInactive}:                                            exitDenied,
		&client.ToolError{Code: codes.IntrospectionFailed}:                                        exitDenied,
		&client.ToolError{Code: codes.Unavailable}:                                                exitUnavailable,
		&client.ToolError{Code: codes.Internal}:                                                   exitUnavailable,
		errors.New("connection refused"):                                                          exitUnavailable,
	}
	for err, want := range cases {
		var stderr bytes.Buffer
		c := &cli{stderr: &stderr}
		if got := c.fail(err); got != want {
			t.Errorf("%v: exit %d, want %d", err, got, want)
		}
		// docs/02 §5.5: Nyyrikki's own failure is the last line, naming
		// its code.
		if !bytes.HasPrefix(stderr.Bytes(), []byte("nyyrikki: error: ")) || bytes.Count(stderr.Bytes(), []byte(":")) < 3 {
			t.Errorf("outcome line %q", stderr.String())
		}
	}
}

func TestReadsStdin(t *testing.T) {
	for args, want := range map[string]bool{
		"apply -f -": true, "apply -f=-": true, "apply --filename=-": true, "apply -f-": true,
		"apply --filename -": true, "get pods": false, "exec p -- cat -f -": false, "apply -f x.yaml": false,
	} {
		if got := readsStdin(bytesFields(args)); got != want {
			t.Errorf("%q: %v", args, got)
		}
	}
}

func bytesFields(s string) []string {
	var out []string
	for _, f := range bytes.Fields([]byte(s)) {
		out = append(out, string(f))
	}
	return out
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"bogus"}, {"run", "prod", "get", "pods"}, {"run", "--reason", "x", "prod"}, {"elevate", "prod"},
		{"ssh"}, {"ssh", "--reason", "x", "db-1", "uptime"}, {"ssh", "--reason", "x", "db-1", "--"}} {
		if got := run(context.Background(), args, nil, &out, &errb); got != exitUsage {
			t.Errorf("%v: exit %d", args, got)
		}
	}
	// --reason is required: the approver sees it.
	if got := run(context.Background(), []string{"run", "prod", "--", "get", "pods"}, nil, &out, &errb); got != exitUsage {
		t.Errorf("run without reason: %d", got)
	}
}

func TestMCPHeadersFailsClosed(t *testing.T) {
	t.Setenv("NYYRIKKI_LOGIN_FILE", t.TempDir()+"/none.json")
	var out, errb bytes.Buffer
	if got := run(context.Background(), []string{"mcp-headers"}, nil, &out, &errb); got == 0 || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q", got, out.String())
	}
}

func TestOutcomeLineNamesCode(t *testing.T) {
	var stderr bytes.Buffer
	(&cli{stderr: &stderr}).fail(&client.ToolError{Code: codes.Denied, Message: "denied: the approver denied the request"})
	if got := stderr.String(); got != "nyyrikki: error: denied: the approver denied the request\n" {
		t.Fatalf("%q", got)
	}
}

// TestStreamErrorsKeepTheirCode: /stream reports a cut run as a
// *codes.Error; the CLI maps its code like a tool error's (found by the
// e2e test: an exec cut at expiry exited 69 instead of 75).
func TestStreamErrorsKeepTheirCode(t *testing.T) {
	var stderr bytes.Buffer
	got := (&cli{stderr: &stderr}).fail(&codes.Error{Code: codes.Expired, Message: "the run was cut: the elevation expired"})
	if got != exitNoAnswer || stderr.String() != "nyyrikki: error: expired: the run was cut: the elevation expired\n" {
		t.Fatalf("exit %d, %q", got, stderr.String())
	}
}

// sshCLI is a cli whose list_targets lookup and run are recorded.
type sshCLI struct {
	cli
	types   map[string]string
	looked  []string
	ran     [][]string
	lookErr error
}

func newSSHCLI() *sshCLI {
	c := &sshCLI{types: map[string]string{"db-1": codes.TypeSSH, "prod": codes.TypeKubernetes}}
	c.stderr = &bytes.Buffer{}
	c.stdout = &bytes.Buffer{}
	c.typeOf = func(_ context.Context, _, target string) (string, error) {
		c.looked = append(c.looked, target)
		return c.types[target], c.lookErr
	}
	c.runCmd = func(_ context.Context, args []string) int {
		c.ran = append(c.ran, args)
		return 0
	}
	return c
}

// TestSSHCommand covers docs/08 D12 (G11): nyyrikki ssh with a command
// is run TARGET -- COMMAND..., its flags passed on; with no command it
// needs a terminal, where it is exactly run -t TARGET (tested through
// sshRunArgs, since a test's stdin isn't one).
func TestSSHCommand(t *testing.T) {
	c := newSSHCLI()
	if got := c.ssh(context.Background(), []string{"--reason", "why", "--timeout", "2m", "--login-file", "/l", "db-1", "--", "systemctl", "status", "nginx"}); got != 0 {
		t.Fatalf("exit %d: %s", got, c.stderr)
	}
	want := []string{"--login-file", "/l", "--reason", "why", "--timeout", "2m", "db-1", "--", "systemctl", "status", "nginx"}
	if len(c.ran) != 1 || !slices.Equal(c.ran[0], want) {
		t.Fatalf("ran %q, want %q", c.ran, want)
	}
	c = newSSHCLI()
	if got := c.ssh(context.Background(), []string{"--reason", "r", "-i", "--elevation", "nyel_x", "--login-file", "/l", "db-1", "--", "sh", "-c", "cat > f"}); got != 0 {
		t.Fatalf("exit %d", got)
	}
	if want := []string{"--login-file", "/l", "--reason", "r", "--elevation", "nyel_x", "-i", "db-1", "--", "sh", "-c", "cat > f"}; !slices.Equal(c.ran[0], want) {
		t.Fatalf("ran %q, want %q", c.ran[0], want)
	}

	for _, tc := range []struct {
		rest     []string
		terminal bool
		want     []string
	}{
		{[]string{"db-1"}, true, []string{"-t", "db-1"}},
		{[]string{"db-1", "--", "uptime"}, true, []string{"db-1", "--", "uptime"}},
		{[]string{"db-1", "--", "uptime"}, false, []string{"db-1", "--", "uptime"}},
		{[]string{"db-1", "--", "--", "x"}, false, []string{"db-1", "--", "--", "x"}},
	} {
		got, err := sshRunArgs(tc.rest, tc.terminal)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%q terminal=%v: %q %v, want %q", tc.rest, tc.terminal, got, err, tc.want)
		}
	}
	for _, rest := range [][]string{nil, {"db-1"}, {"db-1", "uptime"}, {"db-1", "--"}} {
		if got, err := sshRunArgs(rest, false); err == nil {
			t.Errorf("%q without a terminal: %q", rest, got)
		}
	}
	// With no command and no terminal, nothing is asked of the server.
	c = newSSHCLI()
	if got := c.ssh(context.Background(), []string{"--reason", "r", "db-1"}); got != exitUsage || len(c.looked) != 0 || len(c.ran) != 0 {
		t.Fatalf("exit %d, looked %v, ran %v", got, c.looked, c.ran)
	}
}

// TestSSHCommandRefusesNonSSH covers docs/08 D12 (G11): a target that
// list_targets doesn't list as SSH (a Kubernetes target, or one it
// doesn't list at all) is refused before run is called; so is a failed
// lookup, and a missing reason before the lookup.
func TestSSHCommandRefusesNonSSH(t *testing.T) {
	for _, target := range []string{"prod", "no-such"} {
		c := newSSHCLI()
		if got := c.ssh(context.Background(), []string{"--reason", "r", target, "--", "get", "pods"}); got != exitUsage || len(c.ran) != 0 {
			t.Errorf("%s: exit %d, ran %v", target, got, c.ran)
		}
		if len(c.looked) != 1 || !strings.Contains(c.stderr.(*bytes.Buffer).String(), "is not an SSH target") {
			t.Errorf("%s: looked %v, stderr %q", target, c.looked, c.stderr)
		}
	}
	c := newSSHCLI()
	c.lookErr = &client.ToolError{Code: codes.Unavailable, Message: "down"}
	if got := c.ssh(context.Background(), []string{"--reason", "r", "db-1", "--", "id"}); got != exitUnavailable || len(c.ran) != 0 {
		t.Fatalf("a failed lookup: exit %d, ran %v", got, c.ran)
	}
	c = newSSHCLI()
	if got := c.ssh(context.Background(), []string{"db-1", "--", "id"}); got != exitUsage || len(c.looked) != 0 {
		t.Fatalf("no reason: exit %d, looked %v", got, c.looked)
	}
}

// TestPrintTargets covers docs/08 D11 on the CLI: nyyrikki targets shows
// each target's groups, and sudo for SSH targets only, as list_targets
// returns them.
func TestPrintTargets(t *testing.T) {
	yes, no := true, false
	var b bytes.Buffer
	printTargets(&b, []api.TargetInfo{
		{Name: "prod", Type: codes.TypeKubernetes, Description: "Production\tcluster"},
		{Name: "db-1", Type: codes.TypeSSH, Sudo: &yes, Groups: []string{"dbs", "all"}},
		{Name: "web-1", Type: codes.TypeSSH, Sudo: &no},
	})
	want := "prod\tkubernetes\t-\t-\tProduction\tcluster\n" +
		"db-1\tssh\tyes\tdbs,all\t\n" +
		"web-1\tssh\tno\t-\t\n"
	if b.String() != want {
		t.Fatalf("got\n%q\nwant\n%q", b.String(), want)
	}
}
