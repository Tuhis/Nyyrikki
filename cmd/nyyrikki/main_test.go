package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

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
	for _, args := range [][]string{nil, {"bogus"}, {"run", "prod", "get", "pods"}, {"run", "--reason", "x", "prod"}, {"elevate", "prod"}} {
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
