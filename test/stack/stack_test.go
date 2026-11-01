//go:build e2e || quickstart

package stack

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// alive reports whether pid runs (a zombie, ended but not yet reaped,
// doesn't count).
func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	f := strings.Fields(string(b)[strings.LastIndex(string(b), ")")+1:])
	return len(f) > 0 && f[0] != "Z"
}

// A cancelled step ends with all its children, as kind create cluster's
// docker run, before the cleanup runs: not only the direct child.
func TestCancelEndsTheWholeGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runEnv(ctx, nil, "sh", "-c", "sleep 300 & echo $! > "+pidFile+"; wait")
		done <- err
	}()
	var pid int
	for deadline := time.Now().Add(10 * time.Second); ; {
		if b, err := os.ReadFile(pidFile); err == nil && strings.TrimSpace(string(b)) != "" {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never started its child")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled command succeeded")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a cancelled command didn't return")
	}
	for deadline := time.Now().Add(5 * time.Second); alive(pid); {
		if time.Now().After(deadline) {
			t.Fatalf("the command's child %d outlived the cancel", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Without a context, as the e2e runs it, a command runs to its end.
func TestRunWithoutContext(t *testing.T) {
	out, err := Run("sh", "-c", "sleep 0.2; echo done")
	if err != nil || strings.TrimSpace(out) != "done" {
		t.Fatalf("Run: %q %v", out, err)
	}
}

// stubs puts scripts named after tools first on PATH, for the test.
func stubs(t *testing.T, scripts map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// shortTeardown makes Teardown's waits short, for the test.
func shortTeardown(t *testing.T, settle, bound time.Duration) {
	t.Helper()
	s, b, p := teardownSettle, teardownBound, teardownPoll
	teardownSettle, teardownBound, teardownPoll = settle, bound, 50*time.Millisecond
	t.Cleanup(func() { teardownSettle, teardownBound, teardownPoll = s, b, p })
}

// A check that fails is no proof that the stack is gone: with docker and
// kind failing, Teardown keeps trying to its bound and says it couldn't.
func TestTeardownCountsFailedChecks(t *testing.T) {
	stubs(t, map[string]string{
		"docker": `echo "Cannot connect to the Docker daemon" >&2; exit 1`,
		"kind":   `echo "failed to list clusters" >&2; exit 1`,
	})
	shortTeardown(t, 300*time.Millisecond, 2*time.Second)
	var logged []string
	cfg := Config{Name: "nyyrikki-stub", Dir: t.TempDir(), Logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }}
	start := time.Now()
	Teardown(cfg)
	if took := time.Since(start); took < 2*time.Second {
		t.Errorf("Teardown gave up after %v, before its bound, though every check failed", took)
	}
	if len(logged) == 0 || !strings.Contains(logged[len(logged)-1], "could not remove all of nyyrikki-stub") {
		t.Errorf("Teardown said %q", logged)
	}
}

// Only docker's "not found" means a network is gone.
func TestTeardownEndsWhenAllIsGone(t *testing.T) {
	stubs(t, map[string]string{
		"docker": `case "$1 $2" in
"network inspect") echo "Error response from daemon: network $3 not found" >&2; exit 1 ;;
esac
exit 0`,
		"kind": `exit 0`,
	})
	shortTeardown(t, 300*time.Millisecond, 5*time.Second)
	var logged []string
	cfg := Config{Name: "nyyrikki-stub", Dir: t.TempDir(), Logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }}
	start := time.Now()
	Teardown(cfg)
	if took := time.Since(start); took > 2*time.Second || len(logged) > 0 {
		t.Errorf("with nothing left, Teardown took %v and said %q", took, logged)
	}
}
