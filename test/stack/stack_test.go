//go:build e2e || quickstart

package stack

import (
	"context"
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
