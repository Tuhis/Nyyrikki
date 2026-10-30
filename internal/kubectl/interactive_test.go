package kubectl

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest"
)

// fakeTerm is a Terminal driven by the test.
type fakeTerm struct {
	in      *io.PipeReader
	inW     *io.PipeWriter
	mu      sync.Mutex
	out     bytes.Buffer
	resizes chan Size
}

func newFakeTerm() *fakeTerm {
	r, w := io.Pipe()
	return &fakeTerm{in: r, inW: w, resizes: make(chan Size, 4)}
}

func (f *fakeTerm) Read(p []byte) (int, error) { return f.in.Read(p) }
func (f *fakeTerm) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.Write(p)
}
func (f *fakeTerm) Resizes() <-chan Size { return f.resizes }
func (f *fakeTerm) Term() string         { return "" }
func (f *fakeTerm) close()               { f.in.CloseWithError(io.ErrClosedPipe) }

func (f *fakeTerm) output() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.String()
}

func (f *fakeTerm) waitFor(t *testing.T, s string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(f.output(), s) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("terminal never showed %q; got %q", s, f.output())
}

func (f *fakeTerm) send(t *testing.T, s string) {
	t.Helper()
	go f.inW.Write([]byte(s))
}

type interactiveResult struct {
	code int
	err  error
}

func startInteractive(t *testing.T, h *harness, ctx context.Context, term *fakeTerm) <-chan interactiveResult {
	t.Helper()
	c := parse(t, []string{"exec", "-it", "web", "--", "sh"}, nil, true)
	g := grantFor(ctx, "lab", c, nil)
	done := make(chan interactiveResult, 1)
	go func() {
		code, err := h.runner.RunInteractive(g, c, term)
		done <- interactiveResult{code, err}
	}()
	t.Cleanup(term.close)
	return done
}

func waitResult(t *testing.T, done <-chan interactiveResult) interactiveResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("RunInteractive didn't return")
		return interactiveResult{}
	}
}

// TestRunInteractive covers docs/04 D12 (G8, unit): the child runs on a
// pty, bytes go both ways, resizes apply, and the exit status comes back.
func TestRunInteractive(t *testing.T) {
	h := newHarness(t, modeExecutable(t, modeEchoTTY), nil)
	term := newFakeTerm()
	term.resizes <- Size{Cols: 120, Rows: 50}
	done := startInteractive(t, h, t.Context(), term)

	term.waitFor(t, "READY")
	term.send(t, "size\n")
	term.waitFor(t, "SIZE 120x50")
	term.resizes <- Size{Cols: 100, Rows: 40}
	time.Sleep(100 * time.Millisecond)
	term.send(t, "size\n")
	term.waitFor(t, "SIZE 100x40")
	term.send(t, "hello\n")
	term.waitFor(t, "got:hello")
	term.send(t, "exit 3\n")

	r := waitResult(t, done)
	if r.err != nil || r.code != 3 {
		t.Fatalf("RunInteractive = %d, %v; want 3, nil", r.code, r.err)
	}
	if got := h.audit.kinds(); len(got) != 2 || got[0] != codes.KindRunStarted || got[1] != codes.KindRunFinished {
		t.Errorf("audit kinds = %v", got)
	}
	if fin, _ := h.audit.last(codes.KindRunFinished); fin.ExitCode == nil || *fin.ExitCode != 3 || fin.StdoutBytes == 0 || fin.Request == nil || !fin.Request.Interactive {
		t.Errorf("run_finished = %+v", fin)
	}
	h.assertRuntimeEmpty()
}

// TestRunInteractiveCut covers docs/04 G8 and D8: an interactive run is
// cut when its grant ends, when the client goes away, and at its limit.
func TestRunInteractiveCut(t *testing.T) {
	exe := modeExecutable(t, modeEchoTTY)
	t.Run("grant ended", func(t *testing.T) {
		h := newHarness(t, exe, nil)
		term := newFakeTerm()
		ctx, cancel := context.WithCancel(t.Context())
		done := startInteractive(t, h, ctx, term)
		term.waitFor(t, "READY")
		cancel()
		r := waitResult(t, done)
		wantCode(t, r.err, codes.Expired, DetailGrantEnded)
		if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.Detail != DetailGrantEnded {
			t.Errorf("run_cut = %+v", rec)
		}
		h.assertRuntimeEmpty()
	})
	// docs/07 D17: "End now" ends the grant with ErrEndedByApprover, and
	// the cut says so (TestEndNowInteractive, kubectl half).
	t.Run("ended by approver", func(t *testing.T) {
		h := newHarness(t, exe, nil)
		term := newFakeTerm()
		t.Cleanup(term.close)
		c := parse(t, []string{"exec", "-it", "web", "--", "sh"}, nil, true)
		g := grantFor(t.Context(), "lab", c, nil)
		done := make(chan interactiveResult, 1)
		go func() {
			code, err := h.runner.RunInteractive(g, c, term)
			done <- interactiveResult{code, err}
		}()
		term.waitFor(t, "READY")
		decisiontest.End(g, decision.ErrEndedByApprover)
		r := waitResult(t, done)
		wantCode(t, r.err, codes.Expired, decision.DetailEndedByApprover)
		if rec, ok := h.audit.last(codes.KindRunCut); !ok || rec.Detail != decision.DetailEndedByApprover {
			t.Errorf("run_cut = %+v", rec)
		}
		h.assertRuntimeEmpty()
	})
	t.Run("client gone", func(t *testing.T) {
		h := newHarness(t, exe, nil)
		term := newFakeTerm()
		done := startInteractive(t, h, t.Context(), term)
		term.waitFor(t, "READY")
		term.close()
		r := waitResult(t, done)
		wantCode(t, r.err, codes.Expired, DetailClientGone)
		h.assertRuntimeEmpty()
	})
	t.Run("max interactive", func(t *testing.T) {
		h := newHarness(t, exe, func(c *RunnerConfig) { c.Limits.MaxInteractive = 700 * time.Millisecond })
		term := newFakeTerm()
		done := startInteractive(t, h, t.Context(), term)
		r := waitResult(t, done)
		wantCode(t, r.err, codes.Expired, DetailTimeout)
		h.assertRuntimeEmpty()
	})
}

func TestRunInteractiveRefusesNonInteractive(t *testing.T) {
	h := newHarness(t, modeExecutable(t, modeEchoTTY), nil)
	c := parse(t, []string{"exec", "-it", "web", "--", "sh"}, nil, false)
	_, err := h.runner.RunInteractive(grantFor(t.Context(), "lab", c, nil), c, newFakeTerm())
	wantCode(t, err, codes.Internal, DetailInteractiveMismatch)
	other := parse(t, []string{"attach", "-it", "web"}, nil, true)
	_, err = h.runner.RunInteractive(grantFor(t.Context(), "lab", other, nil), parse(t, []string{"exec", "-it", "web", "--", "sh"}, nil, true), newFakeTerm())
	wantCode(t, err, codes.Internal, DetailDigestMismatch)
	h.assertRuntimeEmpty()
}
