// Package target holds what every target type shares: the canonical
// request the decision point binds approvals to, and the result and
// terminal the runners use (docs/02 D6, docs/07 §5.2). Each type's own
// package (internal/kubectl/request, internal/sshtarget) implements
// Request; nothing here knows how a request is parsed or run.
package target

import (
	"bytes"
	"sync"

	"github.com/Tuhis/Nyyrikki/internal/audit"
)

// Request is a parsed, checked request for one target type. It is
// immutable once built, and it is the one value the approver sees, the
// approval binds to and the runner executes (CODE-REVIEW.md: what is
// forwarded is what was approved).
type Request interface {
	// Type is the target type the request is for (codes.TypeKubernetes,
	// codes.TypeSSH). The decision point refuses a request whose type
	// differs from its target's.
	Type() string
	// Interactive reports whether this is a terminal session.
	Interactive() bool
	// Digest is what an approval binds to. runAs is the identity on the
	// target, from the registry, never from the request; a type whose
	// digest doesn't cover it (kubectl, docs/04 §5.3) ignores it.
	Digest(target, runAs string) [32]byte
	// Audit is the audited form: never stdin's contents (docs/03 D6).
	Audit() audit.Request
	// DisplayCommand and DisplayStdin are what the approver is shown,
	// already redacted where the type redacts, not HTML-escaped.
	// DisplayStdin is "" when there is no stdin.
	DisplayCommand() string
	DisplayStdin() string
}

// Result is the outcome of a non-interactive run (docs/04 D13).
type Result struct {
	ExitCode        int
	Stdout, Stderr  []byte
	StdoutTruncated bool
	StderrTruncated bool
	// Detail is a short machine-readable note on the exit, such as
	// "signal: TERM" for a command a signal ended (docs/07 D9).
	Detail string
}

// Size is a terminal size.
type Size struct{ Cols, Rows uint16 }

// Terminal is the far end of an interactive run (docs/04 D12): bytes the
// user types come from Read, the run's output goes to Write, and size
// changes arrive on Resizes. A Read error means the user has gone, and
// ends the run. The caller closes the Terminal after the run returns,
// which must unblock any pending Read or Write.
type Terminal interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resizes() <-chan Size
	// Term is the client's TERM, already checked (docs/07 D9); "" when
	// it sent none.
	Term() string
}

// CapWriter keeps the first Limit bytes written to it and counts the
// rest, so a run never blocks on a full pipe (docs/04 D7).
type CapWriter struct {
	mu    sync.Mutex
	limit int64
	n     int64
	buf   bytes.Buffer
}

// NewCapWriter returns a CapWriter that keeps limit bytes.
func NewCapWriter(limit int64) *CapWriter { return &CapWriter{limit: limit} }

func (w *CapWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.limit - int64(w.buf.Len()); room > 0 {
		w.buf.Write(p[:min(int64(len(p)), room)])
	}
	w.n += int64(len(p))
	return len(p), nil
}

// Bytes returns what was kept.
func (w *CapWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes())
}

// N is how many bytes were written in all.
func (w *CapWriter) N() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

// Truncated reports whether more was written than kept.
func (w *CapWriter) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n > int64(w.buf.Len())
}
