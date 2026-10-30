package kubectl

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// Size is a terminal size.
type Size = target.Size

// Terminal is the far end of an interactive run (docs/04 D12).
type Terminal = target.Terminal

// defaultSize is the pty's size until the client sends its own.
var defaultSize = Size{Cols: 80, Rows: 24}

// RunInteractive runs c on a pseudo-terminal bridged to term (docs/04
// D12). It is bounded by MaxInteractive and, under an elevation, by its
// expiry, and it is cut like Run when g's context ends (D8). It returns
// kubectl's exit status; a cut run returns a *codes.Error with
// codes.Expired. g is released on every path.
func (r *Runner) RunInteractive(g *decision.Grant, c *request.Canonical, term Terminal) (int, error) {
	if g == nil || c == nil || term == nil {
		return -1, codes.New(codes.Internal, "no grant, request or terminal")
	}
	defer g.Release()
	if err := checkGrant(g, c); err != nil {
		r.auditRefusal(g, c, codes.KindDecision, err)
		return -1, err
	}
	if !c.Interactive() {
		err := codes.WithDetail(codes.Internal, DetailInteractiveMismatch, "not an interactive request")
		r.auditRefusal(g, c, codes.KindDecision, err)
		return -1, err
	}
	l := r.limitsFor(g, r.limits.MaxInteractive)
	defer l.cancel()

	rd, err := r.prepare(l.ctx, g, c)
	if err != nil {
		return -1, err
	}
	defer rd.remove(r.log)

	cmd, killed := r.childCommand(l, rd.dir, c)
	size := defaultSize
	select {
	case s := <-term.Resizes():
		if s.Cols > 0 && s.Rows > 0 {
			size = s
		}
	default:
	}

	if err := r.appendAudit(g, record(codes.KindRunStarted, g, c)); err != nil {
		r.log.Error("audit write failed; run not started", "run_id", g.RunID(), "err", err)
		return -1, codes.Wrap(codes.Unavailable, err, "the audit log is unavailable")
	}
	// Setsid makes the child lead a new session and process group, so
	// Cancel's kill of -pid reaches all of it; Setctty gives it the pty.
	ptmx, err := pty.StartWithAttrs(cmd, &pty.Winsize{Cols: size.Cols, Rows: size.Rows},
		&syscall.SysProcAttr{Setsid: true, Setctty: true, Pdeathsig: syscall.SIGKILL})
	if err != nil {
		r.finish(g, c, codes.KindRunFinished, -1, 0, 0, codes.Unavailable, DetailSetup)
		return -1, codes.Wrap(codes.Unavailable, err, "kubectl could not be started")
	}
	var closeOnce sync.Once
	closePty := func() { closeOnce.Do(func() { ptmx.Close() }) }
	defer closePty()

	// Input: the user's bytes to the pty. A read error means the client
	// went away: cut the run.
	go func() {
		_, _ = io.Copy(ptmx, term)
		l.clientGone.Store(true)
		l.cancel()
	}()
	// Resizes, until the run ends.
	go func() {
		for {
			select {
			case <-l.ctx.Done():
				return
			case s, ok := <-term.Resizes():
				if !ok {
					return
				}
				if s.Cols > 0 && s.Rows > 0 {
					_ = setSize(ptmx, s)
				}
			}
		}
	}()
	// Output: the pty to the user, until the child's side closes (EIO).
	var outBytes atomic.Int64
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if _, werr := term.Write(buf[:n]); werr != nil {
					return
				}
				outBytes.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	// Let the last output drain, but don't wait on a client that has
	// stopped reading: the caller closing term ends that goroutine.
	select {
	case <-outDone:
	case <-time.After(2 * time.Second):
		closePty()
	}
	code := exitCode(cmd, waitErr)
	if killed.Load() {
		detail := l.cutDetail()
		r.finish(g, c, codes.KindRunCut, code, outBytes.Load(), 0, codes.Expired, detail)
		return code, codes.WithDetail(codes.Expired, detail, "the run was cut: %s", cutMessage(detail))
	}
	r.finish(g, c, codes.KindRunFinished, code, outBytes.Load(), 0, "", "")
	return code, nil
}

// setSize resizes the pty. pty.Setsize goes through os.File.Fd, which
// races with Close and puts the file in blocking mode; Control holds a
// reference to the descriptor instead, and fails once it is closed.
func setSize(f *os.File, s Size) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	ws := struct{ Row, Col, X, Y uint16 }{Row: s.Rows, Col: s.Cols}
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}
