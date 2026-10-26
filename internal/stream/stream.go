// Package stream serves GET /stream (docs/02 D10): a WebSocket that
// attaches to an interactive run the decision point has already allowed.
// It makes no decision of its own: the ticket names a Grant, and only a
// Grant runs (docs/02 D6).
package stream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/stream/protocol"
)

// Tickets redeems a stream ticket (docs/02 D10): once, within 30 s, only
// for the agent key it was issued to. Any error is a refusal.
type Tickets interface {
	Redeem(ctx context.Context, ticket string, p *authn.Principal) (*decision.Grant, *request.Canonical, error)
}

// Runner runs an interactive request; *kubectl.Runner implements it.
type Runner interface {
	RunInteractive(g *decision.Grant, c *request.Canonical, term kubectl.Terminal) (int, error)
}

type handler struct {
	tickets Tickets
	runner  Runner
	intro   authn.Introspector
	audit   audit.Appender
	log     *slog.Logger
}

// NewHandler returns the /stream handler. It must sit behind the
// authentication middleware, which puts the Principal in the request
// context (docs/02 D2, D11).
func NewHandler(t Tickets, r Runner, in authn.Introspector, a audit.Appender, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &handler{tickets: t, runner: r, intro: in, audit: a, log: logger}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		refuse(w, http.StatusMethodNotAllowed, codes.InvalidRequest, "only GET")
		return
	}
	p, ok := authn.FromContext(ctx)
	if !ok {
		refuse(w, http.StatusUnauthorized, codes.Unauthenticated, "not authenticated")
		return
	}
	// docs/02 D11: /stream introspects, like run and elevate.
	if err := h.intro.Introspect(ctx, p); err != nil {
		code := codes.Of(err)
		if code != codes.SessionInactive {
			code = codes.IntrospectionFailed
		}
		h.auditPrincipal(ctx, p, codes.KindDecision, code, "stream_introspection")
		refuse(w, http.StatusForbidden, code, "the session could not be confirmed")
		return
	}
	ticket := r.Header.Get(protocol.TicketHeader)
	if ticket == "" {
		h.auditPrincipal(ctx, p, codes.KindInvalidRequest, codes.InvalidRequest, "stream_no_ticket")
		refuse(w, http.StatusBadRequest, codes.InvalidRequest, "no stream ticket")
		return
	}
	g, c, err := h.tickets.Redeem(ctx, ticket, p)
	if err != nil || g == nil || c == nil {
		if g != nil {
			g.Release()
		}
		code := codes.Denied
		if err != nil && codes.Of(err) != codes.Internal {
			code = codes.Of(err)
		}
		// Never the ticket or the redeemer's message: only the code.
		h.auditPrincipal(ctx, p, codes.KindDecision, code, "stream_ticket")
		refuse(w, http.StatusForbidden, code, "the stream ticket is not valid")
		return
	}
	// The decision point binds the ticket to the agent key; check the
	// result anyway, since a Grant for someone else must never attach.
	if g.AgentKey() != p.AgentKey || g.Human() != p.Human || !g.Interactive() || !c.Interactive() {
		g.Release()
		h.auditPrincipal(ctx, p, codes.KindDecision, codes.Denied, "stream_grant_mismatch")
		refuse(w, http.StatusForbidden, codes.Denied, "the stream ticket is not valid")
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		g.Release() // Accept has written the HTTP error.
		return
	}
	conn.SetReadLimit(protocol.ReadLimit)
	defer conn.CloseNow()

	rec := grantRecord(codes.KindStreamAttached, g, c)
	if err := h.audit.Append(ctx, rec); err != nil {
		g.Release()
		h.log.Error("audit write failed; stream not attached", "run_id", g.RunID(), "err", err)
		finish(ctx, conn, -1, codes.New(codes.Unavailable, "the audit log is unavailable"))
		return
	}

	termCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	term := newWSTerm(termCtx, conn)
	exit, runErr := h.runner.RunInteractive(g, c, term)
	finish(termCtx, conn, exit, runErr)
	stop()
}

// finish sends the final message and closes (docs/04 D12).
func finish(ctx context.Context, conn *websocket.Conn, exit int, err error) {
	var msg protocol.ServerMessage
	if err != nil {
		msg.Error = &protocol.Error{Code: string(codes.Of(err)), Message: messageOf(err)}
	} else {
		msg.ExitCode = &exit
	}
	b, _ := json.Marshal(msg)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if conn.Write(wctx, websocket.MessageText, b) == nil {
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}
}

// messageOf returns the agent-facing message of err: a codes.Error's own
// Message, never a wrapped error's text.
func messageOf(err error) string {
	var ce *codes.Error
	if errors.As(err, &ce) && ce.Message != "" {
		return ce.Message
	}
	return string(codes.Of(err))
}

func refuse(w http.ResponseWriter, status int, code codes.Code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error protocol.Error `json:"error"`
	}{protocol.Error{Code: string(code), Message: msg}})
}

func (h *handler) auditPrincipal(ctx context.Context, p *authn.Principal, kind string, code codes.Code, detail string) {
	rec := audit.Record{
		Kind: kind, Human: p.Human, Agent: p.AgentKey, ClientID: p.ClientID,
		Decision: codes.Deny, Code: string(code), Detail: detail,
	}
	if err := h.audit.Append(context.WithoutCancel(ctx), rec); err != nil {
		h.log.Error("audit write failed for a refused stream", "kind", kind, "err", err)
	}
}

func grantRecord(kind string, g *decision.Grant, c *request.Canonical) audit.Record {
	req := c.Audit()
	ra := g.RunAs()
	return audit.Record{
		Kind: kind, Human: g.Human(), Agent: g.AgentKey(), ClientID: g.ClientID(),
		Targets: []string{g.Target()}, RunID: g.RunID(),
		ApprovalID: g.ApprovalID(), ElevationID: g.ElevationID(), CoveredBy: g.CoveredBy(),
		Request: &req, RunAs: &audit.RunAs{User: ra.User, Groups: ra.Groups},
	}
}

// wsTerm adapts the WebSocket to kubectl.Terminal: binary messages are
// terminal bytes, text messages are resizes.
type wsTerm struct {
	ctx     context.Context
	conn    *websocket.Conn
	in      *io.PipeReader
	resizes chan kubectl.Size
}

func newWSTerm(ctx context.Context, conn *websocket.Conn) *wsTerm {
	pr, pw := io.Pipe()
	t := &wsTerm{ctx: ctx, conn: conn, in: pr, resizes: make(chan kubectl.Size, 8)}
	go t.readLoop(pw)
	return t
}

func (t *wsTerm) readLoop(pw *io.PipeWriter) {
	for {
		typ, data, err := t.conn.Read(t.ctx)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		switch typ {
		case websocket.MessageBinary:
			if _, err := pw.Write(data); err != nil {
				return
			}
		case websocket.MessageText:
			var m protocol.ClientMessage
			if json.Unmarshal(data, &m) != nil || m.Resize == nil || m.Resize.Cols == 0 || m.Resize.Rows == 0 {
				continue // not a resize: ignored
			}
			s := kubectl.Size{Cols: m.Resize.Cols, Rows: m.Resize.Rows}
			select {
			case t.resizes <- s:
			default: // the run is behind on resizes; drop the oldest
				select {
				case <-t.resizes:
				default:
				}
				select {
				case t.resizes <- s:
				default:
				}
			}
		}
	}
}

func (t *wsTerm) Read(p []byte) (int, error) { return t.in.Read(p) }

func (t *wsTerm) Write(p []byte) (int, error) {
	if err := t.conn.Write(t.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *wsTerm) Resizes() <-chan kubectl.Size { return t.resizes }
