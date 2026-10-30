// Package mcpserver offers Nyyrikki's three operations as MCP tools
// (docs/02 D1, §5.2). It holds no decision of its own: every run and
// elevation goes through the decision point, and only a Grant reaches the
// runner.
package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Tuhis/Nyyrikki/internal/api"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl/request"
	"github.com/Tuhis/Nyyrikki/internal/sshtarget"
	"github.com/Tuhis/Nyyrikki/internal/target"
)

// Limits on tool arguments (docs/02 D13).
const (
	maxArgs      = 256
	maxArgBytes  = 8 << 10
	maxStdin     = 1 << 20
	maxReason    = 1000
	maxBodyBytes = 4 << 20
)

// Runner runs a non-interactive request of any target type
// (runner.Runners).
type Runner interface {
	Run(g *decision.Grant, c target.Request, timeout time.Duration) (*target.Result, error)
}

// Deps wires the server.
type Deps struct {
	Config  *config.Config
	Point   *decision.Point
	Runner  Runner
	Audit   audit.Appender
	Logger  *slog.Logger
	Version string
}

// Server is the MCP endpoint.
type Server struct {
	d   Deps
	mcp *mcp.Server
}

// New builds the MCP server with exactly the three tools and nothing else.
func New(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	s := &Server{d: d}
	s.mcp = mcp.NewServer(&mcp.Implementation{Name: "nyyrikki", Version: d.Version}, &mcp.ServerOptions{
		// Tools only: no logging, prompts, resources or completions
		// (docs/01 D4).
		Capabilities: &mcp.ServerCapabilities{},
		Instructions: "Nyyrikki runs privileged requests on target systems after a human approves them on Telegram: " +
			"kubectl requests on Kubernetes targets, shell commands on SSH hosts. " +
			"Call list_targets first; its 'type' says how run reads 'args'. run waits for approval. " +
			"elevate asks for a window of up to 30 minutes; pass its handle as 'elevation' to run without asking again.",
	})
	s.mcp.AddReceivingMiddleware(onlyTools)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        api.ToolListTargets,
		Description: "List the target systems this agent may ask for. Needs no approval.",
	}, s.listTargets)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: api.ToolRun,
		Description: "Run one request on a target, as the human you act for. Waits until the approver answers on Telegram, " +
			"unless 'elevation' carries the handle of a live elevation covering the target. 'reason' is shown to the approver as your claim. " +
			"On a kubernetes target, 'args' are the kubectl arguments without 'kubectl', and 'stdin' is sent to commands that read it ('-f -', or exec/attach with -i). " +
			"On an ssh target, 'args' are joined with single spaces into one command string, as ssh does, which the host's shell runs. " +
			"The approver never sees stdin, only its size and hash, and will deny a command that runs what it reads (sh, bash -s, python3 -): " +
			"put anything the approver must read, such as a script, in the command itself, for example as a heredoc.",
	}, s.run)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: api.ToolElevate,
		Description: "Ask for a time-boxed elevation on one or more targets (default 15m, at most 30m). Waits for the approver. " +
			"Returns a secret handle: pass it as 'elevation' to run. Never write the handle anywhere other agents can read.",
	}, s.elevate)
	return s
}

// allowedMethods are the only MCP methods Nyyrikki answers: the
// handshake, ping and the tools (docs/01 D4, docs/02 D1).
var allowedMethods = map[string]bool{
	"initialize": true, "notifications/initialized": true, "server/discover": true,
	"ping": true, "notifications/cancelled": true,
	"tools/list": true, "tools/call": true,
}

func onlyTools(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if !allowedMethods[method] {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not offered: " + method}
		}
		return next(ctx, method, req)
	}
}

// Handler returns the Streamable HTTP handler, stateless (docs/01 D5).
// It must sit behind the authentication middleware, which puts the
// principal in the request context.
func (s *Server) Handler() http.Handler {
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.mcp }, &mcp.StreamableHTTPOptions{
		Stateless: true,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if _, ok := authn.FromContext(r.Context()); !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func principal(ctx context.Context, _ *mcp.CallToolRequest) (*authn.Principal, error) {
	if p, ok := authn.FromContext(ctx); ok {
		return p, nil
	}
	return nil, codes.New(codes.Unauthenticated, "no principal")
}

// errOut turns err into a failed tool result. The code travels in the
// result's own "error" field, so the result still matches the tool's
// output schema (docs/02 D14).
func errOut(err error) (*mcp.CallToolResult, *api.ErrorBody) {
	msg := err.Error()
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "nyyrikki: " + msg}},
	}, &api.ErrorBody{Code: codes.Of(err), Message: msg}
}

// invalid audits a request refused before any decision, and returns err.
func (s *Server) invalid(ctx context.Context, p *authn.Principal, targets []string, err error) error {
	rec := audit.Record{Kind: codes.KindInvalidRequest, Targets: targets, Code: string(codes.Of(err)), Detail: codes.DetailOf(err)}
	if p != nil {
		rec.Human, rec.Agent, rec.ClientID = p.Human, p.AgentKey, p.ClientID
	}
	_ = s.d.Audit.Append(ctx, rec)
	return err
}

func progress(ctx context.Context, req *mcp.CallToolRequest) func(string) {
	if req == nil || req.Params == nil || req.Session == nil {
		return nil
	}
	tok := req.Params.GetProgressToken()
	if tok == nil {
		return nil
	}
	n := 0.0
	return func(msg string) {
		n++
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Progress: n, Message: msg})
	}
}

func (s *Server) listTargets(ctx context.Context, req *mcp.CallToolRequest, _ api.ListTargetsIn) (*mcp.CallToolResult, api.ListTargetsOut, error) {
	p, err := principal(ctx, req)
	if err != nil {
		r, b := errOut(err)
		return r, api.ListTargetsOut{Error: b}, nil
	}
	out := api.ListTargetsOut{Targets: []api.TargetInfo{}}
	for _, t := range s.d.Point.VisibleTargets(p) {
		out.Targets = append(out.Targets, api.TargetInfo{Name: t.Name, Description: t.Description, Type: t.Type()})
	}
	return nil, out, nil
}

func validateRun(in api.RunIn, ssh bool) (time.Duration, error) {
	if !config.IsSlug(in.Target) {
		return 0, codes.New(codes.InvalidRequest, "target must be a target name")
	}
	// An SSH login shell has no args (docs/07 D13); Build checks the rest.
	if (len(in.Args) == 0 && !(ssh && in.Interactive)) || len(in.Args) > maxArgs {
		return 0, codes.New(codes.InvalidRequest, "args must have 1 to %d elements", maxArgs)
	}
	for _, a := range in.Args {
		if len(a) > maxArgBytes || !utf8.ValidString(a) {
			return 0, codes.New(codes.InvalidRequest, "each arg must be valid UTF-8 of at most %d bytes", maxArgBytes)
		}
	}
	if len(in.Stdin) > maxStdin {
		return 0, codes.New(codes.InvalidRequest, "stdin is limited to %d bytes", maxStdin)
	}
	if err := validateReason(in.Reason); err != nil {
		return 0, err
	}
	var timeout time.Duration
	if in.Timeout != "" {
		d, err := time.ParseDuration(in.Timeout)
		if err != nil || d <= 0 {
			return 0, codes.New(codes.InvalidRequest, "timeout must be a positive Go duration")
		}
		timeout = d
	}
	return timeout, nil
}

func validateReason(r string) error {
	if n := utf8.RuneCountInString(r); n == 0 || n > maxReason || !utf8.ValidString(r) {
		return codes.New(codes.InvalidRequest, "reason must be 1 to %d characters", maxReason)
	}
	return nil
}

func (s *Server) run(ctx context.Context, req *mcp.CallToolRequest, in api.RunIn) (*mcp.CallToolResult, api.RunOut, error) {
	p, err := principal(ctx, req)
	if err != nil {
		r, b := errOut(err)
		return r, api.RunOut{Error: b}, nil
	}
	// The target's type says how args are read (docs/07 D13). An unknown
	// target, or one this agent may not see, is read as kubectl and the
	// decision point refuses it: both answer the same (docs/02 D5).
	t, _ := s.d.Config.TargetByName(in.Target)
	isSSH := t != nil && t.Visible(p.Human, p.ClientID) && t.Type() == codes.TypeSSH
	timeout, err := validateRun(in, isSSH)
	if err != nil {
		r, b := errOut(s.invalid(ctx, p, []string{in.Target}, err))
		return r, api.RunOut{Error: b}, nil
	}
	var stdin []byte
	if in.Stdin != "" {
		stdin = []byte(in.Stdin)
	}
	c, err := buildRequest(isSSH, in.Args, stdin, in.Interactive)
	if err != nil {
		r, b := errOut(s.invalid(ctx, p, []string{in.Target}, err))
		return r, api.RunOut{Error: b}, nil
	}
	runID := decision.NewRunID()
	g, err := s.d.Point.DecideRun(ctx, decision.RunRequest{
		Principal: p, RunID: runID, Target: in.Target, Request: c,
		Handle: in.Elevation, Reason: in.Reason, Progress: progress(ctx, req),
	})
	if err != nil {
		r, b := errOut(err)
		return r, api.RunOut{Error: b}, nil
	}
	out := api.RunOut{RunID: runID, CoveredBy: g.CoveredBy()}
	if c.Interactive() {
		tk, exp, err := s.d.Point.IssueTicket(g, c)
		if err != nil {
			g.Release()
			r, b := errOut(err)
			return r, api.RunOut{Error: b}, nil
		}
		out.StreamTicket, out.StreamURL = tk, s.d.Config.StreamURL()
		out.TicketExpiresAt = exp.UTC().Format(time.RFC3339Nano)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "approved; attach to the stream with the nyyrikki CLI"}}}, out, nil
	}
	res, err := s.d.Runner.Run(g, c, timeout)
	if err != nil && res == nil {
		r, b := errOut(err)
		return r, api.RunOut{Error: b}, nil
	}
	if err == nil {
		code := res.ExitCode
		out.ExitCode = &code
	}
	if utf8.Valid(res.Stdout) {
		out.Stdout = string(res.Stdout)
	} else {
		out.StdoutBase64 = base64.StdEncoding.EncodeToString(res.Stdout)
	}
	out.Stderr = string(res.Stderr)
	out.StdoutTruncated, out.StderrTruncated = res.StdoutTruncated, res.StderrTruncated
	out.Detail = res.Detail
	text := out.Stdout
	if out.StdoutBase64 != "" {
		text = "(binary output in stdout_base64)"
	}
	if out.Stderr != "" {
		text += "\n--- stderr ---\n" + out.Stderr
	}
	if err != nil {
		// A cut run (timeout, elevation expiry or end) keeps what it
		// printed so far, next to the error (docs/04 D7).
		r, b := errOut(err)
		out.Error = b
		r.Content = append([]mcp.Content{&mcp.TextContent{Text: text}}, r.Content...)
		return r, out, nil
	}
	text += fmt.Sprintf("\n--- exit code %d ---", *out.ExitCode)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}, IsError: *out.ExitCode != 0}, out, nil
}

// buildRequest parses args for the target's type, once, before the
// decision (CODE-REVIEW.md: what is forwarded is what was approved).
func buildRequest(ssh bool, args []string, stdin []byte, interactive bool) (target.Request, error) {
	if ssh {
		return sshtarget.Build(args, stdin, interactive)
	}
	c, err := request.Parse(args, stdin, interactive)
	if err != nil {
		if codes.Of(err) == codes.Internal {
			err = codes.Wrap(codes.InvalidRequest, err, "the kubectl arguments could not be parsed")
		}
		return nil, err
	}
	return c, nil
}

func (s *Server) elevate(ctx context.Context, req *mcp.CallToolRequest, in api.ElevateIn) (*mcp.CallToolResult, api.ElevateOut, error) {
	p, err := principal(ctx, req)
	if err != nil {
		r, b := errOut(err)
		return r, api.ElevateOut{Error: b}, nil
	}
	var dur time.Duration
	if in.Duration != "" {
		if dur, err = time.ParseDuration(in.Duration); err != nil || dur <= 0 {
			r, b := errOut(s.invalid(ctx, p, in.Targets, codes.New(codes.InvalidRequest, "duration must be a positive Go duration")))
			return r, api.ElevateOut{Error: b}, nil
		}
	}
	if len(in.Targets) == 0 || len(in.Targets) > decision.MaxTargets {
		r, b := errOut(s.invalid(ctx, p, nil, codes.New(codes.InvalidRequest, "an elevation names 1 to %d targets", decision.MaxTargets)))
		return r, api.ElevateOut{Error: b}, nil
	}
	for _, t := range in.Targets {
		if !config.IsSlug(t) {
			r, b := errOut(s.invalid(ctx, p, nil, codes.New(codes.InvalidRequest, "targets must be target names")))
			return r, api.ElevateOut{Error: b}, nil
		}
	}
	if err := validateReason(in.Reason); err != nil {
		r, b := errOut(s.invalid(ctx, p, in.Targets, err))
		return r, api.ElevateOut{Error: b}, nil
	}
	e, err := s.d.Point.Elevate(ctx, decision.ElevateRequest{
		Principal: p, Targets: in.Targets, Duration: dur, Reason: in.Reason, Progress: progress(ctx, req),
	})
	if err != nil {
		r, b := errOut(err)
		return r, api.ElevateOut{Error: b}, nil
	}
	out := api.ElevateOut{ElevationID: e.ID, Handle: e.Handle, Targets: e.Targets, ExpiresAt: e.ExpiresAt.Format(time.RFC3339Nano)}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{
		Text: fmt.Sprintf("elevation %s live until %s on %v; pass the handle as 'elevation' to run", e.ID, out.ExpiresAt, e.Targets),
	}}}, out, nil
}
