package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// authTransport adds the login's headers, with a fresh DPoP proof, to
// every request to /mcp.
type authTransport struct {
	login *Login
	base  http.RoundTripper
	now   func() time.Time
}

func (t *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.try(r)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || t.login.key == nil {
		return resp, err
	}
	// Nyyrikki asks for its DPoP nonce on the first call, and again after
	// it restarts (RFC 9449 §8): learn it and retry once.
	n := resp.Header.Get("DPoP-Nonce")
	if n == "" || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
		return resp, nil
	}
	if r.Body != nil && r.GetBody == nil {
		return resp, nil
	}
	resp.Body.Close()
	t.login.SetNonce(n)
	if r.GetBody != nil {
		body, err := r.GetBody()
		if err != nil {
			return nil, err
		}
		r = r.Clone(r.Context())
		r.Body = body
	}
	return t.try(r)
}

func (t *authTransport) try(r *http.Request) (*http.Response, error) {
	h, err := t.login.Header(r.Context(), r.Method, t.login.MCPURL, t.now)
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	for k, v := range h {
		r.Header[k] = v
	}
	return t.base.RoundTrip(r)
}

// Session is a connection to /mcp.
type Session struct {
	cs *mcp.ClientSession
}

// Connect opens an MCP session to the login's server. onProgress, if set,
// receives progress messages while a call waits for an approval.
func Connect(ctx context.Context, l *Login, version string, onProgress func(string)) (*Session, error) {
	hc, err := HTTPClient(l.CAFile)
	if err != nil {
		return nil, err
	}
	hc.Transport = &authTransport{login: l, base: hc.Transport, now: time.Now}
	c := mcp.NewClient(&mcp.Implementation{Name: "nyyrikki-cli", Version: version}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
			if onProgress != nil && req.Params != nil {
				onProgress(req.Params.Message)
			}
		},
	})
	cs, err := c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: l.MCPURL, HTTPClient: hc, MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &Session{cs: cs}, nil
}

// Close ends the session.
func (s *Session) Close() error { return s.cs.Close() }

// ToolError is a failed tool call, with Nyyrikki's code (docs/02 D14).
type ToolError struct {
	Code    codes.Code
	Message string
}

func (e *ToolError) Error() string { return e.Message }

// Call calls a tool and decodes its structured result into out.
func (s *Session) Call(ctx context.Context, name string, args, out any) error {
	res, err := s.cs.CallTool(ctx, &mcp.CallToolParams{
		Name: name, Arguments: args,
		Meta: mcp.Meta{"progressToken": fmt.Sprintf("nyyrikki-%d", time.Now().UnixNano())},
	})
	if err != nil {
		return err
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return err
	}
	if res.IsError {
		var e struct {
			Error struct {
				Code    codes.Code `json:"code"`
				Message string     `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error.Code != "" {
			if out != nil {
				// The result may still carry partial output (a cut run).
				_ = json.Unmarshal(b, out)
			}
			return &ToolError{Code: e.Error.Code, Message: e.Error.Message}
		}
		// A run whose command failed is IsError too, but carries a
		// normal result.
		if out != nil && json.Unmarshal(b, out) == nil && len(b) > 4 {
			return nil
		}
		return &ToolError{Code: codes.Internal, Message: textOf(res)}
	}
	if out == nil {
		return nil
	}
	if res.StructuredContent == nil {
		return errors.New("the server returned no structured result")
	}
	return json.Unmarshal(b, out)
}

func textOf(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			return t.Text
		}
	}
	return "tool call failed"
}
