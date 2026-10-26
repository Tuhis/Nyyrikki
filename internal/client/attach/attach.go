// Package attach is the CLI's client of /stream (docs/02 D10, D12): it
// opens the WebSocket with a stream ticket and bridges it to a terminal.
package attach

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/coder/websocket"
	"golang.org/x/term"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/stream/protocol"
)

// Size is a terminal size.
type Size = protocol.Size

// Attach opens streamURL with ticket and the caller's authentication
// headers (Authorization and DPoP, made for GET on the canonical stream
// URL), copies in to the stream and the stream to out, and sends resizes.
// It returns the remote exit status once the server sends it. A refusal or
// a cut run returns a *codes.Error with the server's code.
func Attach(ctx context.Context, streamURL, ticket string, header http.Header, in io.Reader, out io.Writer, resizes <-chan Size) (int, error) {
	return AttachClient(ctx, nil, streamURL, ticket, header, in, out, resizes)
}

// AttachClient is Attach with a given HTTP client (nil for the default).
func AttachClient(ctx context.Context, client *http.Client, streamURL, ticket string, header http.Header, in io.Reader, out io.Writer, resizes <-chan Size) (int, error) {
	if ticket == "" {
		return -1, codes.New(codes.InvalidRequest, "no stream ticket")
	}
	h := header.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set(protocol.TicketHeader, ticket)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, streamURL, &websocket.DialOptions{
		HTTPClient:      client,
		HTTPHeader:      h,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return -1, refusal(resp, err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(protocol.ReadLimit)

	// Input and resizes go out until the stream ends. A local EOF just
	// stops sending: the remote side decides when the session is over.
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				if conn.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-resizes:
				if !ok {
					return
				}
				b, _ := json.Marshal(protocol.ClientMessage{Resize: &s})
				if conn.Write(ctx, websocket.MessageText, b) != nil {
					return
				}
			}
		}
	}()

	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return -1, ctx.Err()
			}
			return -1, codes.Wrap(codes.Unavailable, err, "the stream ended without an exit status")
		}
		switch typ {
		case websocket.MessageBinary:
			if _, err := out.Write(data); err != nil {
				return -1, codes.Wrap(codes.Internal, err, "writing the output failed")
			}
		case websocket.MessageText:
			var m protocol.ServerMessage
			if err := json.Unmarshal(data, &m); err != nil {
				return -1, codes.New(codes.Internal, "the server sent an unreadable message")
			}
			switch {
			case m.Error != nil:
				_ = conn.Close(websocket.StatusNormalClosure, "")
				return -1, &codes.Error{Code: codes.Code(m.Error.Code), Message: m.Error.Message}
			case m.ExitCode != nil:
				_ = conn.Close(websocket.StatusNormalClosure, "")
				return *m.ExitCode, nil
			}
		}
	}
}

// refusal turns a failed handshake into the server's error code.
func refusal(resp *http.Response, err error) error {
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
		var body struct {
			Error protocol.Error `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, protocol.ReadLimit)).Decode(&body) == nil && body.Error.Code != "" {
			return &codes.Error{Code: codes.Code(body.Error.Code), Message: body.Error.Message}
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return codes.New(codes.Unauthenticated, "not authenticated")
		}
	}
	return codes.Wrap(codes.Unavailable, err, "the stream could not be opened")
}

// AttachTerminal is Attach on the local terminal: stdin is put in raw mode
// for the session and restored on every path, and window size changes
// (SIGWINCH) are sent as resizes.
func AttachTerminal(ctx context.Context, streamURL, ticket string, header http.Header, stdin *os.File, stdout io.Writer) (int, error) {
	fd := int(stdin.Fd())
	if !term.IsTerminal(fd) {
		return -1, errors.New("stdin is not a terminal")
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return -1, err
	}
	defer term.Restore(fd, old)

	resizes := make(chan Size, 1)
	sendSize := func() {
		w, h, err := term.GetSize(fd)
		if err != nil || w <= 0 || h <= 0 || w > 0xffff || h > 0xffff {
			return
		}
		// Only the latest size matters: replace a pending one.
		select {
		case <-resizes:
		default:
		}
		select {
		case resizes <- Size{Cols: uint16(w), Rows: uint16(h)}:
		default:
		}
	}
	sendSize()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-winch:
				sendSize()
			}
		}
	}()
	return Attach(ctx, streamURL, ticket, header, stdin, stdout, resizes)
}
