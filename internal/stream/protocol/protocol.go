// Package protocol is the wire format of the /stream endpoint (docs/02
// D10, docs/04 D12), shared by the server (internal/stream) and the CLI
// (internal/client/attach). It imports nothing heavy, so the CLI doesn't
// pull in kubectl.
//
// Binary messages carry terminal bytes both ways. The client sends text
// messages {"resize":{"cols":N,"rows":N}}. At the end the server sends one
// text message, {"exit_code":N} or {"error":{"code":"…","message":"…"}},
// and closes.
package protocol

// TicketHeader carries the stream ticket on the WebSocket handshake.
const TicketHeader = "Nyyrikki-Stream-Ticket"

// ReadLimit bounds every message either side reads.
const ReadLimit = 64 << 10

// Size is a terminal size.
type Size struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// ClientMessage is a text message from the client.
type ClientMessage struct {
	Resize *Size `json:"resize,omitempty"`
}

// ServerMessage is the server's final text message.
type ServerMessage struct {
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    *Error `json:"error,omitempty"`
}

// Error is an error code (docs/02 D14) and a message that never holds a
// credential, handle or ticket. Refused handshakes carry it as the HTTP
// body, as {"error": …}.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
