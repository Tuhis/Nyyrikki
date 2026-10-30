// Package sshtarget runs commands on Linux hosts with OpenSSH, as an
// account that belongs to the human, with a short-lived certificate from
// Nyyrikki's user CA (docs/07): the request and its display and digest
// (D1, D2), certificate minting (D5), host verification (D8) and the
// runner (D9, D11).
package sshtarget

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/textsafe"
)

// MaxCommand is the longest command string (docs/07 D1).
const MaxCommand = 16 << 10

// Detail values of the refusals Build returns.
const (
	DetailEmpty            = "empty_command"
	DetailTooLong          = "command_too_long"
	DetailControlChar      = "control_character"
	DetailInvalidUTF8      = "invalid_utf8"
	DetailInteractiveStdin = "interactive_with_stdin"
)

// Request is a checked SSH request (docs/07 D1): the command string, as
// the host's shell will read it, stdin, and whether it is a terminal
// session. It is immutable once Build returns it.
type Request struct {
	command     string
	stdin       []byte
	interactive bool
}

// Build joins args with single spaces into the command string, as ssh
// does (docs/07 D1, M13), and checks it. args may be empty only for an
// interactive run, which then asks for a login shell. Every refusal is a
// *codes.Error with codes.InvalidRequest and a Detail.
func Build(args []string, stdin []byte, interactive bool) (*Request, error) {
	if len(args) == 0 && !interactive {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailEmpty, "no command; only an interactive run may open a login shell")
	}
	cmd := strings.Join(args, " ")
	if len(args) > 0 && strings.TrimSpace(cmd) == "" {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailEmpty, "the command is empty")
	}
	if len(cmd) > MaxCommand {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailTooLong, "the command is limited to %d bytes", MaxCommand)
	}
	if !utf8.ValidString(cmd) {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailInvalidUTF8, "the command must be valid UTF-8")
	}
	for _, r := range cmd {
		// Tab and newline are what multi-line commands and heredocs need;
		// any other control character could make what the approver reads
		// differ from what the shell reads (docs/07 D1).
		if unicode.IsControl(r) && r != '\t' && r != '\n' {
			return nil, codes.WithDetail(codes.InvalidRequest, DetailControlChar, "the command may not contain control characters other than tab and newline")
		}
	}
	if interactive && len(stdin) > 0 {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailInteractiveStdin, "an interactive run takes its input from the terminal, not from stdin")
	}
	return &Request{command: cmd, stdin: bytes.Clone(stdin), interactive: interactive}, nil
}

// Command is the command string, exactly as it is sent; "" asks for a
// login shell.
func (r *Request) Command() string { return r.command }

// Stdin returns the stdin bytes, as sent.
func (r *Request) Stdin() []byte { return bytes.Clone(r.stdin) }

// Interactive reports whether this is a terminal session.
func (r *Request) Interactive() bool { return r.interactive }

// Type is the target type SSH requests are for.
func (r *Request) Type() string { return codes.TypeSSH }

const digestPrefix = "nyyrikki-ssh-request-v1\x00"

// Digest is what an approval binds to (docs/07 D2): SHA-256 over the
// prefix and then the target, the remote account, the command string,
// stdin and the interactive flag, each but the flag preceded by its
// length as 8 bytes big-endian, so no two requests share an encoding.
// account comes from the registry (docs/07 D3), never from the request.
func (r *Request) Digest(target, account string) [32]byte {
	h := sha256.New()
	h.Write([]byte(digestPrefix))
	var n [8]byte
	for _, f := range [][]byte{[]byte(target), []byte(account), []byte(r.command), r.stdin} {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	if r.interactive {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// Audit is the audited form: the command string as sent, and stdin's
// size and hash (docs/07 §6, docs/03 D6).
func (r *Request) Audit() audit.Request {
	a := audit.Request{Command: r.command, Interactive: r.interactive}
	if len(r.stdin) > 0 {
		sum := sha256.Sum256(r.stdin)
		a.StdinBytes = len(r.stdin)
		a.StdinSHA256 = hex.EncodeToString(sum[:])
	}
	return a
}

// DisplayCommand is the command string with every character that could
// hide or reorder text shown as \u{…} (docs/04 §5.2); tab and newline
// stay, so a multi-line command reads as it runs (docs/07 D2). A login
// shell shows as "(login shell)". Nothing is redacted.
func (r *Request) DisplayCommand() string {
	if r.command == "" {
		return "(login shell)"
	}
	var b strings.Builder
	run := 0
	for _, c := range r.command {
		if textsafe.IsCombining(c) {
			run++
		} else {
			run = 0
		}
		switch {
		case c == '\n' || c == '\t':
			b.WriteRune(c)
		case textsafe.Invisible(c) || run > textsafe.MaxCombiningRun:
			fmt.Fprintf(&b, `\u{%x}`, c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// DisplayStdin is stdin's size and hash, never its contents
// (docs/07 OD6, D2); "" without stdin.
func (r *Request) DisplayStdin() string {
	if len(r.stdin) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.stdin)
	return fmt.Sprintf("‹stdin: %d bytes, sha256:%s, not shown›", len(r.stdin), hex.EncodeToString(sum[:])[:12])
}
