package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maxResponseBytes = 4 << 20
	callTimeout      = 30 * time.Second
	maxTokenLen      = 256
)

// apiError is a Bot API answer with ok=false or a non-2xx status. Its text
// never contains the request URL (docs/05 D10).
type apiError struct {
	Method      string
	Status      int
	Description string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("telegram %s: %d %s", e.Method, e.Status, e.Description)
}

// transportError is a failed HTTP exchange. net/http wraps those in a
// *url.Error whose text includes the URL, and so the token; this keeps only
// the inner error, with the token scrubbed from its text in case.
type transportError struct {
	method string
	msg    string
	err    error
}

func (e *transportError) Error() string { return "telegram " + e.method + ": " + e.msg }
func (e *transportError) Unwrap() error { return e.err }

type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
}

// readToken reads the token file. It is called on every API call so that a
// rotated token takes effect without a restart (docs/05 D10). Errors never
// include the file's contents.
func (b *Bot) readToken() (string, error) {
	raw, err := os.ReadFile(b.cfg.TokenFile)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return "", fmt.Errorf("telegram: reading the bot token file: %w", pe.Err)
		}
		return "", errors.New("telegram: reading the bot token file failed")
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" || len(tok) > maxTokenLen {
		return "", errors.New("telegram: the bot token file is empty or too long")
	}
	// The token goes into the URL path; anything outside Telegram's token
	// alphabet could change the URL, so it is refused.
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ':' || c == '_' || c == '-') {
			return "", errors.New("telegram: the bot token file holds characters a bot token can't have")
		}
	}
	return tok, nil
}

// call POSTs params as JSON to method and decodes the result into out
// (when non-nil). timeout bounds the call; zero means callTimeout.
func (b *Bot) call(ctx context.Context, method string, params any, out any, timeout time.Duration) error {
	tok, err := b.readToken()
	if err != nil {
		return err
	}
	body, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("telegram %s: encoding the request: %w", method, err)
	}
	if timeout <= 0 {
		timeout = callTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.apiURL+"/bot"+tok+"/"+method, bytes.NewReader(body))
	if err != nil {
		// The error text would contain the URL.
		return fmt.Errorf("telegram %s: building the request failed", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		inner := err
		var ue *url.Error
		if errors.As(err, &ue) {
			inner = ue.Err
		}
		return &transportError{method: method, msg: scrub(inner.Error(), tok), err: inner}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return &transportError{method: method, msg: "reading the response failed", err: ctx.Err()}
	}
	var ar apiResponse
	if err := json.Unmarshal(data, &ar); err != nil {
		if resp.StatusCode/100 != 2 {
			return &apiError{Method: method, Status: resp.StatusCode, Description: "unparseable error response"}
		}
		return &apiError{Method: method, Status: resp.StatusCode, Description: "unparseable response"}
	}
	if !ar.OK || resp.StatusCode/100 != 2 {
		status := ar.ErrorCode
		if status == 0 || resp.StatusCode/100 != 2 {
			status = resp.StatusCode
		}
		if status/100 == 2 {
			status = http.StatusBadGateway // ok=false with 200: treat as a failure
		}
		return &apiError{Method: method, Status: status, Description: shorten(scrub(ar.Description, tok), 200)}
	}
	if out != nil {
		if err := json.Unmarshal(ar.Result, out); err != nil {
			return &apiError{Method: method, Status: resp.StatusCode, Description: "unexpected result shape"}
		}
	}
	return nil
}

func scrub(s, tok string) string {
	if tok == "" {
		return s
	}
	for _, t := range []string{tok, url.PathEscape(tok), url.QueryEscape(tok)} {
		s = strings.ReplaceAll(s, t, "[token]")
	}
	return s
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Bot API types: only the fields this package reads.

type tgUser struct {
	ID int64 `json:"id"`
}

type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// tgMessage covers Message and InaccessibleMessage (docs/05 M5): both carry
// chat and message_id, which is all a callback check needs.
type tgMessage struct {
	MessageID int64   `json:"message_id"`
	Chat      *tgChat `json:"chat"`
	From      *tgUser `json:"from"`
	Date      int64   `json:"date"`
	Text      string  `json:"text"`
}

type tgCallbackQuery struct {
	ID      string     `json:"id"`
	From    *tgUser    `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUpdate struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message"`
	CallbackQuery *tgCallbackQuery `json:"callback_query"`
}

type update struct {
	id  int64
	raw json.RawMessage
}

type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type inlineKeyboard struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

func (b *Bot) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	params := map[string]any{
		"offset":          offset,
		"timeout":         b.pollSec,
		"allowed_updates": []string{"message", "callback_query"},
	}
	var raws []json.RawMessage
	if err := b.call(ctx, "getUpdates", params, &raws, time.Duration(b.pollSec)*time.Second+callTimeout); err != nil {
		return nil, err
	}
	out := make([]update, 0, len(raws))
	for _, r := range raws {
		var head struct {
			UpdateID *int64 `json:"update_id"`
		}
		if err := json.Unmarshal(r, &head); err != nil || head.UpdateID == nil {
			// Without an ID the offset can't move past it; treat the whole
			// batch as a failed call.
			return nil, &apiError{Method: "getUpdates", Status: http.StatusBadGateway, Description: "update without update_id"}
		}
		out = append(out, update{id: *head.UpdateID, raw: r})
	}
	return out, nil
}

// sendMessage sends HTML text to chatID through the per-chat queue and
// returns the message ID.
func (b *Bot) sendMessage(ctx context.Context, chatID int64, text string, kb *inlineKeyboard) (int64, error) {
	params := map[string]any{
		"chat_id":              chatID,
		"text":                 text,
		"parse_mode":           "HTML",
		"protect_content":      true,
		"link_preview_options": map[string]any{"is_disabled": true},
	}
	if kb != nil {
		params["reply_markup"] = kb
	}
	var msg tgMessage
	err := b.queue.do(ctx, chatID, func() error {
		return b.call(ctx, "sendMessage", params, &msg, 0)
	})
	if err != nil {
		return 0, err
	}
	if msg.MessageID == 0 || msg.Chat == nil || msg.Chat.ID != chatID {
		return 0, &apiError{Method: "sendMessage", Status: http.StatusBadGateway, Description: "result names another chat or no message"}
	}
	return msg.MessageID, nil
}

// editMessage replaces a prompt's text and keyboard. A nil kb removes the
// buttons. "message is not modified" counts as success, so a repeated edit
// is harmless.
func (b *Bot) editMessage(ctx context.Context, chatID, messageID int64, text string, kb *inlineKeyboard) error {
	if kb == nil {
		kb = &inlineKeyboard{InlineKeyboard: [][]inlineButton{}}
	}
	params := map[string]any{
		"chat_id":              chatID,
		"message_id":           messageID,
		"text":                 text,
		"parse_mode":           "HTML",
		"link_preview_options": map[string]any{"is_disabled": true},
		"reply_markup":         kb,
	}
	err := b.queue.do(ctx, chatID, func() error {
		return b.call(ctx, "editMessageText", params, nil, 0)
	})
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusBadRequest && strings.Contains(ae.Description, "message is not modified") {
		return nil
	}
	return err
}

func (b *Bot) answerCallback(ctx context.Context, id, text string) {
	if id == "" {
		return
	}
	err := b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil, 0)
	if err != nil && ctx.Err() == nil {
		b.log.Warn("answerCallbackQuery failed", "error", err.Error())
	}
}
