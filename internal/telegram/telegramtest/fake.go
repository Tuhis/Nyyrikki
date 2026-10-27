// Package telegramtest is a fake Telegram Bot API for tests. It records the
// messages a bot sends and edits, lets a test push updates (button taps and
// text messages) for getUpdates to return, and can fail chosen calls.
//
// It checks what the real API would refuse and Nyyrikki relies on being
// refused: a wrong token (401), HTML that doesn't parse or uses an
// unsupported tag (400), and text over 4096 UTF-16 code units (400).
package telegramtest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// DefaultToken is the token a new Fake accepts.
const DefaultToken = "123456789:AAFakeTokenForTestsOnly_x-yz0123456789"

// Button is an inline keyboard button.
type Button struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// Message is a message the bot sent, as it currently stands (after edits
// when returned by Message).
type Message struct {
	ChatID              int64
	MessageID           int64
	Text                string
	ParseMode           string
	ProtectContent      bool
	LinkPreviewDisabled bool
	Buttons             [][]Button
}

// Button returns the button with the given text, if any.
func (m Message) Button(text string) (Button, bool) {
	for _, row := range m.Buttons {
		for _, b := range row {
			if b.Text == text {
				return b, true
			}
		}
	}
	return Button{}, false
}

// ButtonTexts lists the button labels in order.
func (m Message) ButtonTexts() []string {
	var out []string
	for _, row := range m.Buttons {
		for _, b := range row {
			out = append(out, b.Text)
		}
	}
	return out
}

// Edit is one editMessageText call that the fake accepted.
type Edit struct {
	ChatID    int64
	MessageID int64
	Text      string
	ParseMode string
	Buttons   [][]Button
}

// Answer is one answerCallbackQuery call.
type Answer struct {
	CallbackQueryID string
	Text            string
}

// Callback describes a button tap to push.
type Callback struct {
	FromID    int64
	ChatID    int64
	MessageID int64
	Data      string
	// Inaccessible sends the message as an InaccessibleMessage (date 0).
	Inaccessible bool
	// NoMessage omits the message, as for inline-mode callbacks.
	NoMessage bool
}

// TextMessage describes an incoming text message to push.
type TextMessage struct {
	FromID   int64
	ChatID   int64
	ChatType string // "private" when empty
	Text     string
}

// Fake is a fake Bot API server.
type Fake struct {
	srv *httptest.Server

	mu           sync.Mutex
	token        string
	sent         []Message
	current      map[[2]int64]*Message
	edits        []Edit
	answers      []Answer
	updates      []json.RawMessage
	nextUpdateID int64
	nextMsgID    int64
	nextCQ       int64
	fail         map[string][]int
	calls        map[string]int
	lastOffset   int64
	allowed      []string
	dropPending  []bool
	wake         chan struct{}
}

// New starts a Fake; it is closed when the test ends.
func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{
		token:        DefaultToken,
		current:      make(map[[2]int64]*Message),
		fail:         make(map[string][]int),
		calls:        make(map[string]int),
		nextUpdateID: 1000,
		nextMsgID:    1,
		wake:         make(chan struct{}),
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// URL is the base URL to configure as the bot's API URL.
func (f *Fake) URL() string { return f.srv.URL }

// Token is the token the fake currently accepts.
func (f *Fake) Token() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.token
}

// SetToken changes the accepted token (to test rotation).
func (f *Fake) SetToken(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = tok
}

// TokenFile writes the current token to a file in a temp dir and returns
// its path.
func (f *Fake) TokenFile(t testing.TB) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bot-token")
	if err := os.WriteFile(p, []byte(f.Token()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// FailNext makes the next call to method answer with status (and
// ok=false). Calls queue up: FailNext twice fails the next two calls.
// Status 409 and 401 carry Telegram's descriptions.
func (f *Fake) FailNext(method string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[method] = append(f.fail[method], status)
}

// Calls is the number of requests for method, failed ones included.
func (f *Fake) Calls(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// Sent returns every message sent, as sent.
func (f *Fake) Sent() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Message(nil), f.sent...)
}

// Message returns a sent message as it stands after edits.
func (f *Fake) Message(chatID, messageID int64) (Message, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.current[[2]int64{chatID, messageID}]
	if !ok {
		return Message{}, false
	}
	return *m, true
}

// Edits returns every accepted edit.
func (f *Fake) Edits() []Edit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Edit(nil), f.edits...)
}

// Answers returns every answerCallbackQuery call.
func (f *Fake) Answers() []Answer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Answer(nil), f.answers...)
}

// Answer returns the answer to the callback query with the given ID.
func (f *Fake) Answer(callbackQueryID string) (Answer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.answers {
		if a.CallbackQueryID == callbackQueryID {
			return a, true
		}
	}
	return Answer{}, false
}

// LastOffset is the offset of the most recent getUpdates call.
func (f *Fake) LastOffset() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastOffset
}

// AllowedUpdates is the allowed_updates of the most recent getUpdates call.
func (f *Fake) AllowedUpdates() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.allowed...)
}

// DeleteWebhookCalls lists the drop_pending_updates value of each
// deleteWebhook call.
func (f *Fake) DeleteWebhookCalls() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.dropPending...)
}

// PushCallback queues a callback query update and returns its query ID.
func (f *Fake) PushCallback(c Callback) string {
	f.mu.Lock()
	f.nextCQ++
	id := fmt.Sprintf("cq%d", f.nextCQ)
	f.mu.Unlock()
	cq := map[string]any{
		"id":            id,
		"from":          map[string]any{"id": c.FromID, "is_bot": false, "first_name": "Tester"},
		"chat_instance": "ci",
		"data":          c.Data,
	}
	if !c.NoMessage {
		date := time.Now().Unix()
		if c.Inaccessible {
			date = 0
		}
		cq["message"] = map[string]any{
			"message_id": c.MessageID,
			"chat":       map[string]any{"id": c.ChatID, "type": "private"},
			"date":       date,
		}
	}
	f.push("callback_query", cq)
	return id
}

// Tap pushes a tap on the button labelled text of msg, by user fromID, from
// msg's own chat. It fails the test if msg has no such button.
func (f *Fake) Tap(t testing.TB, msg Message, text string, fromID int64) string {
	t.Helper()
	b, ok := msg.Button(text)
	if !ok {
		t.Fatalf("message %d has no %q button (has %v)", msg.MessageID, text, msg.ButtonTexts())
	}
	return f.PushCallback(Callback{FromID: fromID, ChatID: msg.ChatID, MessageID: msg.MessageID, Data: b.CallbackData})
}

// PushMessage queues a text message update.
func (f *Fake) PushMessage(m TextMessage) {
	typ := m.ChatType
	if typ == "" {
		typ = "private"
	}
	f.mu.Lock()
	f.nextMsgID++
	id := f.nextMsgID
	f.mu.Unlock()
	f.push("message", map[string]any{
		"message_id": id,
		"from":       map[string]any{"id": m.FromID, "is_bot": false, "first_name": "Tester"},
		"chat":       map[string]any{"id": m.ChatID, "type": typ},
		"date":       time.Now().Unix(),
		"text":       m.Text,
	})
}

// PushRaw queues an update with the given fields; update_id is added.
func (f *Fake) PushRaw(fields map[string]any) { f.push("", fields) }

func (f *Fake) push(key string, v map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextUpdateID++
	u := map[string]any{"update_id": f.nextUpdateID}
	if key == "" {
		for k, val := range v {
			u[k] = val
		}
	} else {
		u[key] = v
	}
	raw, _ := json.Marshal(u)
	f.updates = append(f.updates, raw)
	close(f.wake)
	f.wake = make(chan struct{})
}

// Wait polls cond until it holds or the timeout passes, then fails the test.
func (f *Fake) Wait(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// WaitSent waits until at least n messages were sent and returns them.
func (f *Fake) WaitSent(t testing.TB, n int) []Message {
	t.Helper()
	f.Wait(t, fmt.Sprintf("%d sent messages", n), func() bool { return len(f.Sent()) >= n })
	return f.Sent()
}

// WaitAnswer waits for the answer to a callback query.
func (f *Fake) WaitAnswer(t testing.TB, callbackQueryID string) Answer {
	t.Helper()
	var a Answer
	f.Wait(t, "answer to "+callbackQueryID, func() bool {
		var ok bool
		a, ok = f.Answer(callbackQueryID)
		return ok
	})
	return a
}

type apiReply struct {
	OK          bool   `json:"ok"`
	Result      any    `json:"result,omitempty"`
	ErrorCode   int    `json:"error_code,omitempty"`
	Description string `json:"description,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v apiReply) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, desc string) {
	writeJSON(w, status, apiReply{OK: false, ErrorCode: status, Description: desc})
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/bot")
	if !ok {
		fail(w, http.StatusNotFound, "Not Found")
		return
	}
	tok, method, ok := strings.Cut(rest, "/")
	if !ok {
		fail(w, http.StatusNotFound, "Not Found")
		return
	}
	f.mu.Lock()
	f.calls[method]++
	goodToken := tok == f.token
	var forced int
	if q := f.fail[method]; len(q) > 0 {
		forced, f.fail[method] = q[0], q[1:]
	}
	f.mu.Unlock()

	if !goodToken {
		fail(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if forced != 0 {
		switch forced {
		case http.StatusConflict:
			fail(w, forced, "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running")
		case http.StatusUnauthorized:
			fail(w, forced, "Unauthorized")
		default:
			fail(w, forced, "Forced failure")
		}
		return
	}
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "Bad Request: invalid JSON")
		return
	}
	switch method {
	case "getUpdates":
		f.getUpdates(w, r, body)
	case "deleteWebhook":
		var drop bool
		_ = json.Unmarshal(body["drop_pending_updates"], &drop)
		f.mu.Lock()
		f.dropPending = append(f.dropPending, drop)
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, apiReply{OK: true, Result: true})
	case "sendMessage":
		f.sendMessage(w, body)
	case "editMessageText":
		f.editMessageText(w, body)
	case "answerCallbackQuery":
		var a Answer
		_ = json.Unmarshal(body["callback_query_id"], &a.CallbackQueryID)
		_ = json.Unmarshal(body["text"], &a.Text)
		f.mu.Lock()
		f.answers = append(f.answers, a)
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, apiReply{OK: true, Result: true})
	default:
		fail(w, http.StatusNotFound, "Not Found: method not found")
	}
}

func (f *Fake) getUpdates(w http.ResponseWriter, r *http.Request, body map[string]json.RawMessage) {
	var offset int64
	var timeout int
	var allowed []string
	_ = json.Unmarshal(body["offset"], &offset)
	_ = json.Unmarshal(body["timeout"], &timeout)
	if raw, ok := body["allowed_updates"]; ok {
		_ = json.Unmarshal(raw, &allowed)
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()
	for {
		f.mu.Lock()
		f.lastOffset = offset
		if allowed != nil {
			f.allowed = allowed
		}
		// An offset confirms every update below it.
		kept := f.updates[:0]
		var out []json.RawMessage
		for _, u := range f.updates {
			var head struct {
				UpdateID int64 `json:"update_id"`
			}
			_ = json.Unmarshal(u, &head)
			if head.UpdateID >= offset {
				kept = append(kept, u)
				out = append(out, u)
			}
		}
		f.updates = kept
		wake := f.wake
		f.mu.Unlock()
		if len(out) > 0 {
			writeJSON(w, http.StatusOK, apiReply{OK: true, Result: out})
			return
		}
		select {
		case <-wake:
		case <-ctx.Done():
			writeJSON(w, http.StatusOK, apiReply{OK: true, Result: []json.RawMessage{}})
			return
		}
	}
}

type markup struct {
	InlineKeyboard [][]Button `json:"inline_keyboard"`
}

func decodeText(w http.ResponseWriter, body map[string]json.RawMessage) (text, mode string, ok bool) {
	_ = json.Unmarshal(body["text"], &text)
	_ = json.Unmarshal(body["parse_mode"], &mode)
	if text == "" {
		fail(w, http.StatusBadRequest, "Bad Request: message text is empty")
		return "", "", false
	}
	n := len(text)
	if mode == "HTML" {
		var err error
		if n, err = CheckHTML(text); err != nil {
			fail(w, http.StatusBadRequest, "Bad Request: can't parse entities: "+err.Error())
			return "", "", false
		}
	}
	if n > 4096 {
		fail(w, http.StatusBadRequest, "Bad Request: message is too long")
		return "", "", false
	}
	return text, mode, true
}

func (f *Fake) sendMessage(w http.ResponseWriter, body map[string]json.RawMessage) {
	var chatID int64
	if err := json.Unmarshal(body["chat_id"], &chatID); err != nil || chatID == 0 {
		fail(w, http.StatusBadRequest, "Bad Request: chat not found")
		return
	}
	text, mode, ok := decodeText(w, body)
	if !ok {
		return
	}
	var protect bool
	_ = json.Unmarshal(body["protect_content"], &protect)
	var lpo struct {
		IsDisabled bool `json:"is_disabled"`
	}
	_ = json.Unmarshal(body["link_preview_options"], &lpo)
	var mk markup
	_ = json.Unmarshal(body["reply_markup"], &mk)

	f.mu.Lock()
	f.nextMsgID++
	m := Message{
		ChatID: chatID, MessageID: f.nextMsgID, Text: text, ParseMode: mode,
		ProtectContent: protect, LinkPreviewDisabled: lpo.IsDisabled, Buttons: mk.InlineKeyboard,
	}
	f.sent = append(f.sent, m)
	cur := m
	f.current[[2]int64{chatID, m.MessageID}] = &cur
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, apiReply{OK: true, Result: map[string]any{
		"message_id": m.MessageID,
		"chat":       map[string]any{"id": chatID, "type": "private"},
		"date":       time.Now().Unix(),
		"text":       text,
	}})
}

func (f *Fake) editMessageText(w http.ResponseWriter, body map[string]json.RawMessage) {
	var chatID, msgID int64
	_ = json.Unmarshal(body["chat_id"], &chatID)
	_ = json.Unmarshal(body["message_id"], &msgID)
	text, mode, ok := decodeText(w, body)
	if !ok {
		return
	}
	var mk markup
	_ = json.Unmarshal(body["reply_markup"], &mk)

	f.mu.Lock()
	defer f.mu.Unlock()
	cur, found := f.current[[2]int64{chatID, msgID}]
	if !found {
		fail(w, http.StatusBadRequest, "Bad Request: message to edit not found")
		return
	}
	if cur.Text == text && buttonsEqual(cur.Buttons, mk.InlineKeyboard) {
		fail(w, http.StatusBadRequest, "Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message")
		return
	}
	cur.Text, cur.ParseMode, cur.Buttons = text, mode, mk.InlineKeyboard
	f.edits = append(f.edits, Edit{ChatID: chatID, MessageID: msgID, Text: text, ParseMode: mode, Buttons: mk.InlineKeyboard})
	writeJSON(w, http.StatusOK, apiReply{OK: true, Result: map[string]any{
		"message_id": msgID,
		"chat":       map[string]any{"id": chatID, "type": "private"},
		"date":       time.Now().Unix(),
		"text":       text,
	}})
}

func buttonsEqual(a, b [][]Button) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

var allowedTags = map[string]bool{
	"b": true, "strong": true, "i": true, "em": true, "u": true, "ins": true,
	"s": true, "strike": true, "del": true, "code": true, "pre": true,
	"blockquote": true, "tg-spoiler": true,
}

// CheckHTML parses text as the Bot API's HTML parse mode would, closely
// enough for tests: only supported tags without attributes, properly nested;
// only &lt; &gt; &amp; &quot; and numeric entities; no bare '<' or '&'. It
// returns the length of the parsed text in UTF-16 code units.
func CheckHTML(text string) (int, error) {
	var stack []string
	n := 0
	for i := 0; i < len(text); {
		switch c := text[i]; c {
		case '<':
			j := strings.IndexByte(text[i:], '>')
			if j < 0 {
				return 0, fmt.Errorf("unclosed tag at byte %d", i)
			}
			tag := text[i+1 : i+j]
			i += j + 1
			if name, ok := strings.CutPrefix(tag, "/"); ok {
				if len(stack) == 0 || stack[len(stack)-1] != name {
					return 0, fmt.Errorf("unexpected end tag %q", name)
				}
				stack = stack[:len(stack)-1]
				continue
			}
			if !allowedTags[tag] {
				return 0, fmt.Errorf("unsupported start tag %q", tag)
			}
			stack = append(stack, tag)
		case '&':
			j := strings.IndexByte(text[i:], ';')
			if j < 0 {
				return 0, fmt.Errorf("bare & at byte %d", i)
			}
			ent := text[i+1 : i+j]
			switch {
			case ent == "lt", ent == "gt", ent == "amp", ent == "quot":
			case strings.HasPrefix(ent, "#") && len(ent) > 1:
			default:
				return 0, fmt.Errorf("unsupported entity &%s;", ent)
			}
			n++
			i += j + 1
		case '>':
			return 0, fmt.Errorf("bare > at byte %d", i)
		default:
			r, size := utf8.DecodeRuneInString(text[i:])
			if r == utf8.RuneError && size <= 1 {
				return 0, fmt.Errorf("invalid UTF-8 at byte %d", i)
			}
			n += utf16.RuneLen(r)
			i += size
		}
	}
	if len(stack) > 0 {
		return 0, fmt.Errorf("unclosed %q", stack[len(stack)-1])
	}
	return n, nil
}
