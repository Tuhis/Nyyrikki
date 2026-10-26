package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// answerRejected is the answer to every rejected tap (docs/05 D4),
// including ones rejected because a dependency failed: the approver can't
// tell those apart and doesn't need to.
const answerRejected = "No longer valid"

// Reasons a callback is rejected, recorded as the audit Detail. They never
// include the callback data (docs/05 D4).
const (
	rejectNoMessage    = "no_message"
	rejectNoSender     = "no_sender"
	rejectMalformed    = "malformed_data"
	rejectUnknownKey   = "unknown_key"
	rejectWrongUser    = "wrong_user"
	rejectWrongChat    = "wrong_chat"
	rejectWrongMessage = "wrong_message"
	rejectNotPending   = "not_pending"
	rejectBadAction    = "bad_action"
	rejectNoResolver   = "no_resolver"
	rejectResolver     = "resolver_refused"
	rejectResolveError = "resolve_failed"
	rejectStoreError   = "store_failed"
)

func (b *Bot) handleUpdate(ctx context.Context, u update) {
	var tu tgUpdate
	if err := json.Unmarshal(u.raw, &tu); err != nil {
		b.log.Warn("skipping an update that does not parse", "update_id", u.id)
		return
	}
	switch {
	case tu.CallbackQuery != nil:
		b.handleCallback(ctx, tu.CallbackQuery)
	case tu.Message != nil:
		b.handleMessage(ctx, tu.Message)
	}
}

// handleMessage ignores every message except /start in a private chat,
// which is answered with the sender's user ID as a setup aid (docs/05
// non-goals). Nothing a message says changes any state.
func (b *Bot) handleMessage(ctx context.Context, m *tgMessage) {
	if m.From == nil || m.Chat == nil || m.Chat.Type != "private" || m.Chat.ID != m.From.ID {
		return
	}
	t := strings.TrimSpace(m.Text)
	if t != "/start" && !strings.HasPrefix(t, "/start ") && !strings.HasPrefix(t, "/start@") {
		return
	}
	text := fmt.Sprintf("Your Telegram user ID is <code>%d</code>.\nSet it as <code>telegram_user_id</code> in Nyyrikki's human registry to receive approval requests here.", m.From.ID)
	if _, err := b.sendMessage(ctx, m.Chat.ID, text, nil); err != nil && ctx.Err() == nil {
		b.log.Warn("replying to /start failed", "error", err.Error())
	}
}

// handleCallback applies the checks of docs/05 D4 and, if all pass, hands
// the tap to the decision point, which does the compare-and-set. Every
// callback is answered; every rejected one is audited.
func (b *Bot) handleCallback(ctx context.Context, cq *tgCallbackQuery) {
	reject := func(reason string, p *promptRow) {
		b.rejected(ctx, cq, reason, p)
		b.answerCallback(ctx, cq.ID, answerRejected)
	}

	if cq.From == nil || cq.From.ID <= 0 {
		reject(rejectNoSender, nil)
		return
	}
	// Inline-mode callbacks carry no message; ours always have one. An
	// InaccessibleMessage still has chat and message_id (docs/05 M5).
	if cq.Message == nil || cq.Message.Chat == nil {
		reject(rejectNoMessage, nil)
		return
	}
	// callback_data is client-controlled (docs/05 M1): only an opaque key.
	if !wellFormedKey(cq.Data) {
		reject(rejectMalformed, nil)
		return
	}
	p, action, err := b.lookupKey(ctx, cq.Data)
	if errors.Is(err, errNoPrompt) {
		reject(rejectUnknownKey, nil)
		return
	}
	if err != nil {
		reject(rejectStoreError, nil)
		return
	}
	// docs/05 D1, D4: only the approver, in their private chat, on the very
	// message the key was sent with.
	if cq.From.ID != p.approverID {
		reject(rejectWrongUser, &p)
		return
	}
	if cq.Message.Chat.ID != cq.From.ID {
		reject(rejectWrongChat, &p)
		return
	}
	if cq.Message.Chat.ID != p.chatID || cq.Message.MessageID != p.messageID {
		reject(rejectWrongMessage, &p)
		return
	}
	switch action {
	case approval.ActionApprove, approval.ActionDeny:
		if p.state != stateOpen {
			reject(rejectNotPending, &p)
			return
		}
	case approval.ActionEnd:
		if p.state != stateLive || p.kind != kindElevation {
			reject(rejectNotPending, &p)
			return
		}
	default:
		reject(rejectBadAction, &p)
		return
	}
	r := b.getResolver()
	if r == nil {
		reject(rejectNoResolver, &p)
		return
	}
	ok, err := r.Resolve(ctx, p.id, action, cq.From.ID)
	if err != nil {
		b.log.Warn("resolving a tap failed", "prompt", p.id, "error", err.Error())
		reject(rejectResolveError, &p)
		return
	}
	if !ok {
		// Already settled, expired, or a second tap: the decision point's
		// compare-and-set changed nothing.
		reject(rejectResolver, &p)
		return
	}
	var answer string
	switch action {
	case approval.ActionApprove:
		answer = "Approved"
	case approval.ActionDeny:
		answer = "Denied"
	default:
		answer = "Ended"
	}
	b.answerCallback(ctx, cq.ID, answer)
}

// rejected audits and logs a rejected callback. The audit record names the
// reason and, if known, the prompt; never the callback data.
func (b *Bot) rejected(ctx context.Context, cq *tgCallbackQuery, reason string, p *promptRow) {
	var from int64
	if cq.From != nil {
		from = cq.From.ID
	}
	rec := audit.Record{
		Kind:     codes.KindCallbackRejected,
		Decision: codes.Deny,
		Detail:   fmt.Sprintf("%s (from telegram user %d)", reason, from),
	}
	attrs := []any{"reason", reason, "from", from}
	if p != nil {
		if p.kind == kindElevation {
			rec.ElevationID = p.id
		} else {
			rec.ApprovalID = p.id
		}
		attrs = append(attrs, "prompt", p.id)
	}
	b.log.Info("callback rejected", attrs...)
	if err := b.audit.Append(ctx, rec); err != nil {
		b.log.Error("auditing a rejected callback failed", "reason", reason, "error", err.Error())
	}
}
