package telegram

import (
	"context"
	"errors"
	"fmt"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// AskRun sends the one-off prompt of docs/05 D5 to the approver. It returns
// nil once the prompt is sent and its buttons are stored; any error means
// the request must be denied (docs/05 D3).
func (b *Bot) AskRun(ctx context.Context, p approval.RunPrompt) error {
	return b.ask(ctx, p.ID, p.ApproverID, kindRun, renderRun(p))
}

// AskElevation sends the elevation prompt of docs/05 D7, with the same
// contract as AskRun.
func (b *Bot) AskElevation(ctx context.Context, p approval.ElevationPrompt) error {
	return b.ask(ctx, p.ID, p.ApproverID, kindElevation, renderElevation(p))
}

func (b *Bot) ask(ctx context.Context, id string, approverID int64, kind, body string) error {
	// docs/05 D9: refused, not shortened, before anything else can happen.
	if !fits(body) {
		return codes.New(codes.InvalidRequest, errTooLargeMsg)
	}
	if id == "" || approverID <= 0 {
		// A user ID is positive; a private chat with the approver is the
		// only place a prompt may go (docs/05 D1).
		return codes.New(codes.Internal, "approval prompt without an ID or approver")
	}
	if !b.Healthy() {
		return codes.New(codes.Unavailable, "the approval channel is unavailable")
	}
	if exists, err := b.promptExists(ctx, id); err != nil {
		return codes.Wrap(codes.Internal, err, "the approval channel's store failed")
	} else if exists {
		return codes.New(codes.Internal, "an approval prompt with this ID was already sent")
	}

	approve, deny := newCallbackKey(), newCallbackKey()
	kb := &inlineKeyboard{InlineKeyboard: [][]inlineButton{{
		{Text: "Approve", CallbackData: approve},
		{Text: "Deny", CallbackData: deny},
	}}}
	msgID, err := b.sendMessage(ctx, approverID, body, kb)
	if err != nil {
		b.log.Warn("sending a prompt failed", "prompt", id, "error", err.Error())
		return codes.Wrap(codes.Unavailable, err, "the approval channel is unavailable")
	}
	row := promptRow{id: id, kind: kind, approverID: approverID, chatID: approverID, messageID: msgID, body: body, state: stateOpen}
	if err := b.insertPrompt(ctx, row, []keyedAction{{approve, approval.ActionApprove}, {deny, approval.ActionDeny}}); err != nil {
		// The prompt is visible but its buttons are unknown, so a tap would
		// be rejected anyway. Retire it so the chat doesn't show a live
		// question, and deny.
		b.log.Error("storing a sent prompt failed", "prompt", id, "error", err.Error())
		if status, serr := statusLine(approval.Outcome{Kind: approval.Failed}, b.now()); serr == nil {
			if eerr := b.editMessage(context.WithoutCancel(ctx), approverID, msgID, withStatus(body, status), nil); eerr != nil {
				b.log.Error("retiring an unstored prompt failed", "prompt", id, "error", eerr.Error())
			}
		}
		return codes.Wrap(codes.Internal, err, "the approval channel's store failed")
	}
	return nil
}

// Settle edits the prompt to show o (docs/05 D6, D7). Settled prompts lose
// their buttons, and their callback keys are dropped first, so a later tap
// is rejected. ElevationLive swaps Approve and Deny for End now. Settle is
// idempotent: settling a closed prompt, or a live one live again, changes
// nothing and returns nil. A prompt that was never sent is not an error.
func (b *Bot) Settle(ctx context.Context, id string, o approval.Outcome) error {
	status, err := statusLine(o, b.now())
	if err != nil {
		return codes.Wrap(codes.Internal, err, "unknown outcome")
	}
	row, err := b.loadPrompt(ctx, id)
	if errors.Is(err, errNoPrompt) {
		return nil
	}
	if err != nil {
		return codes.Wrap(codes.Internal, err, "the approval channel's store failed")
	}

	var from, to string
	var kb *inlineKeyboard
	var newKeys []keyedAction
	switch {
	case row.state == stateClosed:
		return nil
	case o.Kind == approval.ElevationLive:
		if row.kind != kindElevation {
			return codes.New(codes.Internal, "ElevationLive for a run prompt")
		}
		if row.state == stateLive {
			return nil
		}
		end := newCallbackKey()
		from, to = stateOpen, stateLive
		newKeys = []keyedAction{{end, approval.ActionEnd}}
		kb = &inlineKeyboard{InlineKeyboard: [][]inlineButton{{{Text: "End now", CallbackData: end}}}}
	case row.state == stateLive:
		switch o.Kind {
		case approval.ElevationEnded, approval.ElevationExpired, approval.Failed:
		default:
			return codes.New(codes.Internal, "outcome %d does not follow a live elevation", o.Kind)
		}
		from, to = stateLive, stateClosed
	default: // open, terminal outcome
		from, to = stateOpen, stateClosed
	}

	won, err := b.transition(ctx, id, from, to, newKeys)
	if err != nil {
		return codes.Wrap(codes.Internal, err, "the approval channel's store failed")
	}
	if !won {
		return nil // a concurrent Settle got there first
	}
	// The keys are already gone, so even if the edit fails no tap on the old
	// buttons can count. The edit runs to completion even if the caller's
	// context ends: a half-retired prompt is misleading.
	if err := b.editMessage(context.WithoutCancel(ctx), row.chatID, row.messageID, withStatus(row.body, status), kb); err != nil {
		b.log.Warn("editing a settled prompt failed", "prompt", id, "error", err.Error())
		return codes.Wrap(codes.Unavailable, fmt.Errorf("edit: %w", err), "could not update the approver's message")
	}
	return nil
}
