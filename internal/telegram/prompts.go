package telegram

import (
	"context"
	"errors"
	"fmt"
	"sync"

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

// AskEnroll sends the enrollment prompt of docs/08 §5.2, with the same
// contract as AskRun. It is stored as a one-off prompt: Approve and
// Deny, then closed; it never goes live.
func (b *Bot) AskEnroll(ctx context.Context, p approval.EnrollPrompt) error {
	return b.ask(ctx, p.ID, p.ApproverID, kindRun, renderEnroll(p))
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
// is rejected. ElevationLive swaps Approve and Deny for End now, and so
// does SessionLive on an interactive run's message (docs/07 D17). Settle is
// idempotent: settling a closed prompt, or a live one live again, changes
// nothing and returns nil. A prompt that was never sent is not an error.
//
// A terminal outcome always wins over ElevationLive, whatever order the
// calls arrive in (review L1): Settles of one prompt are serialised, edits
// included, and a lost compare-and-set is retried from a fresh read.
func (b *Bot) Settle(ctx context.Context, id string, o approval.Outcome) error {
	status, err := statusLine(o, b.now())
	if err != nil {
		return codes.Wrap(codes.Internal, err, "unknown outcome")
	}
	unlock := b.settleLocks.lock(id)
	defer unlock()

	// States only move open → live → closed, so after two lost
	// compare-and-sets the prompt is closed and the next read returns.
	for attempt := 0; attempt < 3; attempt++ {
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
		case o.Kind == approval.SessionApproved:
			// docs/07 D17: an approved interactive run keeps its message
			// (state live, no buttons) until its session attaches or not.
			if row.kind != kindRun {
				return codes.New(codes.Internal, "SessionApproved for an elevation prompt")
			}
			if row.state == stateLive {
				return nil // SessionLive came first
			}
			from, to = stateOpen, stateLive
		case o.Kind == approval.SessionLive:
			if row.kind != kindRun {
				return codes.New(codes.Internal, "SessionLive for an elevation prompt")
			}
			end := newCallbackKey()
			from, to = row.state, stateLive
			newKeys = []keyedAction{{end, approval.ActionEnd}}
			kb = &inlineKeyboard{InlineKeyboard: [][]inlineButton{{{Text: "End now", CallbackData: end}}}}
		case row.state == stateLive && row.kind == kindRun:
			switch o.Kind {
			case approval.SessionEnded, approval.SessionUnused, approval.Failed:
			default:
				return codes.New(codes.Internal, "outcome %d does not follow a live session", o.Kind)
			}
			from, to = stateLive, stateClosed
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

		if h := b.testHookBeforeTransition; h != nil {
			h()
		}
		won, err := b.transition(ctx, id, from, to, newKeys)
		if err != nil {
			return codes.Wrap(codes.Internal, err, "the approval channel's store failed")
		}
		if !won {
			continue // the state moved on since the read: decide again
		}
		// The keys are already gone, so even if the edit fails no tap on the
		// old buttons can count. The edit runs to completion even if the
		// caller's context ends: a half-retired prompt is misleading.
		if err := b.editMessage(context.WithoutCancel(ctx), row.chatID, row.messageID, withStatus(row.body, status), kb); err != nil {
			b.log.Warn("editing a settled prompt failed", "prompt", id, "error", err.Error())
			return codes.Wrap(codes.Unavailable, fmt.Errorf("edit: %w", err), "could not update the approver's message")
		}
		return nil
	}
	return codes.New(codes.Internal, "the prompt kept changing while it was settled")
}

// keyedLocks is one mutex per prompt ID, dropped when nobody holds it.
type keyedLocks struct {
	mu sync.Mutex
	m  map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func (k *keyedLocks) lock(id string) (unlock func()) {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*keyedLock)
	}
	l := k.m[id]
	if l == nil {
		l = &keyedLock{}
		k.m[id] = l
	}
	l.refs++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(k.m, id)
		}
		k.mu.Unlock()
	}
}
