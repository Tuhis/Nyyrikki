# R5 — Telegram escalation: one-off approvals and time-boxed elevation (docs/05)

**Status**: drafted 2026-10-26, owner decision OD1 taken the same day.
Awaiting the owner's approval of the doc as a whole; merging the PR that
adds it is that approval. Status lives in [`ROADMAP.md`](../ROADMAP.md).

Chunks **TG1–TG4** (`TG` = Telegram; unused).

**Relationship to earlier work**: builds on [docs/01](01-foundations.md)
OD1 (one human, who approves their own agents) and
[docs/02](02-gateway-core.md) D7 (waiting). The replaced plan's
docs/04 is the source of the measured facts in `docs/measured.md`; its
decisions are not carried over except where re-stated here.

---

## 1. Purpose

Every privileged request waits for a human who is away from the agent's
machine and has a phone. The approver needs to see, in a few seconds,
exactly what will run, as whom, for which agent, and what the agent
claims it is for, and answer with one tap. Nothing the agent controls
may be able to produce that tap.

### Non-goals

- Approval surfaces other than Telegram (`CLAUDE.md`, Rejected).
- More than one approver (docs/01 OD1).
- Text commands that do anything: the bot answers `/start` with the
  user's ID (for setup) and ignores every other message.

## 2. Measured and verified before writing

Re-read on 2026-10-26 against the current Bot API reference; the rows
come from `docs/measured.md` (Telegram).

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `callback_data` is 1–64 bytes and is not checked by Telegram against the message's buttons | Bot API: InlineKeyboardButton, CallbackQuery | Confirmed. D4 treats it as an opaque random key |
| M2 | `getUpdates` long polling confirms updates by `offset`; a `409 Conflict` means another poller or a webhook uses the token | Bot API: getUpdates; `docs/gotchas.md` | Confirmed. D2 |
| M3 | `sendMessage` text is at most 4096 characters; `protect_content` and `link_preview_options.is_disabled` exist; HTML mode needs `<`, `>`, `&` escaped | Bot API: sendMessage, HTML style | Confirmed. D5, D9 |
| M4 | Bots can edit their messages without a time limit, but delete only within 48 h | Bot API: editMessageText | Confirmed. D6: prompts are retired by editing |
| M5 | `CallbackQuery.message` may be an `InaccessibleMessage` that still carries `chat.id` and `message_id` | Bot API: MaybeInaccessibleMessage | Confirmed. D4 |
| M6 | In a private chat, the chat ID equals the user ID, though the docs say so only indirectly | `docs/measured.md` (Telegram M15) | D4 checks `chat.id == from.id` explicitly |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | Can the approver end an elevation early from the chat? | **Yes, an "End now" button** (owner, 2026-10-26; docs/02 OD2). |
| OD2 | May the human an agent acts for approve its requests? | **Yes, they must**: with one human in v1 (docs/01 OD1) they are the only approver. Recorded here as R5's answer. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **The approver** of a human's agents is that human's `telegram_user_id` (docs/02 D4). Messages go to the private chat with that ID. A callback counts only if it comes from that user. | OD2; INV-04. |
| D2 | **Long polling only**, `getUpdates` with a 50 s timeout, `allowed_updates: ["message", "callback_query"]`. At startup the bot calls `deleteWebhook` without dropping updates, so polling works. The offset is stored in SQLite and advanced after each update is handled. A `409 Conflict` or `401` stops the poller and marks the approval channel unhealthy: every new escalation is denied `unavailable`, and `/readyz` fails, until the process restarts. Other errors back off (1 s doubling to 30 s). | `CLAUDE.md`, Rejected: no webhooks. A second poller would be handed the approvals (gotchas). |
| D3 | **Sending fails closed.** If `sendMessage` fails, the approval is settled `denied` with code `unavailable`, and the waiting call gets that. | INV-07. |
| D4 | **A callback is checked** before anything happens: `callback_data` is `v1:` plus 22 base64url characters (16 random bytes) stored with the approval or elevation and the action, looked up by exact match. The update's `from.id` must be the approver's ID, `message.chat.id` must equal `from.id`, and the chat and message IDs must equal the ones stored when the prompt was sent. The approval must still be `pending` (or, for "End now", the elevation `live`) and unexpired. The transition is a compare-and-set, so a second tap, a replay or a race with expiry is a no-op. Every rejected callback is answered "No longer valid" and audited. | M1, M5; INV-04; `CODE-REVIEW.md`: an approval is bound to exactly one thing. |
| D5 | **The one-off message** (HTML, `protect_content`, no link previews): a header "Run request" with the target; "Runs as" with the Kubernetes user and groups; "Agent" with the client's registered name marked as its claim, the short agent key (docs/03 D3) and the sign-in time; the canonical request in `<pre>` (docs/04 §5.2); stdin, if any, in a second `<pre>`; the reason in a `<blockquote>` headed "Agent's claim (unverified):"; and the expiry time. Buttons: "Approve" and "Deny". | `CLAUDE.md`: the approver sees the request itself, and the reason as the agent's claim. |
| D6 | **Settled prompts are edited**, never deleted (M4): the buttons are removed and a line says what happened ("Approved at 12:03:04", "Denied", "Expired: denied", "Withdrawn by the agent"). | The chat stays an honest record; deleting fails after 48 h. |
| D7 | **The elevation message** shows the targets, the duration, "Runs as", the agent and the reason as in D5. Once approved it is edited to "Live until 12:18:04" with an **"End now"** button (OD1); ending, or expiry, edits it to "Ended at …" or "Expired at …" without buttons. Ending cancels the elevation's runs and streams at once (docs/02 D8, docs/04 D8). | OD1. |
| D8 | **Agent-controlled text is escaped and marked.** The reason, the client name and the request are HTML-escaped; control, bidi and zero-width characters are shown as `\u{…}`; the reason is cut at 500 characters and the client name at 64, with "…(cut)" appended. They never appear outside their labelled block, so they can't pass for Nyyrikki's text. | `CODE-REVIEW.md`: the agent is untrusted; hostile-input tests. |
| D9 | **A request that doesn't fit is refused**, not shortened: if the rendered message exceeds 4096 characters, the call fails `invalid_request` ("request too large to show the approver; split it"), audited, and nothing is sent. | `CLAUDE.md`: the approver sees the request itself, never a part of it. |
| D10 | **The bot token** is read from a file (`telegram.bot_token_file`) on each API call, never logged; the API base URL is configurable (`telegram.api_url`, default `https://api.telegram.org`) so tests can use a fake. Errors from the Bot API are logged without the request URL, which contains the token. | docs/01 D15, D16. |
| D11 | **Rate**: messages to one chat are sent at most one per second, queued in order. | Telegram's per-chat limit (`docs/measured.md`, Telegram M13). |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Sending long requests as a document | The approver would have to open a file to see what runs; a one-tap answer to a message that doesn't show the request is what `CLAUDE.md` forbids. Revisit if D9 refuses real work often. |
| Approving with a text command (`/approve <id>`) | Text is easy to forge into a message the agent influences (a reason that looks like a command); buttons bound by D4 aren't. |
| Webhooks | `CLAUDE.md`, Rejected. |

## 5. Design

### 5.1 Interface to the decision point

```go
type Asker interface {
    // AskRun sends a one-off prompt and returns when it was sent.
    AskRun(ctx context.Context, p RunPrompt) error
    AskElevation(ctx context.Context, p ElevationPrompt) error
    // Settle edits the prompt to show the outcome.
    Settle(ctx context.Context, id string, outcome Outcome) error
    Healthy() bool
}
```

The decision point owns the state; Telegram callbacks call back into
`decision.Point.Resolve(id, action, approverID)`, which does the
compare-and-set (docs/02 D15).

### 5.2 Configuration

```yaml
telegram:
  bot_token_file: /etc/nyyrikki/telegram/bot-token
  api_url: https://api.telegram.org
```

## 6. Security considerations

- **Inputs.** Telegram updates are untrusted (`CLAUDE.md`): D4.
  Agent text shown to the approver: D8.
- **Dependency failures.** Bot API unreachable or failing: D2, D3.
- **What reaches Telegram.** The canonical request with docs/04 D14's
  redaction, the reason, the agent's claimed name and short key. Never a
  token, handle, ticket or credential.
- **New ways to reach a target.** None: callbacks only settle state
  that the decision point owns.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 Approve, deny and expiry each settle the prompt and edit it | `telegram` tests against a fake Bot API |
| G2 A callback from another user, another chat, another message, with unknown data, after expiry, or a second time is rejected and audited | `TestCallbackRejected*` |
| G3 Hostile reasons and names (HTML, bidi, zero-width, 10 000 characters) render escaped inside their labelled block | `TestRenderHostile` |
| G4 A send failure, a 409 and a 401 each deny | `TestSendFailureDenies`, `TestConflictStopsPolling` |
| G5 "End now" ends the elevation and cuts its runs | `TestEndNow` |
| G6 An oversized request is refused before anything is sent | `TestOversizeRefused` |
| G7 The bot token never appears in logs | `TestTokenNotLogged` |
| G8 A real approval on a real phone works end to end | manual, by the owner, M4 |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **TG1** | Bot API client, poller, offset, health | G4, G7 |
| **TG2** | rendering | G3, G6 |
| **TG3** | callbacks, settle, edits | G1, G2 |
| **TG4** | elevation messages and "End now" | G5 |

## 9. Risks and open questions

- **Rubber-stamping**: one human approving their own agents (OD2). The
  message design is the defence; R8 may help later.
- **Do clients auto-link text inside `<pre>`?** (`docs/measured.md`,
  Telegram M16.) Measured by the owner in M4; no text command acts, so
  the answer isn't critical.

## 10. How it was implemented (YYYY-MM-DD)

<!-- Added during implementation. -->

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
