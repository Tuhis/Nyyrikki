# R5 — Telegram escalation (docs/04)

**Status**: drafted 2026-10-25. Status lives in
[`ROADMAP.md`](../ROADMAP.md). Open: OD1 (what may be sent to Telegram)
and OD2 (dual control in v1). Decisions D1–D14 await the owner's
approval.

Chunks **TG1–TG5** (`TG` = Telegram; unused).

**Relationship to earlier work**: implements the approval channel chosen
in [docs/01](01-foundations.md) OD2: a tap in Telegram approves on its
own. It decides the grants, extensions and held steps defined in
[docs/02](02-grant-core.md), and it writes every decision through
[docs/03](03-audit-log.md). It replaces the Warden design's passkey
approval page and its Web Push and ntfy notifications.

---

## 1. Purpose

The agent's request is only as useful as the time it takes a human to
answer it. If the answer means opening a laptop, finding a page and
logging in, the agent sits idle and the user loses the thread. The
approver already has Telegram on their phone. With this doc, they get a
message within a second of the request, carrying what they need to
decide: who is asking, for which profile, what that profile can do, and
what the agent says it wants. One tap approves or denies. The same chat
carries the held operations of step mode, extension requests and a
revoke button for every active grant.

The tap has to be bound to exactly one decision, by exactly one approver,
before it expires. It must not be replayable, forwardable or producible
by anything on A.

### Non-goals

- **Passkey step-up for high-risk profiles.** It was rejected by the
  owner (docs/01 OD2).
- **Group chats and channels.** Approvals happen in private chats only
  (D4).
- **Moderated mode and live session view** (R7, docs/02 D12).
- **Notifications through other channels**, such as e-mail, ntfy or Web
  Push.
- **A Telegram Mini App.** v1 uses plain messages and inline keyboards.

## 2. Measured and verified before writing

All sources were fetched on 2026-10-25. The Bot API version at that date
is **10.3 (2026-08-24)**.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `callback_data` is 1–64 bytes | [Bot API: InlineKeyboardButton](https://core.telegram.org/bots/api#inlinekeyboardbutton) | Confirmed: "1-64 bytes" |
| M2 | Callback `data` is **not** checked by Telegram against the buttons on the message. A modified client can send any bytes for any message it can see. | [Bot API: CallbackQuery](https://core.telegram.org/bots/api#callbackquery); [MTProto messages.getBotCallbackAnswer](https://core.telegram.org/method/messages.getBotCallbackAnswer) (takes `peer`, `msg_id`, arbitrary `data:bytes`) | Confirmed. The Bot API says "the message originated the query can contain no callback buttons with this data". D5 treats `data` as an opaque lookup key and nothing more. |
| M3 | `CallbackQuery.message` may be an `InaccessibleMessage` (fields `chat`, `message_id`, and `date` = 0) when the message was deleted or is otherwise inaccessible | Bot API: MaybeInaccessibleMessage | Confirmed. `chat.id` and `message_id` are still present, so D5's checks still work |
| M4 | Clients show a progress indicator until the bot calls `answerCallbackQuery` | Bot API: CallbackQuery | Confirmed |
| M5 | `getUpdates` long polling: `timeout` in seconds. An update is confirmed once `getUpdates` is called with a higher `offset`. It doesn't work while a webhook is set. Unconfirmed updates are kept for at most 24 h. `allowed_updates` persists between calls. | [Bot API: getUpdates](https://core.telegram.org/bots/api#getupdates) | Confirmed. Consequences: D2 (no webhook), D3 (offset committed with the effects), D12 (24 h loss is harmless because decisions expire within minutes) |
| M6 | `sendMessage` has `protect_content` ("Protects the contents of the sent message from forwarding and saving") and `link_preview_options.is_disabled`. Text is 1–4096 characters after entity parsing. | Bot API: sendMessage | Confirmed |
| M7 | HTML parse mode: every `<`, `>` and `&` that is not part of a tag or entity must be escaped. Named entities supported: only `&lt; &gt; &amp; &quot;`. `<pre>`, `<code>`, `<blockquote>` and `<blockquote expandable>` are supported. | [Bot API: HTML style](https://core.telegram.org/bots/api#html-style) | Confirmed. Drives §5.7 |
| M8 | A bot can edit its own messages without a time limit. The 48 h limit applies only to some business messages. **Deleting** is limited to messages less than 48 h old. | Bot API: editMessageText, editMessageReplyMarkup, deleteMessage | Confirmed. Prompts are retired by editing, never by deleting (D9) |
| M9 | Bots can't start a conversation. Deep link `t.me/<bot>?start=<param>`: up to 64 characters of `A-Z a-z 0-9 _ -`, arriving as the message `/start <param>` | [Bots: deep linking](https://core.telegram.org/bots/features#deep-linking) | Confirmed. Drives pairing (§5.2) |
| M10 | A forwarded copy of a message keeps its inline keyboard only if the keyboard has nothing but URL or login buttons, so callback buttons are stripped | [Bot API changelog, 4.3 (2019-05-31)](https://core.telegram.org/bots/api-changelog) | Confirmed in the changelog only, not in the current reference. Not relied on: D5 checks `from.id` regardless |
| M11 | `keyboardButtonCallback.requires_password` (the user re-enters their 2FA password before the tap reaches the bot) is not exposed to Bot API bots | MTProto constructor docs; the Bot API reference has no such field | Confirmed absent. So a 2FA-on-tap step-up is not available (RR-3 in SECURITY.md) |
| M12 | Bot chats are cloud chats: Telegram's servers see message content | [telegram.org/faq](https://telegram.org/faq) ("Server-client encryption is used in Cloud Chats (private and group chats)") | Confirmed. Telegram is in the trust base (SECURITY.md RR-6, OD1) |
| M13 | Rate limits: about 1 message per second per chat; about 30 per second overall | [Bots FAQ](https://core.telegram.org/bots/faq) | Confirmed. The per-chat send queue in §5.8 respects these |
| M14 | Telegram accounts support 2-Step Verification (a cloud password in addition to the SMS code), a local passcode lock, and a list of active sessions that can be terminated. "whoever has the number, has the account" without 2SV. | telegram.org/faq | Confirmed. The approver setup in §5.2 requires the first two. A bot cannot check either (D13) |
| M15 | `User.id` has at most 52 significant bits (safe in int64). In a private chat, the chat ID equals the user's ID. | Bot API: User; [MTProto bot IDs](https://core.telegram.org/api/bots/ids) | `User.id`: confirmed. The private-chat equality is only indirect ("MTProto user IDs are equal to bot API user dialog IDs"). D4 therefore checks `chat.id == from.id` explicitly and doesn't assume it |
| M16 | Do Telegram clients auto-link `/commands`, URLs and `@mentions` inside `<pre>` and `<code>`? | **Not yet verified.** Measure in TG5 with a real bot and the official Android and iOS clients | D7 makes the answer non-critical: no text command escalates |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | Telegram's servers see every approval message (M12). Is it acceptable to send them the agent's `reason` and `label`, client and profile names, the scope summary, and parsed step operations (Kubernetes object names, HTTP paths, SSH command lines)? | *Open.* Recommendation: **yes**, because an approver can't decide without them. Never send secrets (§5.7, INV-11). Set `protect_content` on every message. Truncate free text. The alternative, a message that says only "a request is waiting", would need a second, non-Telegram surface to show the details, which reopens the UX problem OD2 settled. |
| OD2 | Dual control (`approvals_required ≥ 2`, two distinct approvers) in v1? | *Open.* Recommendation: **not in v1.** The project has one maintainer and one approver. The data model already records N approvals (docs/02 §5.16), so adding it later means a config-validation change plus tests. Until then, validation rejects `approvals_required > 1`. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **The bot runs entirely on G.** The bot token is a G secret (`/etc/nyyrikki/secrets/…`, `0600`) and never leaves G. | INV-04. Whoever holds the token can read and answer the bot's updates. |
| D2 | **Long polling (`getUpdates`), no webhook.** At startup G calls `getWebhookInfo`. If a webhook URL is set, G **refuses to start** and alerts. It does not delete the webhook. | INV-19: no inbound endpoint accepts updates. A webhook that G didn't set means someone else holds the token. M5. |
| D3 | **The `getUpdates` offset is committed in the same DB transaction as the update's effects.** Processing is idempotent regardless (single-use refs). | M5: a crash between processing and confirming redelivers the update. |
| D4 | **Approvers are configured by numeric Telegram user ID and bound by pairing** (§5.2). Only private chats count: `chat.type == "private"` and `chat.id == from.id == approver.telegram_user_id`. Updates from anyone else are ignored, audited and rate-limited. | Pairing catches a mistyped ID and proves the bot can reach the approver (M9). M15. |
| D5 | **Callback data is an opaque, single-use reference.** Format: `1:<ref>`, where `<ref>` is 16 random bytes in base64url (22 chars). G stores `SHA-256(ref)` with the approver, chat, message ID, action, object and expiry. The **action lives server-side**; it is never read from `data`. A tap is accepted only if every check in §5.4 passes. | M2: `data` is client-controlled. A modified client can only present refs it was sent, and only from the approver's own account. INV-02, INV-03. |
| D6 | **One prompt per approver per decision.** Each approver gets their own message with their own refs. Deciding retires every approver's copy. | A ref can't cross approvers. Everyone sees the outcome. |
| D7 | **No text command escalates.** `/grants`, `/revoke_all` and `/help` only show information or remove access. Anything that adds access (approve, step off, allowance, unmute) happens only through a button ref. | A command embedded in untrusted text could be auto-linked and tapped (M16). |
| D8 | **Messages are HTML parse mode. Untrusted text is escaped and neutralized (§5.7), and always sits inside a labelled `<blockquote>`, after all the trusted lines.** Every send sets `protect_content: true` and `link_preview_options.is_disabled: true`. | INV-15, M6, M7. The agent's text can't pose as Nyyrikki's own lines. |
| D9 | **Prompts are retired by editing** (the outcome text, with the keyboard removed), never by deleting. | M8: editing has no time limit, deletion does. A record stays in the chat. |
| D10 | **No configurable Bot API base URL.** The client takes its base URL as a constructor argument. Production passes `https://api.telegram.org`, and tests pass a local fake. TLS is verified against the system trust store. | A config knob pointing the bot at another server would let that server forge every approval. |
| D11 | **Timeouts deny.** A pending grant that isn't decided within the request window becomes `request_expired`. A step that isn't decided within 5 min becomes `step_expired`. An unreachable Telegram means no decisions, so everything expires (fail closed). | CLAUDE.md "fail closed". |
| D12 | **G down for more than 24 h loses queued updates** (M5). This is accepted: every decision window is shorter than 24 h, so a lost tap would have expired anyway. | No hidden allow can result from the loss. |
| D13 | **Approver account hardening is a setup requirement, not a runtime check.** The pairing message tells the approver to enable 2-Step Verification and a passcode, and the setup doc repeats it (docs/09). | M14: the bot can't observe either. RR-3 records the residual risk. |
| D14 | **A deny can mute the client.** The request prompt has a "Deny + mute 1 h" button. While muted, a client's new requests are denied immediately, without a prompt. Unmuting is a button (D7). | A looping agent shouldn't be able to flood the approver's phone. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Passkey (WebAuthn) approval on G, always or for high-risk profiles | The owner chose a Telegram tap for every decision (docs/01 OD2). Recorded in CLAUDE.md "Rejected". |
| A webhook instead of long polling | Needs an inbound public HTTPS endpoint on G, which is a new attack surface and a second way to inject updates. Long polling needs only outbound HTTPS. |
| A self-hosted Telegram Bot API server | More infrastructure on G for no security gain. The updates still originate at Telegram. |
| The action encoded in `callback_data` (e.g. `approve:gr_…`), maybe signed with an HMAC | `data` is client-controlled (M2). Server-side state is simpler, and it can be revoked. An HMAC would add a key to manage and no property the server-side row lacks. |
| Approvals from a group chat | A group adds members and admins to the trust base, and forwards and replies blur who decided. |
| 2FA-on-tap (`requires_password` buttons) | Not available to Bot API bots (M11). |
| Telegram Login Widget or a Mini App for richer UI | More surface. v1's messages carry everything an approver needs. Revisit with R7. |

## 5. Design

### 5.1 Bot and transport

Setup, once: the owner creates the bot with @BotFather, stores the token
at `/etc/nyyrikki/secrets/telegram-bot-token`, and sets `bot_username` in
config.

At startup:

1. `getMe`: the token works and its username equals `bot_username`.
   Otherwise refuse to start.
2. `getWebhookInfo`: if a URL is set, refuse to start (D2).
3. Load `next_offset` from `telegram_state`.

The poll loop runs as a single goroutine:

```
for {
  updates = getUpdates(offset=next_offset, timeout=50,
                       allowed_updates=["message","callback_query"])   // HTTP client timeout 65 s
  for u in updates (in order):
     tx: handle(u) ; telegram_state.next_offset = u.update_id + 1 ; commit   (D3)
}
```

- **Network errors and 5xx**: back off exponentially from 1 s to 30 s,
  with jitter.
- **`429`**: sleep for `parameters.retry_after`.
- **`401`** (token revoked): stop polling, set `approvals_unavailable`,
  alert. Escalations then expire (D11).

Outgoing calls (`sendMessage`, `editMessageText`,
`editMessageReplyMarkup`, `answerCallbackQuery`) go through one
per-chat queue with at most 1 send per second per chat (M13).
`answerCallbackQuery` bypasses the queue, because it must be fast (M4).

### 5.2 Approvers and pairing

```yaml
approvers:
  - id: ap_juho
    display_name: "Juho"
    telegram_user_id: 123456789
    enabled: true
```

To pair:

1. On G: `nyyrikki approver pair ap_juho`. This prints
   `https://t.me/<bot_username>?start=<code>`. `<code>` is 32 characters
   of `[A-Za-z0-9_-]` (M9), single-use, valid for 15 min, and stored
   hashed.
2. The approver opens the link on their phone and taps Start. Telegram
   sends the message `/start <code>`.
3. G accepts it only if all of these hold:
   - `chat.type == "private"`;
   - `from.id == chat.id == telegram_user_id` of the approver the code was
     issued for;
   - the code is unexpired and unused.

   G then records `chat_id` and `paired_at` and replies:
   "Paired as Juho. Approval requests for Nyyrikki will arrive here.
   Before relying on this: turn on Two-Step Verification and a passcode
   in Telegram → Settings → Privacy and Security."
4. Any mismatch burns the code and is audited as
   `telegram.pair_rejected`. The admin runs `pair` again.

An unpaired or disabled approver receives nothing, and nothing they send
is acted on. `nyyrikki approver unpair ap_juho` clears the binding.

### 5.3 Messages

Every message follows the same layout. Lines from G and config come
first, and they are trusted. The agent's text comes last, in a labelled
quote (D8). Times are shown in UTC, with relative times in parentheses.

**Grant request**

```
🔐 Elevation request · gr_01JB…
Client: agent-vm-a
Profile: k8s-node-maint
  Drain, upgrade and uncordon prod nodes one at a time.
TTL: 60 min (profile max 2 h, total 4 h) · Step mode: off
Scope:
  k8s prod: get,list,watch ** → allow
  k8s prod: patch nodes → allow
  k8s prod: create pods/eviction -n * → confirm
  k8s prod: * secrets → deny
  ssh node-1, node-2 as root: exec apt-get -y upgrade* → confirm …
Decide by 13:47 UTC (in 15 min)
Agent says (untrusted):
┃ thread: prod containerd upgrade
┃ Upgrade containerd on prod nodes one by one: drain, apt upgrade via SSH, uncordon
[ Approve ] [ Approve + step mode ]
[ Deny ]    [ Deny + mute 1 h ]
```

The scope lines come from `policy.Describe` (docs/02 §5.8.5). If the
message would exceed 4096 characters (M6), the scope list is cut with
"… N more rules" and the agent's text is truncated first.

**After the decision** (D9), every approver's copy is edited to the
outcome and the keyboard is removed:

```
✅ Approved by Juho at 13:33 UTC · active until 14:33 UTC
[ Revoke ] [ Step mode: turn on ]
```

**When the grant ends**, the copy is edited again: `⏹ Ended 14:20 UTC:
released by agent`, with no keyboard.

**Extension request**

```
⏱ Extend gr_01JB… (k8s-node-maint)?
+30 min → new expiry 15:03 UTC (cap: 17:33 UTC)
Agent says (untrusted): ┃ …
[ Approve ] [ Deny ]
```

**Held step**: see §5.5.

### 5.4 Callback verification (normative)

For each `callback_query` update `cq`, G runs these checks in order. The
first failure stops processing: G answers the query with a short neutral
text ("Not valid", "Already decided", "Expired") and audits
`telegram.callback_rejected` with the reason.

```
1. cq.data matches ^1:[A-Za-z0-9_-]{22}$                       else malformed
2. row = decision_refs[sha256(ref)]                             else unknown_ref
3. approver = approvers[row.approver_id]; enabled and paired   else approver_inactive
4. cq.from.id == approver.telegram_user_id                     else wrong_user
5. cq.message present (not an inline-mode callback),
   cq.message.chat.id == approver.chat_id == cq.from.id,
   cq.message.message_id == row.message_id                     else wrong_message   (M3)
6. now < row.expires_at                                        else expired
7. in one transaction:
     UPDATE decision_refs SET consumed_at=now
       WHERE prompt_id=row.prompt_id AND consumed_at IS NULL    -- the ref and its siblings
     require the clicked ref was among the rows updated        else already_used     (INV-03)
     apply the action as a compare-and-set on the object (docs/02 D3)
       object no longer in the expected state                  -> already_decided
     audit per docs/02 D4 (escalations: append before commit)
     telegram_state.next_offset = update_id + 1                 (D3)
   commit
8. answerCallbackQuery(cq.id, outcome text)
9. retire every approver's prompt for this object (edit, D9)
```

Consuming the siblings in step 7 means that one tap retires every button
on that prompt. A second tap on the same message, or a replay of a
consumed ref, fails at step 7.

### 5.5 Step prompts, allowances and grant controls

A held operation (docs/02 §5.4) produces:

```
⏸ Hold · k8s-node-maint · gr_01JB…
create pods/eviction -n shop web-0
body: Eviction {deleteOptions: {gracePeriodSeconds: 30}}   (redacted digest)
Decide by 13:52 UTC (in 5 min)
[ Approve ] [ Deny ]
[ Approve + allow "create pods/eviction -n shop *" 15 min ]
[ Approve + allow "create pods/eviction -n *" 15 min ]
```

The allowance variants are computed by G from the parsed operation. They
are never taken from A.

| Kind | Narrow variant | Wide variant |
|---|---|---|
| k8s | same verb and resource, same namespace, any name | same verb and resource, any namespace |
| http | same method, path with its last segment replaced by `*` | same method, path with its last two segments replaced by `*`, if the path has ≥ 3 segments |
| ssh | none: commands are matched exactly or not at all (guardrail, RR-4) | none |

The allowance lifetime is fixed at 15 min in v1, capped at the grant's
expiry. The button's ref row stores the exact matcher, and the message
shows it.

**Grant controls**, on the active-grant message:

- `[Revoke]` revokes the grant. It de-escalates.
- `[Step mode: turn on]` / `[Step mode: turn off]`. Turning it off is an
  escalation: it is audited as a decision, and appears only if the
  profile says `optional`.

**Unmute**: the mute notice ("agent-vm-a muted until 14:33 UTC") carries
an `[Unmute]` button.

### 5.6 Text commands (private chat, paired approvers only)

| Command | Effect |
|---|---|
| `/grants` | lists pending and active grants with their expiry, each with a `[Revoke]` or `[Deny]` button, plus `[Revoke all]` |
| `/revoke_all` | replies with a `[Revoke all N active grants]` button. The button revokes; the command alone does not |
| `/help` | the command list |
| anything else | `/help` text |

Messages from anyone who isn't a paired approver are ignored. They are
audited as `telegram.update_ignored`, at most one event per user per
minute.

### 5.7 Rendering untrusted text (INV-15)

These fields are untrusted: `reason`, `label`, and everything that comes
from a parsed operation (object names, paths, commands, body digests).
Before insertion, each one goes through `render.Untrusted(s, max)`:

1. **Neutralize these code points.** Each is replaced with a visible
   marker `⟦U+XXXX⟧`:
   - C0 and C1 controls, except `\n`;
   - bidi controls U+061C, U+200E, U+200F, U+202A–U+202E and
     U+2066–U+2069;
   - zero-width and invisible characters U+200B–U+200D, U+2060 and
     U+FEFF.
2. **Truncate** to `max` runes, appending ` … (truncated)`. The limits
   are 120 for the label, 600 for the reason, and 300 for operation
   fields.
3. **HTML-escape** `&`, `<`, `>` and `"` as `&amp; &lt; &gt; &quot;`
   (M7). No other entities are used.

Free text goes inside `<blockquote>`, after the line `Agent says
(untrusted):`. Commands and object names go inside `<code>`. An SSH
command shows non-printing bytes hex-escaped (`\x1b`). Trusted values
from config (profile description, display names) are escaped too, but
not neutralized.

Nothing a secret could be in ever reaches a message:

- tokens and credentials;
- `Authorization` headers and cookies;
- unredacted bodies;
- the decision refs themselves, which travel only as callback data.

The redaction rules live in docs/03 §5.9 (INV-11).

### 5.8 Failure handling

| Failure | Result |
|---|---|
| `sendMessage` fails | The prompt is retried with backoff until its decision window ends. The grant stays pending, and A sees `delivered: 0` (§5.9). |
| Telegram unreachable for minutes | No updates, so no decisions. Requests and steps expire (D11). Alert after 2 min of failed polls. |
| `401` from the Bot API | `approvals_unavailable`. Polling stops, the alert fires, and everything expires. |
| A callback for a prompt whose `message_id` was never recorded (G crashed after sending) | Rejected as `wrong_message`. G sends a fresh prompt and retires the stale one when it can. |
| Redelivered update after a crash | Effects plus the offset are atomic (D3), and refs are single-use. Nothing happens twice. |
| An update older than the object's window | Fails the expiry check (§5.4 step 6). |
| A flood from a non-approver | Ignored. Audit is rate-limited (§5.6). The poll loop is unaffected. |

Every outcome above is a deny, an expiry, or no change. None is an allow.

### 5.9 What A sees

`GET /v1/grants/{id}` (docs/02 §5.13) includes:

```json
"approval": {"channel":"telegram","approvers":1,"delivered":1,"last_error":null}
```

`nyyrikki-mcp` turns this into the tool text (docs/05):

- "Approval requested on Telegram (1 approver notified). Waiting…"
- or, if `delivered` is still 0 after 30 s: "Telegram delivery is
  failing; the approver has not been notified."

A never learns refs, chat IDs or message content beyond these counts.

### 5.10 Data model (`0002_telegram.sql`)

```sql
CREATE TABLE approver_bindings (
  approver_id TEXT PRIMARY KEY, chat_id INTEGER NOT NULL,
  paired_at INTEGER NOT NULL);

CREATE TABLE pairing_codes (
  id TEXT PRIMARY KEY, approver_id TEXT NOT NULL, code_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL);

CREATE TABLE prompts (
  id TEXT PRIMARY KEY,                       -- pm_<ULID>
  approver_id TEXT NOT NULL, chat_id INTEGER NOT NULL,
  message_id INTEGER,                        -- NULL until sendMessage returns
  purpose TEXT NOT NULL CHECK (purpose IN ('grant','extension','step','grant_controls','list','unmute','revoke_all')),
  object_id TEXT,                            -- gr_/ex_/st_/cl_
  created_at INTEGER NOT NULL, retired_at INTEGER);
CREATE INDEX idx_prompts_object ON prompts(object_id);

CREATE TABLE decision_refs (
  id TEXT PRIMARY KEY,                       -- dr_<ULID>
  prompt_id TEXT NOT NULL REFERENCES prompts(id),
  ref_hash TEXT NOT NULL UNIQUE,             -- sha256(ref), hex
  approver_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('approve','approve_step','deny','deny_mute','approve_ext','deny_ext',
           'approve_step_op','deny_step_op','allow_narrow','allow_wide','revoke','step_on','step_off','unmute','revoke_all')),
  args TEXT,                                 -- JSON, e.g. the allowance matcher
  expires_at INTEGER NOT NULL, consumed_at INTEGER);

CREATE TABLE client_mutes (
  client_id TEXT PRIMARY KEY, until INTEGER NOT NULL,
  created_by TEXT NOT NULL, created_at INTEGER NOT NULL);

CREATE TABLE telegram_state (k TEXT PRIMARY KEY, v TEXT NOT NULL);   -- next_offset
```

Sending a prompt goes in this order:

1. Insert the prompt and its refs, with `message_id` NULL.
2. Call `sendMessage`.
3. Set `message_id` from the response.

A ref expires with its object's decision window. Refs on
`grant_controls` prompts expire with the grant.

### 5.11 Configuration

```yaml
telegram:
  bot_token_ref: "secret://telegram-bot-token"
  bot_username: "nyyrikki_example_bot"
approvers: [ ... ]   # §5.2
```

| Key | Consumed by (production call site) |
|---|---|
| `telegram.bot_token_ref` | `telegram.NewClient` (in `server.Run`) |
| `telegram.bot_username` | `telegram.Startup` (`getMe` check) and `approver.pair` (link) |
| `approvers[]` | `telegram.Authorizer` (§5.4 steps 3–5) and `config` validation (docs/02 §5.15.6) |

Validation:

- Approver IDs are unique, and so are `telegram_user_id`s.
- `approvals_required` is ≤ 1 while OD2 stands.
- At least one approver is enabled, or G refuses to start: with nobody
  to ask, every request would just expire.

## 6. Security considerations

- **New trust boundary: Telegram.** Updates come from `api.telegram.org`
  over TLS verified with the system trust store. They are pulled by G
  (D2, INV-19) and treated as untrusted input until §5.4 passes. Telegram
  itself is trusted to authenticate the approver's account: it sets
  `from.id`. It could forge a tap, and it sees every message in clear
  text (M12). These risks are accepted in SECURITY.md RR-3 and RR-6 and
  were chosen by the owner (docs/01 OD2).
- **Who controls each input.**
  - Telegram users control message text and callback data. Callback data
    is fully attacker-controllable (M2), so it is a lookup key and
    nothing more (D5).
  - The agent controls `reason`, `label` and the operations, all rendered
    per §5.7.
  - Config controls approver IDs.
- **Each dependency failure ends in deny** (§5.8, D11). This is tested
  per row.
- **What reaches Telegram**: §5.3 and §5.7, subject to OD1. Never
  tokens, credentials, cookies, `Authorization` headers, unredacted
  bodies, or the refs in readable form.
- **What reaches the audit log**: every decision, rejection and pairing
  attempt, with the approver ID, the Telegram `update_id`, the action
  and the object. Never the ref or the pairing code.
- **What reaches the model**: nothing (R4).
- **New ways to reach an upstream**: none. A decision changes state
  only. Operations still pass the gate (docs/02 D5).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. A grant, extension or step is decided only through a §5.4-verified tap. No other code path decides one (INV-02) | integration tests against the fake Bot API; an AST check that `grants.Manager.Approve`, `steps.Broker.Approve` and `ExtensionApprove` are called only from `telegram.Decide` |
| G2. Each §5.4 rejection fires for its own case: malformed, unknown ref, wrong user, approver disabled or unpaired, wrong chat, non-private chat, wrong message ID, expired, replayed, sibling already consumed, object already decided (INV-03) | one test per reason, each asserting a deny, no state change, and a `telegram.callback_rejected` audit |
| G3. Two taps on one prompt, from two goroutines, yield exactly one decision | concurrency test with the race detector |
| G4. A crash after the effects but before the offset commit, or a redelivered update, has no second effect (D3) | fault-injection test that kills the handler around the commit |
| G5. A set webhook stops G from starting (D2). A `getMe` username mismatch stops G from starting | startup tests |
| G6. Pairing accepts only the configured user, in a private chat, with a valid code. Every mismatch burns the code (§5.2) | pairing tests |
| G7. Untrusted text is escaped and neutralized. It can't create tags, break out of the blockquote, or hide characters. Messages never exceed 4096 characters. Every send sets `protect_content` and disables link previews (INV-15, D8) | golden-file tests of rendered HTML from adversarial inputs; the fake Bot API asserts the send parameters |
| G8. No message, and no audit event, contains a token, credential, cookie, `Authorization` value, ref or pairing code (INV-11) | a test that scans every fake-Bot-API payload and audit line during the e2e suite for planted canary secrets |
| G9. Telegram unreachable, `429`, `5xx` or `401`: decisions don't happen, requests and steps expire, and nothing is allowed (D11) | one fault-injection test per failure |
| G10. No text command escalates (D7) | a test that enumerates the command table, plus a test that `/revoke_all` alone revokes nothing |
| G11. Deny + mute denies new requests for 1 h without prompting. Unmute requires its button | integration test |
| G12. Allowance buttons create exactly the matcher shown, and nothing broader (INV-17) | broker plus Telegram integration test |
| G13. M16 is measured with a real bot on the official Android and iOS clients, and the result is recorded in §2 | manual, by the owner, before TG5 closes |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **TG1** | `internal/telegram` client, poll loop, per-chat send queue, startup checks; the fake Bot API server in `test/fakebotapi` | G5, G9 |
| **TG2** | Pairing: admin command, `/start` handling, `approver_bindings` | G6 |
| **TG3** | Prompts and the §5.4 verification for grants, extensions and steps; retiring prompts by edit | G1, G2, G3, G4 |
| **TG4** | Grant controls, allowances, mute, `/grants`, `/revoke_all` | G10, G11, G12 |
| **TG5** | `internal/render` hardening; the canary-secret scan; the M16 measurement | G7, G8, G13 |

Ordering notes:

- TG1 needs docs/02 GC2, because offsets live in the store.
- TG3 needs GC4 and GC7, because it decides grants and steps.
- TG5's renderer is pure and can be written first. Its tests gate TG3's
  messages.

## 9. Risks and open questions

- **RR-3 (SECURITY.md)**: an approver's Telegram account or unlocked
  phone is enough to approve. Mitigations: 2-Step Verification and a
  passcode (D13), short windows, every decision visible to the approver
  in the chat, and revoke a tap away. Telegram offers bots no step-up
  (M11).
- **RR-6**: Telegram sees approval content and is technically able to
  forge a tap. The owner accepted it (docs/01 OD2). OD1 decides how much
  detail it sees.
- **M16 is open.** Auto-linking inside code blocks doesn't change
  security (D7), but it may affect readability.
- **Bot API drift.** The API changes several times a year (10.3 at the
  time of writing). Fields used here: `callback_query`, `message`,
  `protect_content` and `link_preview_options`. A nightly e2e run against
  the fake server can't catch upstream drift. A monthly manual smoke test
  with the real bot can, and docs/09 schedules it.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
