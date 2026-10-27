# R2 — Gateway core: MCP and CLI, identity, targets, one decision point (docs/02)

**Status**: drafted 2026-10-26, owner decisions OD1–OD3 taken the same
day. Awaiting the owner's approval of the doc as a whole; merging the PR
that adds it is that approval. Status lives in
[`ROADMAP.md`](../ROADMAP.md).

Chunks **GW1–GW6** (`GW` = gateway; unused).

**Relationship to earlier work**: builds on [docs/01](01-foundations.md)
(D4, D5, D8, D9, D24, D25), which fixed the frame: one MCP endpoint, the
token checks, the agent key and the elevation handle. This doc designs
the operations, the registries, the elevation model and the decision
point inside that frame. It adds one endpoint next to `/mcp` for
interactive streams (D10 here), as docs/01 D4 foresaw, and revises
docs/01 D9 and D10 by dated notes for it.

---

## 1. Purpose

An agent needs to do three things: find out which targets it may ask
for, get one privileged request run, and get a short window in which a
burst of requests runs without a tap each. Each of those has to reach
one place that decides correctly, through MCP and the CLI alike, and
every answer that isn't a clear yes has to be a no.

When this ships (with R3–R5), an agent lists its targets, runs a
request that the owner approves on Telegram, and asks for an elevation,
through either client, and the same decision point answers every time.

### Non-goals

- How a request is parsed, shown and forwarded: R4 ([docs/04](04-kubectl-passthrough.md)).
- What the approver sees and how a tap is checked: R5 ([docs/05](05-telegram-escalation.md)).
- The audit record's fields: R3 ([docs/03](03-audit-log.md)).
- More than one human (docs/01 OD1). The data model carries the human
  everywhere, but nothing is designed or tested for several.
- Any way for an agent to approve, deny or end anything.

## 2. Measured and verified before writing

All checked on 2026-10-26.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | go-sdk v1.8.0: `StreamableHTTPOptions.Stateless` answers GET and DELETE with 405 and creates a temporary session per POST; a tool handler gets `req.Session` and can send `NotifyProgress` with the request's `progressToken`; the client side has `ProgressNotificationHandler` | read `mcp/streamable.go`, `mcp/client.go`, `mcp/streamable_test.go` at v1.8.0 | Confirmed. D3, D7 |
| M2 | A tool handler's context is cancelled when the client drops the HTTP request in stateless mode | read `serveStateless` at v1.8.0: the session is bound to the request's context | Confirmed from source; GW3 has a test that asserts the pending approval is withdrawn on disconnect |
| M3 | Codex's tool timeout defaults differ between its docs (60 s) and its source (300 s); Claude Code's default tool timeout is effectively unbounded | `docs/measured.md` (MCP clients M4, M5), re-read the same sources | Confirmed. D7's default wait (3 min) is longer than Codex's documented 60 s and shorter than the 300 s in its source, so the setup docs set Codex's `tool_timeout_sec` explicitly; that, not the default, is what makes it work |
| M4 | `github.com/go-jose/go-jose/v4` v4.1.6 (Apache-2.0) verifies JWS with an explicit algorithm allowlist, parses JWKs and computes RFC 7638 thumbprints | pkg.go.dev, module source | Confirmed. D2 |

## 3. Owner decisions

Taken by the owner on 2026-10-26, in the conversation that started the
build.

| # | Question | Decision |
|---|---|---|
| OD1 | How are design and code delivered for the first version? | **Docs and code together, as a stack of PRs the owner merges.** Merging a doc's PR approves it; code PRs sit on top of the doc PRs they implement. |
| OD2 | Can the approver end an elevation early from the chat? | **Yes, an "End now" button** on the elevation's message (R5, docs/05 D7). Ending cuts the elevation's open streams at once. |
| OD3 | Interactive exec and attach in v1? | **Yes.** They need an interactive stream that a tool call can't carry, so this doc adds the stream endpoint of D10. Port-forward was not asked for and is not offered (docs/04 D5). |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Three operations**, each one MCP tool and one CLI command, with identical arguments: `list_targets` (`nyyrikki targets`), `run` (`nyyrikki run`), `elevate` (`nyyrikki elevate`). No other tool, resource, prompt or completion is registered; the server advertises only `tools`. | `CLAUDE.md`: three operations; MCP features beyond tools are off (docs/01 D4). |
| D2 | **Authentication middleware** in `internal/authn` implements docs/01 D9 exactly, with `go-jose/v4` (M4) for JWS and JWK. JWKS is fetched from the issuer's discovery document, cached, and refetched at most once a minute when an unknown `kid` arrives. Introspection uses `client_secret_basic` with a client secret read from a file on each use. The middleware puts a `Principal` (human, agent key, client ID, sign-in time, whether introspected) in the request context; nothing downstream reads a header. | docs/01 D9; secrets as files (docs/01 D15), re-read so rotation needs no restart. |
| D3 | **Introspection happens inside the decision path**, not in the middleware: `run` and `elevate` call `authn.Introspect` before the decision point does anything else, and `list_targets` doesn't. A failure is a deny with reason `introspection_failed` or `session_inactive`. | docs/01 OD13: listing stays available without a Keycloak round trip. |
| D4 | **Human registry** (config `humans`): `id` (slug), `subject` (the token `sub`), `kubernetes.user`, `kubernetes.groups`, `telegram_user_id`. A token whose `sub` matches no entry is rejected by the middleware (401). Exactly one human is allowed in v1; config validation rejects zero or more than one. | docs/01 D8, OD1. Refusing more than one keeps the untested case out. |
| D5 | **Target registry** (config `targets`): `name` (slug), `description`, `humans` (ids allowed to ask; required, non-empty), optional `clients` (`azp` values allowed; empty means any), and a `kubernetes` block (docs/04 D9). A target is *visible* to a principal when its human is listed and, if `clients` is set, its client ID is. Invisible targets are absent from `list_targets`, and asking for one is a deny with reason `target_not_allowed`, the same answer as for a target that doesn't exist. | `ROADMAP.md` R2: which agents and humans may ask for each target. The same answer for "absent" and "not yours" leaks nothing. |
| D6 | **One decision point**: `decision.Point.Decide(ctx, Request) (Grant, error)` in `internal/decision` is the only code that produces a `Grant`, and the forwarder (docs/04) takes a `Grant`, never a bare request. `Grant` has unexported fields, so no other package can make one. The steps are in §5.3; every branch that isn't an explicit allow returns an error, and an error is deny. | `CODE-REVIEW.md`: one decision point. The type system makes "forward without deciding" a compile error. |
| D7 | **Waiting.** A call that needs an approval blocks until exactly one of approve, deny, expire or withdraw settles it (compare-and-set in SQLite, R5). The wait is `approval_timeout` (config, default `3m`, at most `10m`). While it waits, the server sends an MCP progress notification every 15 s when the call carried a `progressToken`. If the client drops the call (context cancelled), the pending approval is withdrawn: its Telegram message is edited to say so, and a later tap does nothing. The result of an approval goes only to the call that waited for it (docs/01 D24). | `CODE-REVIEW.md`: one event, one authoritative signal. Withdrawal makes sure no approval exists without a waiter. |
| D8 | **Elevations.** `elevate` takes `targets` (1–10 visible targets), `duration` (Go syntax; default `15m`; anything above `30m` becomes `30m`, anything below `1m` is rejected) and `reason`. After approval it returns the elevation ID, the handle (docs/01 D24), the targets and `expires_at`. The window starts at approval, not at the request. An elevation is stored with the SHA-256 of its handle, agent key, human, targets, `expires_at` and state (`pending`, `live`, `denied`, `expired`, `ended`, `withdrawn`). Expiry is checked against the server clock on every request; a timer also moves it to `expired`, edits the Telegram message and cuts its open runs (docs/04 D8). | `CLAUDE.md`: at most 30 minutes, never widened; `CODE-REVIEW.md`: elevations expire for real. Asking for more gives 30 (`ROADMAP.md` M3). |
| D9 | **Handles.** `nyel_` followed by 43 base64url characters (32 random bytes from `crypto/rand`). Looked up by the SHA-256 of the whole string; the stored hash is compared in constant time. The outcomes are docs/01 D24's: no handle → one-off; unknown hash, or a hash stored under another agent key → deny `handle_unknown`, audited, never turned into a one-off; this agent's handle but expired, ended, another human, or a target it doesn't name → one-off, audited with the reason. | docs/01 D24. The prefix lets secret scanners (gitleaks) match it. |
| D10 | **The stream endpoint** (OD3): `GET /stream` on `:8443`, a WebSocket (`github.com/coder/websocket`, `docs/measured.md` M6), behind the same middleware as `/mcp`. It does nothing on its own: it only attaches to an interactive run that the decision point has already allowed. `run` with `interactive: true` returns, instead of output, a **stream ticket**: `nyst_` plus 43 base64url characters, stored hashed, valid for 30 s, usable once, only by the same agent key, returned only to the call that asked (docs/01 D24). The client opens `/stream` with the ticket in the `Nyyrikki-Stream-Ticket` header. | A tool call can't carry a terminal. Attaching through a ticket means `/stream` adds no decision of its own (`CODE-REVIEW.md`: one decision point). |
| D11 | **DPoP on `/stream`.** The proof's `htu` must equal the configured canonical stream URL (canonical base + `/stream`) and `htm` must be `GET`. Every other rule of docs/01 D9 applies unchanged, and `/stream` also introspects. *Revises docs/01 D9 (2026-10-26)*: the proof is checked against the canonical URL of the endpoint it was sent to, `/mcp` or `/stream`, never one built from the request. | DPoP binds method and URL; a proof for `/mcp` must not open a stream, nor the reverse. |
| D12 | **The CLI** (`cmd/nyyrikki`) is an MCP client of `/mcp` (go-sdk client, Streamable HTTP) and nothing else, plus a WebSocket client of `/stream` for interactive runs. It writes the target's output to stdout and its own messages to stderr, prefixed `nyyrikki:`. Exit codes in §5.5. It blocks while an approval is pending, printing a waiting line on stderr. | `ROADMAP.md` R2; docs/01 D4. |
| D13 | **Arguments are strict.** Tool inputs are decoded with unknown fields rejected and validated before anything else: target names are slugs, `args` is 1–256 strings of at most 8 KiB each, `stdin` at most 1 MiB, `reason` 1–1000 characters, `timeout` a Go duration. A violation is a tool error with code `invalid_request`, audited, and no approval is asked for. | The agent is untrusted; a request nobody could approve shouldn't reach the approver. |
| D14 | **Error codes** are defined once in `internal/codes` and returned in the tool result's structured content (`{"error": {"code": …, "message": …}}`, with `isError: true`): `invalid_request`, `unauthenticated`, `target_not_allowed`, `handle_unknown`, `denied`, `expired`, `withdrawn`, `introspection_failed`, `session_inactive`, `unavailable`, `internal`. The CLI maps them to exit codes. Messages never contain a credential, a handle or a ticket. | `CODE-REVIEW.md`: shared constants have one definition; type your failure phases. |
| D15 | **State** lives in SQLite (docs/01 D11) in `internal/store`: tables `approvals`, `elevations`, `meta`, `audit` (R3) and the Telegram package's own tables (R5). Stream tickets are kept in memory only: they live 30 s, and a restart ends the run they would attach to anyway. Every state change is a compare-and-set `UPDATE … WHERE id=? AND state=?` and acts only if exactly one row changed. On startup, every `pending` approval and elevation is moved to `expired`, since its waiter is gone, and every `live` elevation stays live only until its stored `expires_at`. | docs/01 D11, `docs/measured.md` (grant mechanics M1). A restart can't leave an approval without a waiter. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| A `get_result` tool to pick up an approval after a timeout | docs/01 D24: authority goes only to the call that waited. Re-asking is cheap; a pick-up path is a second way to obtain authority. |
| An `end_elevation` tool for the agent | `CLAUDE.md`: no MCP tool or CLI command ends anything. Ending belongs to the approver (OD2). |
| Interactive input carried as repeated tool calls (`send_stdin`, `read_output`) | It turns one approved session into many calls, each of which would need to be tied back to the approval; a ticketed stream is one thing to check. |
| Elevations keyed by MCP session | docs/01 D5. |
| Silently cutting an `elevate` duration above 30 m to an error | `ROADMAP.md` M3 says asking for more gives 30. |

## 5. Design

### 5.1 Packages

| Package | Holds |
|---|---|
| `internal/codes` | error codes, decision values, audit kinds (one definition) |
| `internal/config` | strict YAML decoding and validation (docs/01 D12) |
| `internal/authn` | token checks, DPoP, JWKS cache, introspection |
| `internal/store` | SQLite, migrations, compare-and-set transitions |
| `internal/audit` | the audit writer (docs/03) |
| `internal/decision` | the decision point, elevations, pending approvals |
| `internal/approval` | the interface the decision point uses to ask a human; implemented by `internal/telegram` (docs/05) |
| `internal/kubectl` | parsing, rendering and running requests (docs/04) |
| `internal/mcpserver` | the tools, wired to the decision point and the runner |
| `internal/stream` | `/stream` |
| `internal/server` | listeners, TLS, lifecycle, wiring |
| `internal/client` | the CLI's login, token store, DPoP and MCP client |

### 5.2 Tools

All three take and return JSON objects; the schemas are generated from
Go structs and published through `tools/list`.

**`list_targets`** `{}` → `{"targets": [{"name", "description", "type": "kubernetes"}]}`.

**`run`** `{"target", "args": [...], "stdin"?, "reason", "elevation"?, "timeout"?, "interactive"?}`.
`args` is the kubectl command line without the leading `kubectl`
(docs/04). Result: `{"run_id", "covered_by": "one-off"|"elevation",
"exit_code", "stdout", "stderr", "stdout_truncated", "stderr_truncated"}`
(`stdout_base64` instead of `stdout` when it isn't valid UTF-8), or for
`interactive: true`, `{"run_id", "covered_by", "stream_ticket",
"stream_url", "ticket_expires_at"}`.

**`elevate`** `{"targets": [...], "duration"?, "reason"}` →
`{"elevation_id", "handle", "targets", "expires_at"}`.

### 5.3 The decision point

`Decide` takes the principal, the operation (`run` or `elevate`), the
target(s), the canonical request (docs/04) and the handle, and runs, in
this order:

1. **Introspect** (D3). Failure → deny.
2. **Visibility** (D5). Any target not visible → deny `target_not_allowed`.
3. **Elevation coverage** (`run` only, handle present, D9). Unknown or
   foreign → deny `handle_unknown`. Covering → **allow**, audited with
   the elevation ID; the `Grant` carries the elevation's expiry and its
   cancellation signal.
4. **One-off**: write the pending approval, ask the approver (R5), wait
   (D7). Approved → **allow** with the approval ID. Anything else → deny
   with its code.
5. Every step writes its audit record *before* it acts on the outcome;
   a failed audit write is a deny (`CODE-REVIEW.md`; docs/03 D4).

`elevate` runs steps 1, 2 and 4, and on approval creates the live
elevation and its handle in the same transaction that settles the
approval.

### 5.4 Cancellation of what a grant covers

A `Grant` carries a context that is cancelled when what covers it ends:
for an elevation, its expiry or "End now"; for a one-off approval, the
run's own deadline (docs/04 D7). The runner derives every process and
stream from that context (docs/04 D8). `decision.Elevations` keeps, per
live elevation, the cancel functions of its runs, and calls them when
the elevation leaves `live`.

### 5.5 The CLI

```
nyyrikki login [--server URL] [--client-id ID] [--mcp] [--force]
nyyrikki logout [--mcp]
nyyrikki targets
nyyrikki run [--reason TEXT] [--elevation HANDLE] [--timeout D] [-i] [-t] TARGET -- KUBECTL-ARGS...
nyyrikki elevate --reason TEXT [--for D] TARGET...
nyyrikki mcp-headers
```

- `run` reads stdin and sends it as `stdin` when the kubectl arguments
  read it (`-f -`, or `exec`/`attach` with `-i`), otherwise it refuses
  input. `-t` with a terminal on stdin makes the run interactive (D10)
  and puts the local terminal in raw mode for the session.
- `--elevation` defaults to `NYYRIKKI_ELEVATION`.
- `elevate` prints the handle alone on stdout, so
  `export NYYRIKKI_ELEVATION=$(nyyrikki elevate …)` works, and the
  expiry on stderr.
- The login file defaults to `$XDG_CONFIG_HOME/nyyrikki/login.json`
  (`mcp-login.json` for `--mcp`), mode 0600, overridable with
  `--login-file` or `NYYRIKKI_LOGIN_FILE`.

| Exit code | Meaning |
|---|---|
| kubectl's own | the request ran; kubectl's exit status (the remote command's for `exec`) |
| 64 | usage error, or `invalid_request` |
| 67 | not signed in, or `unauthenticated` (sign in again) |
| 69 | `unavailable` or `internal`: Nyyrikki or a dependency failed |
| 75 | `expired` or `withdrawn`: nobody answered in time |
| 77 | `denied`, `target_not_allowed`, `handle_unknown`, `session_inactive`, `introspection_failed` |

A remote command can itself exit 64, 67, 69, 75 or 77, and its stderr is
forwarded, so it can also print lines that look like Nyyrikki's. When
Nyyrikki itself fails, the CLI's last stderr line is
`nyyrikki: error: <code>: <message>` with a code of D14. That tells a
cooperative remote command apart, not a hostile one: a script that must
know for certain uses the `run` tool's structured result, where `error`
is set only by Nyyrikki.

### 5.6 Configuration

```yaml
server:
  canonical_url: https://nyyrikki.example.com   # /mcp and /stream are appended
  listen: ":8443"
  health_listen: ":8081"
  tls_cert_file: /etc/nyyrikki/tls/tls.crt
  tls_key_file: /etc/nyyrikki/tls/tls.key
  state_dir: /var/lib/nyyrikki                  # SQLite
  runtime_dir: /run/nyyrikki                    # per-run kubeconfigs (docs/04)
auth:
  issuer: https://keycloak.example.com/realms/nyyrikki
  cli_client_id: nyyrikki-cli
  scope: nyyrikki                               # the audience scope, published in scopes_supported
  introspection_client_id: nyyrikki-introspect
  introspection_secret_file: /etc/nyyrikki/keycloak/client-secret
approval:
  timeout: 3m
humans: [...]          # D4
targets: [...]         # D5, docs/04 D9
telegram: {...}        # docs/05
```

Each knob is consumed where §5.1 says; GW1's test loads the chart's
default values file and checks that every field reaches its consumer.

## 6. Security considerations

- **Inputs.** Tool arguments and the agent's reason: attacker-controlled,
  validated by D13 and docs/04. Token and proof: docs/01 D9. The stream
  ticket: a secret, checked against the agent key (D10).
- **Dependency failures.** Introspection, SQLite, the audit writer and
  the approver channel each fail to deny, with a test each (G3).
- **New ways to reach a target.** `run` and `/stream`. `/stream` can only
  attach to a run that already holds a `Grant` (D10). `list_targets`
  reaches no target.
- **What reaches the agent.** Error codes and messages without
  credentials, handles of its own elevations only, its own tickets.
- **Settle order.** Approve, deny, expire and withdraw race on one row;
  the compare-and-set picks one winner, and the others are no-ops (D7,
  D15).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 An agent lists its targets through MCP and through the CLI, and sees only visible ones | `mcpserver` and CLI integration tests (`TestListTargets*`) |
| G2 Every token-check failure of docs/01 §5.8 is a 401, audited | `authn` table tests and an integration test through `/mcp` |
| G3 Each dependency failure (introspection, SQLite, audit, approver channel) ends in deny, through MCP and the CLI | `decision` tests with failing fakes; integration tests |
| G4 A target that is absent or not visible is denied with the same answer | `TestDecideTargetNotAllowed` |
| G5 One-off: approved runs once; denied, expired, withdrawn (client disconnect) and a second tap each deny or do nothing | `decision` tests; `TestRunClientDisconnectWithdraws` |
| G6 Elevation: a live elevation's handle, from the agent key and human it was issued to, on a target it names → runs without asking; no handle → one-off; this key's handle but expired, ended, another human or a target it doesn't name → one-off; an unknown handle, or one issued to another agent key → deny `handle_unknown`, never a one-off; more than 30 m gives 30 m | `TestElevation*`, `TestElevationHandleUnknownDenies` |
| G7 No package other than `decision` can construct a `Grant`; the runner takes only a `Grant` | compile-time (unexported fields) plus `TestOnlyDecisionMakesGrants` (go/packages scan) |
| G8 The server registers only the three tools and no resources or prompts | `TestOnlyThreeTools` |
| G9 A stream ticket works once, for 30 s, for its agent key only, and `/stream` without one is refused | `TestStreamTicket*` |
| G10 A pending approval left by a crash is expired at startup | `TestStartupExpiresPending` |
| G11 CLI exit codes follow §5.5 | CLI tests |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **GW1** | `codes`, `config`, `store` with migrations | G10, config tests |
| **GW2** | `authn` (docs/01 D9, D11 here) | G2 |
| **GW3** | `decision`: visibility, one-off waiting, elevations, handles, grants | G3–G7 |
| **GW4** | `mcpserver` and `server` wiring, listeners, health | G1, G8 |
| **GW5** | the CLI: login (device grant + DPoP, `--mcp` with DCR), `targets`, `run`, `elevate`, `mcp-headers` | G1, G11 |
| **GW6** | `/stream` and the CLI's interactive mode | G9 |

GW1 before everything; GW2 and GW3 in parallel; GW4 needs both; GW5
needs GW4; GW6 needs GW5 and docs/04 PT4. For `ROADMAP.md`: M1 needs
GW1–GW5 with an approver that always denies; M2 adds R4 and R5; M3 adds
the elevation half of GW3 and GW6.

## 9. Risks and open questions

- **FD3 hasn't measured Keycloak yet** (docs/01 M9). GW2 follows docs/01
  D9 as written; if M9 contradicts it, D2 is revised before M4.
- **A client that drops long tool calls** withdraws every approval it
  waits for. Codex's timeout is set explicitly in the setup docs (M3).
- **One human only.** D4 refuses a second one until a doc designs it.

## 10. How it was implemented (2026-10-26)

- **D6**: the decision point has two entry points, `DecideRun` and
  `Elevate`, in the one package that makes Grants, rather than a single
  `Decide`. `Grant` lives in `internal/decision/internal/grant` so that
  only the decision tree (and `decisiontest`, for tests) can construct
  one; `TestOnlyDecisionMakesGrants` enforces G7.
- **D7, settle order**: a waiter that loses the compare-and-set to a
  settle it isn't told about (another process's restart expiry) reads
  the final state from SQLite instead of blocking. Found by
  `TestStartupExpiresPending`, which hung before the fix.
- **D9 audience**: tokens must have exactly one `aud`, the canonical
  `/mcp` URL, which is also the `resource` in the protected-resource
  metadata. The metadata is served at both
  `/.well-known/oauth-protected-resource` and `…/mcp`, and carries
  `scopes_supported` (config `auth.scope`) and a
  `nyyrikki_cli_client_id` field that `nyyrikki login` reads.
- **D14**: the error travels in the tool result's own `error` field
  (`{"error": {"code", "message"}}` next to the other result fields),
  because the go-sdk replaces `structuredContent` with the typed result.
- **D1**: MCP methods other than the handshake, `ping` and `tools/*` are
  refused with "method not found" by a receiving middleware, not merely
  left empty.
- **§5.5**: the CLI sends stdin when `-i` is given or the kubectl args
  contain `-f -` (in its usual spellings); the server still decides
  whether the command reads it.
- **DPoP server nonce** (docs/01 D9, RFC 9449 §8): each nyyrikkid process
  makes a random nonce, and a proof must carry it. A proof without it, or
  with a previous process's, is answered 401 with `use_dpop_nonce` and the
  current `DPoP-Nonce`, not audited; the CLI learns it and retries once. So
  a proof made before a restart can't be replayed into the new process's
  empty replay cache, with no outage window. Replay cache entries expire
  on the proof's `iat`. Found in review of #10, replacing a first fix that
  refused proofs for 30 s after start.
- **Key set age** (D2): the issuer's key set is trusted for at most an
  hour; then it is refetched, one fetch at a time, with the other callers
  waiting for it, and attempts at most once a minute. If the authorization
  server is down when the hour is up, every call (listing targets
  included) is refused until a fetch succeeds. Found in review of #10.
- **Introspection**: a DPoP-bound token whose introspection answer has no
  `cnf.jkt` is refused, not only one whose `cnf.jkt` differs. docs/01 M9
  will show whether Keycloak reports it; if not, this is relaxed by a
  dated note.

## 11. Post-implementation review (2026-10-27)

An adversarial review of the gateway code, before merge, found no path
that runs a request without cover. Its findings and fixes:

| Finding | Fix | Test |
|---|---|---|
| An elevation approved as its call was cancelled stayed live with nobody holding the handle: the lookup after approval used the cancelled context and returned before ending it | `deliverElevation` takes the handle first and queries on the server's context, and every failure after the approval ends the elevation | `TestDeliverElevationCallerGone` |
| A Telegram 409 or 401 made nyyrikkid exit, so the kubelet restarted it into the retry loop docs/05 D2 forbids | the server keeps serving with the poller stopped; escalations are denied | `TestTelegramConflictKeepsServingAndDenies` |
| An approve tap could commit just after the expiry | the expiry is part of the approve compare-and-set | none: the window between the check and the commit can't be forced in a test |
| The chat showed "Approved" for a run that was then withdrawn or failed | a run's prompt is edited only once its grant exists, otherwise to "Withdrawn" or "Failed" | `TestDependencyFailuresDeny/audit_fails_after_approval` |
| Any token with the audience was accepted, an ID token included | `typ` must be `Bearer` or `DPoP` (docs/01 M9 confirms Keycloak's values) | `TestTokenRejected` |
| `telegram.api_url` accepted plain http, which would send the bot token in cleartext | https only, except on loopback | `TestTelegramAPIURL` |
