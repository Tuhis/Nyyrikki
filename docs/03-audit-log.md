# R3 — Audit log and session recordings (docs/03)

**Status**: drafted 2026-10-25, adapted from the Warden design. Status
lives in [`ROADMAP.md`](../ROADMAP.md). There are no open owner
decisions. Decisions D1–D11 await the owner's approval. Revised 2026-10-26 after
review in PR #1: D3 (what anchors prove before they leave G) and §5.9
(root-level `value`, JSON Patch, `last-applied-configuration`,
unparseable and large bodies).

Chunks **AU1–AU4** (`AU` = audit; unused).

**Relationship to earlier work**: provides the audit sink that
[docs/02](02-grant-core.md) D4 and the gate (docs/02 §5.9) depend on, and
the recording writers used by [docs/07](07-kubernetes-proxy.md) and
[docs/08](08-ssh-proxy.md). Owns the shared redaction rules used by every
proxy and by [docs/04](04-telegram-escalation.md). It lands before R4, so
the first AI decision is already recorded.

---

## 1. Purpose

Once something other than a human can act with admin rights, "why was
this allowed?" has to be answerable after the fact, from evidence an
attacker on A can't rewrite. Today, an agent's admin actions leave
traces scattered across the targets' own logs, if they leave any. With
this doc, every decision and every operation lands in one structured,
tamper-evident log on G:

- who asked, for what, and why;
- who approved, which rule matched, and what happened.

Every terminal and exec stream is recorded, so the actual commands and
output can be replayed.

### Non-goals

- **A live view of sessions** (R7). Recordings are replayed after the
  fact in v1.
- **A search UI or log shipping product.** The log is plain JSONL, and
  shipping it off G is an operations choice (docs/09).
- **Recording file contents for SFTP and port-forwards.** Metadata only.
- **Redacting terminal output.** A shell can print anything.
  Recordings are sensitive by definition (§5.7).

## 2. Measured and verified before writing

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Go's `encoding/json` sorts map keys when marshaling. `Encoder.SetEscapeHTML(false)` turns off the `<`, `>`, `&` escaping. | `go doc encoding/json.Marshal`, `go doc encoding/json.Encoder.SetEscapeHTML`, Go 1.26.8, 2026-10-25 | Confirmed. The canonical form in §5.2 relies on both |
| M2 | asciicast **v2** is still parsed by the current asciinema player (v3.17.0) and by CLI 3.x (v3.2.1), which can also still write it (`--output-format asciicast-v2`). CLI 3.x writes **v3** by default. v3 is not backward compatible: it uses relative event intervals, a `term` header object and an `x` exit event. | [docs.asciinema.org asciicast v2 and v3](https://docs.asciinema.org/manual/asciicast/v3/), CLI `src/cli.rs`, player `src/parser/asciicast.js`, 2026-10-25 | Confirmed. Drives D7 |
| M3 | OpenSSH's sshd logs the user certificate's key ID on login, for example `Accepted publickey for alice … ED25519-CERT SHA256:… ID <keyid> (serial N) CA ED25519 SHA256:…` | ran OpenSSH 10.3p1 in docker, 2026-10-25 | Confirmed. Target logs can be correlated with `ss_` IDs (docs/08 §5.9) |
| M4 | `crypto/ed25519` is in the standard library | `go doc crypto/ed25519` | Confirmed. Anchors need no dependency |

## 3. Owner decisions

None open.

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **One append-only JSONL log on G**, with one event per line, rotated by size (128 MiB) or daily. | Plain text survives every tool. Append-only matches the threat model. |
| D2 | **Hash chain.** Every line carries `hash = sha256(prev_hash ‖ canonical(event without hash))`. The chain continues across rotated files. | Detects edits, deletion, reordering and truncation in the middle of the log (INV-10). |
| D3 | **Signed anchors, which count once they are copied off G.** Every 1000 events or 5 min, whichever comes first, G appends to `anchors.jsonl` an ed25519 signature over `(seq_to, chain_hash, ts)`. The public key is in `audit.anchor_pubkeys` on G, and a copy is kept with the off-G anchor copies (docs/09 OD2), where the verification that matters runs. | Detects truncation at the tail and rewriting of anything an off-G anchor covers. M4. On G alone, anchors add little over file permissions: the signing key is readable by the service user that writes the log, so whoever can rewrite the log can also re-sign it. |
| D4 | **A single writer goroutine** behind a bounded channel. `Append` returns only after the line is written and `fsync`ed. Callers that grant access wait for that (docs/02 D4). | Durable before the effect. One writer keeps `seq` gap-free. |
| D5 | **Back-pressure sheds new escalations, never audit lines.** If the queue is over 80% full, the gate returns `busy` for new operations, and access removal still proceeds. | Audit integrity beats availability (SECURITY.md RR-5). |
| D6 | **The event catalog is closed.** Event types are constants in `internal/audit`, and an unknown type is a compile error. | CODE-REVIEW "shared constants have exactly one definition". |
| D7 | **Recordings use asciicast v2 for PTY streams**, JSONL for non-PTY exec streams, and `meta.json` for metadata-only kinds. | M2: v2 is readable by every current player, and by the 2.x CLIs still shipped by distributions. v3 isn't. |
| D8 | **Recording is fail-closed.** If a session that must be recorded can't open its file, it is refused. A write error mid-session closes the session. | INV-10 applied to recordings. |
| D9 | **Redaction happens at the boundary**, in one package (`internal/redact`), before any body or field reaches an event, a recording's metadata, or a Telegram message (§5.9). | CODE-REVIEW "secrets never leave their lane". |
| D10 | **Metrics are written by hand** in the Prometheus text format, on loopback only. There is no client library. | A dozen counters don't justify a dependency (CONTRIBUTING "adding a dependency"). |
| D11 | **Retention**: audit lines are kept forever by default, anchors always. Recordings are kept for 90 days. | Audit rows are small. Recordings are large and sensitive. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Audit rows in SQLite | Mutable by anyone with the DB file, and tied to the state store's failure modes. A separate append-only file with a chain is easier to verify and to ship. |
| journald or syslog only | Not tamper-evident by itself. Fine as an additional sink, configured by the operator (docs/09). |
| asciicast v3 | Not readable by asciinema 2.x (M2). Revisit when distributions ship 3.x. |
| A Merkle tree or transparency log | More machinery than a single-writer chain with signed anchors needs. |
| The Prometheus client library | D10. |

## 5. Design

### 5.1 Format

- **Location**: `audit.dir` (default `/var/lib/nyyrikki/audit`), with
  files `000001.jsonl`, `000002.jsonl`, … and `anchors.jsonl`.
- **Lines**: UTF-8, ending in `\n`, opened with `O_APPEND`, `fsync`ed
  per batch. A batch is everything queued when the writer wakes, at most
  256 lines.
- **Common fields**:
  - `ts`: RFC 3339 UTC with milliseconds.
  - `seq`: gap-free across the life of the log; resumed from the last
    line at startup.
  - `type`.
  - `request_id`, when there is one.
  - `hash`.
- **No floats.** Durations are integer milliseconds, so canonical
  encoding is exact.

```json
{"approvers":["ap_juho"],"client":"cl_agent_vm_a","expires_at":"2026-10-25T14:33:58.102Z",
 "grant":"gr_01JB…","hash":"9f3c…","profile":"k8s-node-maint","request_id":"01JB…",
 "seq":10431,"step":false,"ts":"2026-10-25T13:33:58.102Z","type":"grant.activated"}
```

### 5.2 Hash chain and canonical form

```
canonical(e) = json(map without "hash"), keys sorted, SetEscapeHTML(false), no trailing newline   (M1)
hash_n      = hex(sha256(bytes(hash_{n-1}) ‖ canonical(e_n)))
hash_0      = 64 × "0"   (the first line of the whole log)
```

`bytes(hash)` is the 32 raw bytes, not the hex string. The first line of
file N chains from the last line of file N−1.

At startup, G verifies the last 1000 lines and the newest anchor. On a
mismatch, G refuses to start and reports the first broken `seq`. An
operator must investigate. The tool for that is `audit.verify`.

### 5.3 Event catalog

| Type | Key fields |
|---|---|
| `nyyrikkid.start`, `nyyrikkid.stop` | version, config sha256 |
| `config.loaded`, `config.rejected` | sha256, error (reload) |
| `client.enrolled`, `client.cert_issued`, `client.cert_revoked`, `client.disabled` | client, serial |
| `approver.paired`, `approver.unpaired`, `approver.pair_rejected` | approver, telegram user ID (rejected attempts), reason |
| `grant.requested` | grant, client, profile, reason, label (both untrusted, stored verbatim), requested_ttl_ms, want_step |
| `grant.approved` | grant, approver, update_id (one per approval) |
| `grant.denied`, `grant.request_expired` | grant, approver? |
| `grant.activated` | grant, approvers[], expires_at, step |
| `grant.step_changed` | grant, approver, step |
| `grant.ended` | grant, end_reason, by (approver, `agent`, `admin` or `timer`) |
| `extension.requested`, `extension.approved`, `extension.denied`, `extension.expired` | grant, extension, approver?, old_expiry, new_expiry |
| `op.start`, `op.end` | grant, op ID, kind, the parsed operation (redacted), decision, matched rule, via_allowance?, step?; at the end: status, bytes, duration_ms, error code |
| `step.pending`, `step.approved`, `step.denied`, `step.expired` | grant, step, summary, approver? |
| `allowance.created`, `allowance.expired`, `allowance.revoked` | grant, allowance, matcher, approver |
| `session.open`, `session.close` | grant, session, kind, target, recording_path, close_reason |
| `client.muted`, `client.unmuted` | client, until, approver |
| `telegram.callback_rejected` | reason (docs/04 §5.4), from user ID, update_id |
| `telegram.update_ignored` | from user ID, kind (rate-limited, docs/04 §5.6) |
| `telegram.unavailable`, `telegram.recovered` | error class |
| `ssh.hostkey_mismatch` | target, expected and seen fingerprints |
| `upstream.auth_failed` | upstream, error class |
| `audit.degraded`, `audit.recovered` | error class (logged to stderr if the audit sink itself is the failure) |
| `security.denied` | any authentication or policy denial: code, client?, remote address |

`op.start` and `op.end` do most of the work. There is one pair per
proxied operation in every protocol, carrying the decision and the
matched rule, so the log alone explains why each operation was allowed,
held or denied.

### 5.4 Recordings

Recordings go under `recordings.dir/<grant>/<session>.<ext>`, with mode
`0600`.

**asciicast v2 (`.cast`)**, for PTY sessions: an SSH shell with a PTY,
an SSH exec with a PTY, and Kubernetes exec with `tty=true`. The first
line is the header:

```json
{"version":2,"width":120,"height":32,"timestamp":1792935238,
 "env":{"TERM":"xterm-256color"},
 "nyyrikki":{"grant":"gr_…","session":"ss_…","target":"node-1","login":"root","key_id":"nyyrikki:gr_…:ss_…"}}
```

The events that follow are `[t, code, data]`, where `t` is float seconds
since `timestamp` (v2 is absolute, M2):

- `o`: output to the user;
- `i`: input from the user;
- `r`: a resize, as `"<cols>x<rows>"`.

Event times are the only floats in the system. They never enter the
audit chain.

**JSONL (`.jsonl`)**, for non-PTY exec in SSH and Kubernetes: one line
per chunk, `{"t_ms":N,"stream":"in|out|err","b64":"…"}`. The last line
is `{"t_ms":N,"event":"exit","code":N}`.

**Metadata (`.meta.json`)**, for SFTP, port-forward and direct-tcpip:
`{grant, session, kind, target, started, ended, bytes_in, bytes_out,
events:[{t_ms, op, path, bytes}]}`. Contents are not stored.

Recorders are passive tees. They never alter the stream. The proxies
own how to parse frames (docs/07 §5.7, docs/08 §5.6).

**Replay**: `nyyrikki recording export ss_…` writes the file to stdout,
for `asciinema play -` (or `cat` for JSONL) on the operator's machine.

### 5.5 Anchors and verification

**Anchor line** (`anchors.jsonl`):

```json
{"seq_from":9431,"seq_to":10431,"chain_hash":"9f3c…","ts":"…","key_id":"an1","sig":"base64"}
```

`sig = ed25519.Sign(anchor_key, bytes(chain_hash) ‖ be64(seq_to) ‖ ts)`.

**`nyyrikki audit.verify --from N --to M`** (admin socket, docs/02 §5.14)
does three things:

1. recomputes the chain over the range;
2. checks each line's hash;
3. verifies every anchor signature against the public keys in
   `audit.anchor_pubkeys` (old keys stay listed after a rotation).

It reports the first broken `seq`, or `ok`.

Anchors SHOULD be copied off G regularly (docs/09 §5.5). Then even a
compromise of G leaves outside evidence of the chain before the
compromise.

### 5.6 Fail-closed behaviour (INV-10)

| Condition | Result |
|---|---|
| An append fails for an escalating transition: activate, extend, step approval, allowance, step mode off | The transaction aborts. The caller gets `audit_unavailable` (docs/02 D4). |
| An append fails for `op.start` | The operation is refused with `audit_unavailable`. |
| An append fails for a de-escalation: expire, revoke, release, deny | The state change stands. G sets `audit_degraded`, writes the event to stderr (journald), and refuses every escalation until an append succeeds. |
| An append fails for `op.end` or `session.close` | G sets `audit_degraded`. The operation already happened, and its `op.start` is on disk. |
| The queue is over 80% full | New operations get `busy`. Access removal is unaffected (D5). |
| A recording file can't be opened | The session is refused (D8). |
| A recording write fails mid-session | The session is closed with `close_reason: recording_failed`. |

`audit_degraded` clears on the first successful append. G emits
`audit.recovered`, and `status` and the metrics both show the state.

### 5.7 Retention and privacy

- **Recordings** are deleted after `recordings.retention` (90d) by the
  janitor, which sets `sessions.recording_path` to NULL. **Audit** lines
  are kept for `audit.retention` (0 = forever). Anchors are always kept.
- **Recordings can contain anything a terminal shows.** They are `0600`,
  never exposed to A, and readable only by root and `nyyrikki-admin` on
  G.
- **No event and no recording metadata contains** a grant token, client
  key, upstream secret, bot token, decision ref, pairing code or Secret
  value (INV-11). §5.9 enforces this for structured data. Adding an event
  type requires a canary test (G6).

### 5.8 Metrics

Metrics are served on `server.metrics.addr` (loopback) in the Prometheus
text format (D10):

- `nyyrikki_grants{state}`
- `nyyrikki_decisions_total{kind,outcome}`
- `nyyrikki_denials_total{code}`
- `nyyrikki_steps_pending`
- `nyyrikki_sessions_open{kind}`
- `nyyrikki_audit_queue_depth`
- `nyyrikki_audit_degraded`
- `nyyrikki_recording_errors_total`
- `nyyrikki_telegram_up`
- `nyyrikki_cert_expiry_seconds{cert}`

Label values come only from config or from constants, never from A.

### 5.9 Redaction (shared, `internal/redact`)

`redact.Body(contentType, bytes) Digest` and `redact.Fields(map)` run on
request bodies and fields before they reach an event, a step summary or
a Telegram message. Redaction is by key, so it needs a body it can parse
completely. Anything else is reduced to its digest:

- **Parsed** content types:
  - JSON: `application/json` and any `+json` type, which includes
    Kubernetes merge and JSON patches;
  - YAML: `application/yaml` and `application/apply-patch+yaml`
    (server-side apply);
  - `application/x-www-form-urlencoded`, parsed into key/value pairs
    that the same key rules apply to (`client_secret=…`).
- **Digest only**, `{sha256, len, content_type}` with no content: any
  other content type, a body that fails to parse, and any body over
  1 MiB. A prefix of a large body is never kept, because a truncated
  JSON document can't be parsed and so can't be redacted.
- **These keys, at any depth, have their values replaced** with
  `"<redacted len=N sha256=8hex>"` (case-insensitive), keeping the keys:
  - `password`, `secret`, `token`, `clientSecret`, `client_secret`,
    `privateKey`, `private_key`, `tls.key`;
  - `apiKey`, `api_key`, `secretData`, `credentialData`;
  - `value`. That covers Keycloak's `CredentialRepresentation`, which
    `PUT …/users/{id}/reset-password` sends bare, with the new password
    at the root (`{"type":"password","value":"…"}`), as well as
    `credentials[].value` and Kubernetes `env[].value`. Losing a few
    harmless values (a toleration's, say) is the price of not having to
    know every API that calls a secret `value`;
  - `data` and `stringData` (Kubernetes Secrets, and ConfigMaps too);
  - and any key ending in `Token`, `Password`, `Secret`, `Credential`
    (Keycloak's LDAP `bindCredential`) or `ApiKey`.
- **JSON Patch** (`application/json-patch+json`) is the exception to
  the `value` rule. There, `value` is the content of the change, so
  hiding it would hide what the approver is approving
  (`{"op":"replace","path":"…/image","value":"evil:latest"}`). An
  operation's `value` is replaced only when a segment of its `path` is
  one of the keys above (`/data/password`, `…/env/3/value`).
  Otherwise it is kept, and the key rules apply inside it.
- **What the approver is told**: `Digest` reports how many values were
  replaced and whether the body was reduced to a digest, so the step
  prompt can say what is hidden (docs/04 §5.5).
- **Kubernetes `Secret` objects** keep only their metadata and their key
  names. The `kubectl.kubernetes.io/last-applied-configuration`
  annotation is not kept, even though it is metadata (below).
- **`kubectl.kubernetes.io/last-applied-configuration`**, on any object,
  is replaced with its digest. Client-side `kubectl apply` and `create
  --save-config` store the whole object in it as a JSON **string**, with
  a Secret's `data` and `stringData` and a Deployment's `env` values.
  Key rules match keys and never look inside strings, so without this
  rule the annotation would carry those values past every other rule.
  The same applies when an update sends the annotation in a
  strategic-merge patch.
- **Headers** never reach events at all. Each proxy records method, path
  and status only.

The proxies add protocol-specific rules in their docs (docs/06 §5.4,
docs/07 §5.5). Those rules are implemented here, in one place, so a
field is redacted everywhere or nowhere.

### 5.10 Configuration

```yaml
audit:
  dir: "/var/lib/nyyrikki/audit"
  rotate_size: 128MiB
  retention: "0"                       # 0 = forever
  anchor_key_file: "/etc/nyyrikki/pki/audit-anchor.ed25519"
  anchor_key_id: "an1"
  anchor_pubkeys: { an1: "/etc/nyyrikki/pki/audit-anchor.ed25519.pub" }
recordings:
  dir: "/var/lib/nyyrikki/recordings"
  retention: 90d                       # >= 7d
```

| Key | Consumed by (production call site) |
|---|---|
| `audit.dir`, `audit.rotate_size` | `audit.Open` → `audit.Writer` |
| `audit.retention`, `recordings.retention` | `store.Janitor` |
| `audit.anchor_key_file`, `audit.anchor_key_id` | `audit.Anchorer` |
| `audit.anchor_pubkeys` | `audit.Verify` (startup and `audit.verify`) |
| `recordings.dir` | `record.Open` (called by the proxies) |

## 6. Security considerations

- **New trust boundary**: none. This is G-internal. Its inputs are
  events produced by G code. The untrusted strings inside them (reason,
  label, parsed operations) are stored verbatim as JSON strings, which
  JSON escaping makes safe. They are only ever rendered by docs/04's
  renderer.
- **Dependency failures end in deny**: §5.6 covers every case.
- **What reaches the audit log**: §5.3 after §5.9. Never secrets (INV-11),
  enforced by G6.
- **New ways to reach an upstream**: none.
- **Tampering**: someone who is neither root nor the service user on G
  can't change the log, because of file permissions. Root or the
  service user can rewrite it and re-sign anchors, but can't change what
  anchors already copied off G cover (D3, RR-2).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. `audit.verify` detects an edited line, a deleted line, swapped lines, a truncated tail (through the anchor), and a forged anchor, and reports the first broken `seq` (INV-10) | `internal/audit` tests, one per tamper kind; fuzzing of the canonical encoder |
| G2. A failing append refuses every escalating transition and every `op.start`, and still lets de-escalations through with `audit_degraded` (INV-10, docs/02 D4) | integration test with a failing sink, together with docs/02 G6 |
| G3. Back-pressure returns `busy`, and never drops a line | load test with a stalled writer |
| G4. A PTY session produces a `.cast` that `asciinema play` (both 2.x and 3.x) accepts. Non-PTY exec produces `.jsonl`. SFTP produces `.meta.json` | e2e: replay through both CLI versions in containers |
| G5. A session whose recording can't be opened is refused. A write error closes the session (D8) | integration test |
| G6. No event or recording metadata contains any of the planted canary secrets (INV-11) | `internal/redact` table tests, one per content type and rule in §5.9; the canary scan over the full e2e audit output (shared with docs/04 G8). The planted canaries include a Keycloak `reset-password` body, an LDAP `bindCredential`, a Kubernetes Secret, the same Secret applied twice with client-side `kubectl apply` (create, then patch, both carrying `last-applied-configuration`), a form-encoded `client_secret`, a JSON Patch `value` under `/data/…` and under `…/env/N/value`, an unparseable JSON body and a 2 MiB JSON body with a canary past the first 64 KiB. A JSON Patch that changes an image keeps the image visible |
| G7. Retention deletes recordings after the configured age, and never deletes audit lines when the retention is 0 | janitor test with a fake clock |
| G8. Every key in §5.10 changes behaviour at its call site | one test per knob |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **AU1** | `internal/audit` writer, chain, catalog constants, fail-closed and `audit_degraded`; `internal/redact` | G2, G3, G6 (unit level) |
| **AU2** | Anchors, `audit.verify`, the startup check | G1 |
| **AU3** | `internal/record`: asciicast v2, JSONL and meta writers | G4, G5 |
| **AU4** | Retention janitor; metrics endpoint | G7, G8 |

Ordering notes: AU1 lands before docs/02 GC4. AU3 lands before docs/07
KP4 and docs/08 SH3.

## 9. Risks and open questions

- **Root on G can rewrite anything not yet anchored off G** (RR-2). How
  anchors leave G is an operations choice (docs/09 §5.5, OD2). Until
  they do, anchors add nothing over file permissions (D3).
- **Recordings are only as safe as G's disk.** Disk encryption at rest
  is required in docs/09.
- **asciicast v2 may eventually be dropped by asciinema.** M2 says it is
  still read today. Re-check at each major player release.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
