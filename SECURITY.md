# Security Policy

Nyyrikki is an identity-aware proxy: its whole job is to keep the wrong
requests away from the services behind it. It is maintained by one person,
on a best-effort basis.

## Reporting a vulnerability

Don't open an issue or a pull request. Contact the maintainer privately,
and include what you found, how to reproduce it and what it lets an
attacker do. You'll get an acknowledgement, and the fix will be
coordinated with you before anything is disclosed.

## Threat model

Drafted 2026-10-25 as part of R1 ([`docs/01`](docs/01-foundations.md)).
It is binding once the owner approves docs/01. The design docs refer to
the invariants below by number (`INV-07`). Each invariant names the doc
that enforces it and the acceptance criterion that tests it.

### Scope

Nyyrikki gives AI agents time-limited, human-approved access to the admin
interfaces of self-hosted infrastructure: the Kubernetes API, SSH, and
admin HTTP APIs such as Keycloak's. The agent runs on an **agent VM (A)**
with full local autonomy. Nyyrikki runs on a separate **gateway host
(G)**. Approvers decide from Telegram. Human sign-in (OIDC) is out of
scope for v1 (docs/01 OD1).

The kinds of issue that are in scope:

- Reaching a protected upstream without passing authentication and
  authorization.
- Any path where an error, timeout or malformed response leads to allow
  instead of deny.
- Steering the AI assessment toward allow with content the requester
  controls (prompt injection), once R4 exists.
- Forging, replaying or reusing a Telegram approval, or approving from an
  account that isn't an approver.
- Leaking tokens, cookies or session identifiers into logs, prompts, audit
  records or Telegram messages.
- Tampering with or suppressing audit records.
- Supply-chain issues in the build and release path.

### Assets

| # | Asset | Where it lives |
|---|---|---|
| AS-1 | Real credentials for targets: Kubernetes impersonation rights, the SSH user CA key, upstream API secrets, and the **Telegram bot token** | G only |
| AS-2 | The ability to perform privileged operations on targets | mediated by G |
| AS-3 | The approvers' Telegram accounts and the phones they are logged in on | the approvers |
| AS-4 | G's own keys: the internal TLS CA, the audit anchor key, the SSH proxy host key | G only |
| AS-5 | The audit log and session recordings | G only |
| AS-6 | Grant credentials issued to A: the client certificate, the per-grant token, the per-grant SSH key | A, for the life of a grant |

AS-1, AS-4 and AS-5 never exist on A. A only ever holds AS-6, which is
short-lived, scoped and revocable.

### Actors

| Actor | Trust | Notes |
|---|---|---|
| Approver | trusted | A human with a paired Telegram account. Approves, denies, revokes. |
| Gateway host G | trusted (the TCB) | The system's security reduces to G behaving correctly and its secrets staying on it. |
| Agent on A | **untrusted** | May be fully autonomous. Treated as potentially adversarial. |
| A itself (host and every process on it) | **untrusted** | Any process on A can read anything on A. |
| Telegram | trusted for one thing | Telegram authenticates the approver's account (it sets `from.id`) and delivers updates. It also sees message content and is technically able to forge a tap (RR-6). |
| Targets | semi-trusted | Trusted to enforce their own authorization (RBAC, account permissions, realm roles). Their identity is verified by G, not assumed. |
| Network between A, G and targets | untrusted | Protected by mTLS, SSH and verified TLS. |

### The central assumption

**An approval means something only if A can't produce it.**

The agent controls A, including the coding tool's UI, its MCP tools,
local CLIs and files. Any confirmation shown, computed or checked on A
can be satisfied by the agent itself. The approval surface is therefore
off A: a tap in the approver's Telegram chat, delivered by Telegram to
G's own long-poll, checked against the approver's account, the prompt,
and a single-use reference G issued for exactly that decision. A has
neither the bot token nor the approver's Telegram session, so A can
produce neither.

Two prohibitions follow:

- Never put the bot token on A.
- Never log in to Telegram (Web, Desktop or a phone emulator) on A or on
  anything A can control.

Breaking either one gives the agent its own approvals.

### Trust boundaries

```
  Untrusted                          │   Trusted (TCB)
  ┌──────────── A ─────────────┐     │   ┌─────────────── G ─────────────────┐
  │ agent, nyyrikki-mcp,       │──mTLS / SSH──▶ nyyrikkid: gate, policy,   │
  │ kubectl, ssh, curl, AS-6   │     │   │ grants, proxies, audit, AS-1/4/5   │
  └────────────────────────────┘     │   └──┬───────────┬──────────┬────────┘
                                     │      │impersonate│ephemeral │injected
                                     │      ▼           ▼cert      ▼credential
                                     │  kube-apiserver  sshd      Keycloak, APIs
  ┌──── Approver ─────┐   ┌──── Telegram ────┐  outbound long-poll │
  │ phone, Telegram   │──▶│ Bot API (cloud)  │◀────────────────────┘ (G pulls; no inbound)
  └───────────────────┘   └──────────────────┘
```

1. **A ↔ G.** Every byte from A is untrusted. G authenticates the
   transport, requires an active grant bound to that identity, re-parses
   every operation itself, and adds the real credential on its own side.
2. **Approver ↔ Telegram ↔ G.** G pulls updates over verified TLS. It
   acts only on taps that pass the checks in docs/04 §5.4.
3. **G ↔ targets.** G verifies each target's identity: pinned or
   CA-validated SSH host keys, TLS trust. It presents only narrow
   credentials.

### The security model in one paragraph

Real power never leaves G. A can only ask G to perform an operation, over
an authenticated channel, under an active grant whose scope an approver
approved in Telegram. For each request, G parses the operation itself,
evaluates default-deny policy, holds the operation for a fresh approval
if policy or step mode says so, performs it with a narrowly scoped
credential of G's own against a verified target, records it, and can
tear it all down within two seconds. The hard boundary is the target's
own authorization, reached through a fixed identity:

- for Kubernetes, the RBAC of the impersonated user;
- for SSH, the account permissions behind the certificate principal;
- for Keycloak, the realm roles of the service account.

Nyyrikki adds deny, hold and recording on top. It does not rely on
understanding the agent's intent.

### Residual risks (accepted in v1)

- **RR-1. An active grant can be used by anything on A.** Bounded by
  narrow profiles, short TTLs, step mode, recording and instant revoke.
  Not removed. The HTTP token also needs A's client key. The per-grant
  SSH key doesn't, because the SSH listener has no mTLS. Copied off A, it
  works from any address that `source_cidrs` and G's firewall admit,
  which is why `source_cidrs` is required for SSH clients (docs/08 D2).
- **RR-2. G is the TCB.** Compromising G compromises everything. G is a
  dedicated, minimal host (docs/09).
- **RR-3. The approver's Telegram account is the approval factor.**
  Whoever controls it, or the unlocked phone, or any other logged-in
  Telegram session, can approve:
  - a SIM swap, if 2-Step Verification is off;
  - malware on the phone;
  - a Telegram Desktop session left open.

  No user verification or step-up is available to bots (docs/04 M11).
  Mitigations:
  - 2-Step Verification and a passcode (required at setup, docs/04 D13);
  - review of active sessions;
  - short decision windows;
  - every decision visible in the approver's own chat;
  - revoke is one tap away;
  - the audit log.
- **RR-4. SSH command rules are not a boundary.** Once a shell is open,
  the account's permissions on the target apply. Prefer narrow accounts
  and `exec:` rules for risky profiles.
- **RR-5. Availability.** If G or Telegram is down, nobody can elevate.
  This is intended: fail closed. Humans keep an independent break-glass
  path to their infrastructure that doesn't depend on G (docs/09).
- **RR-6. Telegram is a party to every approval.** Its servers see
  approval messages in clear text and are technically able to forge a
  callback from an approver's account. The owner accepted this in
  exchange for the UX (docs/01 OD2). docs/04 OD1 decides how much detail
  the messages carry.
- **RR-7. The agent can try to persuade the approver.** `reason` and
  `label` are the agent's words. Messages show G's parsed scope and
  operations first, and the agent's text last, labelled untrusted
  (INV-15). Even so, a persuasive request is still a request a human
  must read.

### Security invariants

| ID | Invariant | Enforced in | Verified by |
|---|---|---|---|
| INV-01 | A never holds a standing privileged credential. It holds only its client identity and per-grant, short-lived, revocable credentials (AS-6). | docs/02 §5.11–5.12, docs/05 | docs/02 G3, docs/05 G2 |
| INV-02 | A grant, extension, step approval, allowance, step-mode-off or unmute takes effect only through a Telegram tap that passes every check in docs/04 §5.4. No other code path performs these transitions. | docs/04 §5.4, D7 | docs/04 G1, G11 |
| INV-03 | Every tap carries a random, single-use reference issued by G for one approver, one prompt and one object, with an expiry. On a decision prompt it is consumed atomically with its siblings, so the object is decided once. A replayed, expired, foreign or forwarded tap is rejected. | docs/04 §5.4 | docs/04 G2, G3 |
| INV-04 | Upstream credentials and the bot token (AS-1) are never sent to, derived on, or reachable from A. G adds credentials on its own side of each proxy. | docs/04 D1, docs/06 §5.5, docs/07 §5.8, docs/08 §5.9 | docs/04 G8, docs/06 G4, docs/07 G9, docs/08 G10 |
| INV-05 | For Kubernetes, G's identity can do nothing but impersonate, beyond the discovery and self-review rules every identity gets, and it impersonates only the fixed per-profile user from the frozen profile. G strips every client-sent `Authorization` and `Impersonate-*` header. Kubernetes RBAC is the boundary. | docs/07 D1, D2, D11, §5.11 | docs/07 G2, G3, G4 |
| INV-06 | Every proxied operation needs an active grant whose client equals the authenticated transport identity, checked per request. | docs/02 §5.11–5.12, docs/08 §5.1 | docs/02 G2, G4, docs/08 G1 |
| INV-07 | Revoke, expiry and release cancel every in-flight request and open connection of the grant within 2 s, and refuse new ones. | docs/02 §5.17, all proxies | docs/02 G10, docs/07 G11, docs/08 G9 |
| INV-08 | Policy is default-deny. An operation proceeds only if a rule matches with `allow`, or with `confirm` and the hold is approved. | docs/02 §5.8 | docs/02 G7 |
| INV-09 | Grant credentials are per grant, and stop working the instant the grant leaves `active`. | docs/02 §5.12 | docs/02 G4 |
| INV-10 | The audit log is append-only and tamper-evident (hash chain plus signed anchors). An audit write that fails never becomes an allow, and access is still removable while audit is down. | docs/03, docs/02 D4 | docs/03 G1, G2, docs/02 G6 |
| INV-11 | No Telegram message or audit event contains a token, credential, cookie, `Authorization` value, unredacted body, decision reference or pairing code. Callback data alone authorizes nothing. | docs/04 §5.7, docs/03 §5.3, §5.9 | docs/04 G8, docs/03 G6 |
| INV-12 | Target identity is verified, never trusted on first use: pinned SSH host keys or a host CA; TLS against a configured trust store. | docs/06 §5.6, docs/07 §5.12, docs/08 §5.3 | docs/06 G5, docs/07 G10, docs/08 G5 |
| INV-13 | SSH logins to targets use ephemeral certificates (valid ≤ 3 min) minted per session from G's SSH user CA. | docs/08 §5.9 | docs/08 G4 |
| INV-14 | G sanitizes request shape. It strips hop-by-hop and identity headers and rejects path traversal (`..`, `//`, encoded slashes). Client input never selects the upstream credential. | docs/06 §5.2, §5.4, docs/07 §5.2 | docs/06 G2, G3, docs/07 G2 |
| INV-15 | Text from A (and from parsed operations) shown in Telegram is escaped, has control, bidi and zero-width characters neutralized, is truncated, and is placed after G's trusted lines in a labelled quote. | docs/04 §5.7 | docs/04 G7 |
| INV-16 | Administrative actions (enrolment, pairing, config, revoke-as-admin) are available only on G's local admin socket. No admin command grants or widens access, and nothing A can reach is an admin path. | docs/02 §5.14 | docs/02 G12 |
| INV-17 | A step approval authorizes only its own operation. An allowance authorizes only within its matcher, its lifetime and the rule that held the approved operation, and never overrides a deny or scope. | docs/02 §5.4–5.5, docs/04 §5.5 | docs/02 G9, docs/04 G12 |
| INV-18 | A can't widen its own authority. Profiles, their scope and their targets are fixed in G's config. A chooses only which permitted profile, and a TTL clamped by config. | docs/02 §5.2, §5.13 | docs/02 G11, docs/06 G1 |
| INV-19 | G receives Telegram updates only through its own outbound long-poll to the Bot API over verified TLS. No endpoint on G accepts updates. G refuses to start if a webhook is set on its bot, and stops polling if a webhook or a second poller appears while it runs (`409`). | docs/04 D2, D10, §5.1 | docs/04 G5, G9, docs/09 G1 |

### Out of scope

- Side-channel and physical attacks on G, or on approvers' phones.
- Security of A itself, beyond RR-1.
- Telegram's own infrastructure security (RR-6).
- Denial of service against G from A. G applies basic rate limits
  (docs/02 §5.13), and availability is covered by RR-5.
