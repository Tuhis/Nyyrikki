# R2 — Grant core: agent identity, grants, policy, one decision point (docs/02)

**Status**: drafted 2026-10-25, adapted from the Warden design. Status
lives in [`ROADMAP.md`](../ROADMAP.md). This doc has no open owner
decisions of its own; [docs/01](01-foundations.md) OD1 and OD2 apply.
Decisions D1–D18 await the owner's approval. Revised 2026-10-26 after
review in PR #1: D9 (token minted at delivery, release without token),
D15 (teardown order matches §5.17), allowances bound to their rule
(§5.5), shadowed denies and holds fail validation (§5.15.6), what reload
re-resolves (§5.15.7), pending steps on restart (§5.17).

Chunks **GC1–GC8** (`GC` = grant core; unused).

**Relationship to earlier work**: builds on [docs/01](01-foundations.md)
(architecture, toolchain, conventions) and the threat model in
[`SECURITY.md`](../SECURITY.md). Approvals arrive through
[docs/04](04-telegram-escalation.md). Every event is written through
[docs/03](03-audit-log.md). The three protocol proxies
([docs/06](06-http-proxy.md), [docs/07](07-kubernetes-proxy.md),
[docs/08](08-ssh-proxy.md)) are clients of the decision point defined
here. This doc replaces the original R2 scope ("OIDC sign-in, sessions"):
per docs/01 OD1 the v1 requester is an agent client, and human sign-in
moved to R12.

---

## 1. Purpose

An agent on the agent VM (A) hits a wall halfway through a task:
`kubectl drain` is forbidden, there is no SSH key for `node-1`, there is
no Keycloak admin token. Today the choice is to give A standing admin
credentials, which every process on A can then read, or for the human to
take over by hand and lose the thread's context.

This doc defines the core that makes a third option possible:

- A asks for a named, pre-defined bundle of authority (a **profile**) for
  a bounded time.
- A human approves (docs/04).
- G issues short-lived grant credentials, bound to A's identity.
- Every operation A then makes is parsed by G and passes through **one
  decision point**. It applies the profile's default-deny rules, holds the
  operations that need a human, and refuses everything once the grant
  ends.

When this ships, grants, clients, profiles, policy and the decision point
exist and are tested. Together with docs/03 and docs/04, a grant can be
requested, approved and torn down end to end. The proxies then only have
to parse and forward.

### Non-goals

- Protocol parsing and forwarding (docs/06–08).
- How an approval is captured (docs/04). This doc defines the decision
  interface it calls.
- Moderated mode, where operations run only while an approver watches
  live. Deferred to R7 (D12).
- Human requesters and OIDC (R12, docs/01 OD1).
- AI risk assessment (R4). §5.10 marks where it plugs in. Nothing here
  implements it.
- High availability. One `nyyrikkid` instance.

## 2. Measured and verified before writing

| # | Claim | How | Result |
|---|---|---|---|
| M1 | With `modernc.org/sqlite`, a compare-and-set `UPDATE grants SET state=? WHERE id=? AND state='pending'` run concurrently by three goroutines has exactly one winner (`RowsAffected()==1`), so the DB row can be the single authoritative signal for racing transitions (D3) | Ran a test, 2026-10-25: Go 1.26.8, `modernc.org/sqlite` v1.61.0, WAL, `busy_timeout=5000`. 200 rounds × 3 concurrent transitions (`active`, `denied`, `request_expired`) on one row | Confirmed: exactly one winner in every round. WAL mode reported by `PRAGMA journal_mode` |
| M2 | Go's `crypto/tls` does **not** call `Config.VerifyPeerCertificate` on resumed connections; `Config.VerifyConnection` runs on every connection, resumptions included | `go doc crypto/tls.Config`, Go 1.26.8, 2026-10-25 | Confirmed, quoted: "This callback is not invoked on resumed connections" (VerifyPeerCertificate); "This callback will run for all connections, including resumptions" (VerifyConnection). Drives D7 and a gotcha |
| M3 | The stdlib covers the internal CA: `x509.ParseCertificateRequest`, `(*CertificateRequest).CheckSignature`, `x509.CreateCertificate`; constant-time compare via `crypto/subtle.ConstantTimeCompare` | `go doc`, Go 1.26.8, 2026-10-25 | Confirmed. No third-party PKI library is needed |
| M4 | `encoding/json.Decoder.DisallowUnknownFields` exists for strict request decoding | `go doc`, Go 1.26.8 | Confirmed |
| M5 | ULID and YAML library status and licences | [docs/01](01-foundations.md) §2 | See docs/01 M-rows (single home) |

## 3. Owner decisions

None open in this doc. docs/01 OD1 (agents first) and OD2 (Telegram tap
approves on its own) shape it.

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Profiles are the only unit of authority.** They are fixed in G's config. A names one when requesting and cannot define or edit scope. | INV-18. Scope is reviewed in a config file, not negotiated at runtime. |
| D2 | **A grant is the unit of authorization, audit, credential issuance and revocation.** States in §5.3. Terminal states are immutable. | One object answers "what could A do, when, approved by whom". |
| D3 | **Every grant, step and extension transition is one compare-and-set on its row** (`UPDATE … WHERE id=? AND state=?`, `RowsAffected()==1`). The loser of a race is a no-op. Approve, deny, expire and revoke race only through this. | CODE-REVIEW "one event, one authoritative signal". Measured in M1. |
| D4 | **Audit ordering on transitions.** If a transition *grants or widens* access (activate, extend, approve a step, create an allowance), the audit event is appended durably *before* the DB commit, and a failed append aborts the transaction. If it *removes* access (expire, revoke, release, deny), it commits first and is audited after. If that append fails, G enters `audit_degraded`: it refuses every escalation until the audit sink recovers. | INV-10. An audit failure never becomes an allow, and it never blocks taking access away. |
| D5 | **Exactly one decision point**: `gate.Authorize(ctx, grant, op) (gate.Permit, error)`. Every forwarder takes a `gate.Permit`, and only the gate can construct one: the struct has unexported fields and lives in package `gate`. A proxy that forwards without a Permit doesn't compile. | CODE-REVIEW "one decision point", enforced by the type system rather than by review. |
| D6 | **Policy is default-deny, with ordered rules where the first match wins.** Actions are `allow`, `deny` and `confirm`. One glob matcher, plus RE2 for `re:` patterns, both compiled at config load. | INV-08. Small enough to review line by line (§5.8). |
| D7 | **Client identity is an mTLS client certificate from G's internal CA.** A generates the key itself and enrols with a one-time token and a CSR. Checks run in `tls.Config.VerifyConnection`, *and* per request against an in-memory index of client and cert status. Session tickets are disabled on the agent listener. | INV-06. M2: `VerifyPeerCertificate` is skipped on resumption, and a keep-alive connection outlives a revocation. |
| D8 | **Grant credentials**: a bearer token `nyg_<grantId>_<secret>`, of which G stores only the SHA-256, plus a per-grant ed25519 SSH public key generated on A. Both stop working the instant the grant leaves `active`. The token is valid only together with the client cert of the grant's client. | INV-06, INV-09. A stolen token is useless without A's client key. |
| D9 | **Credentials are minted when they are delivered, and delivered once.** The first read after activation generates the token, stores its SHA-256 and sets `credentials_delivered_at`, in one compare-and-set transaction (§5.13). If the response is lost, A releases the grant, which needs only mTLS, and requests a new one. | G never stores a plaintext token, not even across a restart between activation and the first read. Release only removes access, so a lost token must not be able to orphan a grant until it expires. |
| D10 | **The profile is frozen at approval** (`profile_snapshot`). A config reload never widens or narrows a live grant. | Approvers approve what they were shown. |
| D11 | **Timers**: request window 15 min, extension window 10 min, step timeout 5 min, full teardown within 2 s. One timer scheduler, with a janitor as backstop. | INV-07. Defaults are in §5.7. |
| D12 | **Moderated mode is deferred to R7.** | It needs a live presence signal (the approver is watching now). Telegram can't provide that without heartbeat taps, which would be bad UX. Step mode covers per-operation oversight in v1. |
| D13 | **Failure phases are typed**: every error that crosses a package boundary carries a `codes.Code` from one package, `internal/codes`. Proxies map codes to protocol errors, and nothing parses messages. | CODE-REVIEW "type your failure phases", "shared constants have exactly one definition". |
| D14 | **Local admin goes over a Unix socket** (`/run/nyyrikki/admin.sock`, group `nyyrikki-admin`). No admin command grants or widens access. `grant.revoke` only de-escalates. | INV-16. Approvals have exactly one path (docs/04, INV-02). |
| D15 | **Teardown order**: commit the state, drop the token and SSH-key index entries, then cancel the grant context, close sessions, and emit `grant.ended` (§5.17). | Access is gone from the index before anything slow happens. |
| D16 | **Config is one YAML file, strictly decoded** (unknown keys are an error), validated in full at startup and on reload. G refuses to start on any error. Secrets are referenced, never inline. | Fail closed. A typo in a deny rule must not silently drop the rule. |
| D17 | **Control-API request bodies are strictly decoded** (`DisallowUnknownFields`) and size-capped. Requests are rate-limited per client. | Untrusted input. M4. |
| D18 | **Dual control is supported but off by default**: `approvals_required` defaults to 1. docs/04 OD2 decides whether it ships in v1. | Cheap in the data model, but a knob nobody asked for until the owner says otherwise. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Give A scoped standing API keys or kubeconfigs | Every process on A can read them. No per-operation mediation, no step mode, no instant teardown. Violates INV-01 and INV-04. |
| Policy in OPA/Rego or CEL | A large dependency and a language reviewers must learn, for a handful of rules per profile. The glob grammar covers the profiles in §5.8. Revisit if real rules outgrow it. |
| Self-contained signed tokens (JWT) instead of opaque tokens | Revoking instantly needs a lookup anyway. An opaque token plus a hash lookup is simpler and leaks nothing. |
| An approve command on the admin socket ("break-glass approval") | It would be a second approval path next to INV-02. Root on G can already reach targets through the documented break-glass path (docs/09 §5.8) without pretending to be an approval. |
| Moderated mode through Telegram heartbeats ("tap every minute to stay present") | Bad UX, and a tap every minute trains approvers to tap without reading. Deferred to R7 (D12). |
| PostgreSQL for state | An extra service on G for a single-instance gateway. SQLite in WAL mode is enough (M1). |

## 5. Design

### 5.1 Objects

| Object | ID prefix | Defined by | Lifetime |
|---|---|---|---|
| Client (identity of one A) | `cl_` | config + enrolment | until removed |
| Approver | `ap_` | config + pairing ([docs/04](04-telegram-escalation.md)) | until removed |
| Profile | name | config | until removed |
| Grant | `gr_` | runtime | minutes to hours |
| Grant approval | — | runtime | life of the grant |
| Extension | `ex_` | runtime | pending ≤ 10 min, then a record |
| Step (held operation) | `st_` | runtime | ≤ 5 min pending, then a record |
| Allowance | `al_` | runtime | approver-set, ≤ the grant's expiry |
| Session (SSH, exec, port-forward, watch) | `ss_` | runtime | life of the connection |

IDs are the prefix plus a ULID (26 characters of Crockford base32), so
they sort by time. Config-defined IDs MAY use `<prefix><slug>`, for
example `cl_agent_vm_a` or `ap_juho`.

### 5.2 Profile

A profile is a named, flat (no inheritance) bundle defined in config
(§5.15.5):

- `name`: matches `^[a-z0-9][a-z0-9-]{1,61}$`.
- `description`: shown to approvers. Trusted, because it comes from config.
- `clients`: the client IDs that may request it.
- `approvals_required`: default 1 (D18).
- `ttl`: `{default, max, max_total}`. `max_total` caps the lifetime
  including extensions. All three are ≤ 24h.
- `step`: `off | optional | required`.
- `k8s`, `http`, `ssh`: the policy sections. Each has a scope list
  (`clusters`, `upstreams` or `targets`) and an ordered `rules` list
  (§5.8). Protocol-specific fields (`k8s.impersonate`, `ssh.logins`) are
  defined in docs/07 and docs/08.

### 5.3 Grant

#### Fields

| Field | Meaning |
|---|---|
| `id` | `gr_<ULID>` |
| `client_id` | the requesting client |
| `profile` | profile name; `profile_snapshot` is the frozen JSON (D10) |
| `reason`, `label` | free text from A. **Untrusted.** Shown to approvers escaped (INV-15). `label` is usually the thread title. |
| `requested_ttl_ms` | what A asked for, clamped to `ttl.max` |
| `state` | see below |
| `step` | effective flag, `on | off` |
| `approvals_required` | copied from the profile at request time |
| `created_at`, `activated_at`, `expires_at`, `ended_at` | timestamps; null until reached |
| `end_reason` | `expired | revoked | released | request_expired | denied` |
| `token_hash` | SHA-256 of the bearer token; set when the token is minted at first delivery (D9), `NULL` before |
| `ssh_pubkey` | the per-grant ed25519 key A registered (if the profile has an `ssh` section) |
| `credentials_delivered_at` | set when the one-time credentials were returned (D9) |

#### Effective step flag

| Profile `step` | A asks off | A asks on |
|---|---|---|
| `off` | off | off. Silently forced off, not an error; the grant reports the effective value. |
| `optional` | off | on |
| `required` | on | on |

An approver MAY turn `step` on when approving, and MAY turn it on or off
later if the profile says `optional`. Turning it off is a decision in its
own right (docs/04 §5.5).

#### State machine

```
                request                approve ×approvals_required
  (none) ──────────────▶ pending ───────────────────────────────▶ active
                            │                                       │
                     deny   │ not approved within 15 min            │ expiry / revoke / release
                            ▼                ▼                      ▼
                         denied      request_expired     expired | revoked | released
```

| From | Event | To | Requires |
|---|---|---|---|
| pending | approve | active | `approvals_required` distinct approvals, each per INV-02 |
| pending | deny | denied | one approver's deny (INV-02) |
| pending | request window elapsed | request_expired | timer |
| active | `expires_at` reached | expired | timer |
| active | revoke | revoked | an approver's revoke (docs/04), or `grant.revoke` on the admin socket |
| active | release | released | A, with the grant token |

`active` is the only state in which any operation runs. Every transition
is a compare-and-set (D3). Leaving `active` triggers teardown (§5.17).
Pending steps and extensions of a grant that leaves `active` become
`expired`, and their waiters get an error.

### 5.4 Step (held operation)

When `step` is on, every **mutating** operation is held. A `confirm` rule
holds an operation regardless of the step flag (§5.8.5). A step records
one held operation:

| Field | Meaning |
|---|---|
| `id` | `st_<ULID>` |
| `grant_id`, `session_id` | parent grant; the `ss_` if it belongs to one |
| `kind` | `k8s | http | ssh` |
| `summary` | the operation as **G parsed it** (verb, resource, name, namespace; method and path; command), not as A described it |
| `detail` | JSON: redacted body digest and similar. Never a secret. |
| `state` | `pending | approved | denied | expired` |
| `decided_by`, `decided_at`, `via_allowance` | outcome |

A step times out to `expired` after 5 min, and the operation fails with
`step_expired`. A step approval authorizes exactly its own operation and
is never reused (INV-17). Each protocol doc defines what counts as
mutating: docs/06 §5.3, docs/07 §5.4 and docs/08 §5.5.

### 5.5 Allowance

An allowance stops a node drain from costing forty taps. When an approver
approves a step, they MAY also create an allowance: a matcher plus a
lifetime. While it is live, matching holds pass without a new tap.

| Field | Meaning |
|---|---|
| `id` | `al_<ULID>` |
| `grant_id`, `kind` | scope |
| `matcher` | a match expression in the §5.8 grammar, built by G from the approved operation (docs/04 §5.5 lists the offered variants) |
| `rule_index` | the rule in the grant's snapshot that held the approved operation. The allowance applies only to operations whose first matching rule is this one |
| `expires_at` | ≤ the grant's `expires_at` |
| `created_by`, `revoked_at` | provenance |

An allowance only short-circuits a **hold**, and only a hold by its own
rule. It never overrides a `deny` or the scope check, and it can't carry
an approval from one rule over to another rule's operations (INV-17).
The snapshot is frozen (D10), so `rule_index` stays meaningful for the
grant's lifetime. Operations that pass through an allowance
are audited with `via_allowance`.

### 5.6 Session

A session (`ss_`) is one proxied connection that carries a stream: an SSH
connection, a Kubernetes exec, attach or port-forward, or a long watch.
It gives recording and teardown a handle. Fields: `id`, `grant_id`,
`kind` (`ssh | k8s-exec | k8s-portforward | k8s-watch`), `target`,
`opened_at`, `closed_at`, `close_reason` and `recording_path`. A plain
request/response call is an operation, not a session, and is audited all
the same.

### 5.7 Timers and extension

| Timer | Default | Config key |
|---|---|---|
| Request window | 15 min | `timers.request` |
| Extension window | 10 min | `timers.extension` |
| Step timeout | 5 min | `timers.step` |
| Grant TTL | per profile | `profiles[].ttl.{default,max,max_total}` |
| Teardown bound | 2 s | none (INV-07) |

Durations use the monotonic clock. Absolute expiries use the wall clock.
G MUST be NTP-synced (docs/09).

**Extension.** A calls extend with `ttl_minutes`, which creates a pending
`ex_`. An approver approves it within the extension window (docs/04).
When approved:

```
new_expiry = min(now + requested_ttl,
                 now + snapshot.ttl.max,
                 grant.activated_at + snapshot.ttl.max_total)
```

`new_expiry` MUST be strictly greater than the current `expires_at`;
otherwise the extension is rejected as `extension_noop`. An extension
changes only the lifetime, never scope or flags.

### 5.8 Policy engine

#### 5.8.1 Operation

Each proxy parses a request into one `Operation`:

```go
type Operation struct {
    Kind     string // "k8s" | "http" | "ssh"
    Mutating bool   // set by the proxy per its doc; drives step mode

    // k8s (docs/07 §5.3)
    Verb, Group, Resource, Namespace, Name, Cluster string // Resource may be "pods/exec"
    // http (docs/06 §5.3)
    Method, Path, Upstream string
    // ssh (docs/08 §5.5)
    SSHType   string // "shell" | "exec" | "subsystem" | "direct-tcpip"
    Command   string
    Subsystem string
    Host      string // direct-tcpip
    Port      uint16 // direct-tcpip
    Login, Target string
}
```

#### 5.8.2 Rules

A rule is `{ match: "<expr>", action: allow | deny | confirm }`. The
grammar depends on the section:

- **k8s**: `<verbs> <resource>[/<subresource>] [-n <namespace>] [<name>]`
  - `<verbs>` is a comma list or `*`.
  - `**` as the resource means any resource.
  - `-n` is omitted for cluster-scoped or "any".
  - Examples: `get,list,watch **`, `patch nodes`, `create pods/eviction -n *`,
    `* secrets`, `delete pods -n shop web-*`, `exec pods/exec -n shop web-*`.
- **http**: `<METHOD> <path-pattern>`
  - `<METHOD>` is one method or `*`.
  - The path is relative to the upstream's base and has a leading `/`.
  - Examples: `GET /realms/acme/users/**`, `POST /realms/acme/users`,
    `* re:/realms/[^/]+/users`.
- **ssh**: `shell` | `exec: <command-glob>` | `subsystem: <name-glob>` |
  `direct-tcpip: <host-glob>:<port-glob>`
  - Examples: `exec: apt-get -y upgrade*`, `subsystem: sftp`,
    `direct-tcpip: 10.0.1.*:5432`.

SSH command matching is a **guardrail, not a boundary**
([`SECURITY.md`](../SECURITY.md) RR-4). Once a shell is allowed, anything
runs.

#### 5.8.3 Glob semantics (normative)

There is one `match(pattern, value)`:

- **`*`**
  - In names, resources, verbs, hosts and commands: any run of characters
    except that token's delimiter (`/` in resources).
  - In paths: exactly one segment.
- **`**`**: any run of characters including delimiters. In paths it
  matches any number of segments, including zero. A trailing `/**`
  matches the path before it and every path below it: `/a/**` matches
  `/a`, `/a/b` and `/a/b/c`.
- **`re:`**: the remainder is an RE2 regex, anchored at both ends
  (`^…$`).
- **Case**: matching is case-sensitive, except that HTTP methods and k8s
  verbs are compared in lowercase.
- **No wildcard**: a pattern without one must equal the value exactly.
- **Control and bidi characters** (the INV-15 set) in a value are matched
  as themselves, never stripped. A `deny` written for `web-0` must not be
  bypassed by `web-0` with a zero-width character appended. To make sure
  of that, a value containing control, bidi or zero-width characters
  fails every `allow` and `confirm` pattern that has no wildcard at that
  position.

Patterns are parsed and compiled at config load. An unparseable pattern
fails startup.

#### 5.8.4 `ruleMatches`

```
k8s:  verbs ∋ op.Verb  AND match(resPat, op.Resource)
      AND (nsPat empty OR match(nsPat, op.Namespace))
      AND (namePat empty OR match(namePat, op.Name))
http: methodMatches(op.Method) AND match(pathPat, op.Path)
ssh:  shell: op.SSHType == "shell"
      exec: op.SSHType == "exec" AND match(cmdGlob, op.Command)
      subsystem: op.SSHType == "subsystem" AND match(nameGlob, op.Subsystem)
      direct-tcpip: op.SSHType == "direct-tcpip" AND match(hostGlob, op.Host) AND match(portGlob, op.Port)
```

An allowance matcher uses the same grammar and the same `ruleMatches`.

#### 5.8.5 Evaluation (normative)

```
Evaluate(grant, op) -> Decision{Action, Rule, Reason}

1. grant.state != active                  -> DENY grant_not_active     (INV-06)
2. now >= grant.expires_at                -> DENY grant_expired        (INV-07)
3. section = grant.snapshot.section(op.Kind)
4. op's cluster/upstream/target not in section scope -> DENY out_of_scope  (INV-18)
5. k8s implicit allows (docs/07 §5.6)     -> ALLOW implicit
6. decision = DENY default_deny                                         (INV-08)
   for i, rule in section.rules:          // first match wins
       if ruleMatches(rule, op): decision = {rule.action, Rule: i}; break
7. decision == DENY                       -> DENY (rule or default_deny)
8. needHold = decision == CONFIRM OR (grant.step AND op.Mutating)
9. needHold:
     live allowance with rule_index == decision.Rule
       and ruleMatches(allowance.matcher, op) -> ALLOW via_allowance    (INV-17)
     else                                 -> HOLD
10. -> ALLOW
```

`confirm` and `step` compose. `confirm` always holds. `step` also holds
any mutating operation that a rule allowed. A read that a rule allowed
passes even with `step` on. `Evaluate` is pure: it doesn't block, write or
call anything. The gate (§5.9) performs a HOLD.

`Describe(section) []string` renders the parsed rules as lines for the
approval message, for example `create pods/eviction in any namespace →
confirm`. It is generated from the parsed rules, so the approver sees
what is enforced.

#### 5.8.6 Test vectors (MUST pass)

Profile `k8s-node-maint` (§5.15.5):

| Operation | Expected |
|---|---|
| `get pods -n shop` on `prod` | ALLOW (`get,list,watch **`) |
| `watch nodes` | ALLOW |
| `patch nodes node-1` | ALLOW (`patch nodes`) |
| `patch nodes/status node-1` | DENY: default, because `nodes` ≠ `nodes/status` |
| `create pods/eviction -n shop web-0` | HOLD (`confirm`) |
| the same, with a live allowance `create pods/eviction -n *` bound to that rule | ALLOW `via_allowance` |
| `get secrets -n shop` | DENY (`* secrets`) |
| `delete pods -n shop web-0` | DENY: default |
| `exec pods/exec -n shop web-0` (WebSocket `GET`, docs/07 §5.3) | DENY: default. Regression vector for the connect-subresource gotcha |
| any operation on cluster `dev` | DENY `out_of_scope` |

Profile `keycloak-users` (`step: required`):

| Operation | Expected |
|---|---|
| `GET /realms/acme/users?max=10` | ALLOW: a read, not held despite step |
| `POST /realms/acme/users` | HOLD |
| `PUT /realms/acme/users/abc/reset-password` | HOLD |
| `DELETE /realms/acme/users/abc` | DENY (`DELETE **`) |
| `POST /realms/other/users` | DENY: default |
| `PUT /realms/acme/users/abc`, with a live allowance `PUT /realms/acme/users/**` bound to the `reset-password` rule | HOLD: the allowance's rule isn't the first match |

An SSH profile with rules `[exec: apt-get -y upgrade* → confirm, shell → confirm]`:

| Operation | Expected |
|---|---|
| `exec: apt-get -y upgrade` | HOLD |
| `exec: rm -rf /` | DENY: default |
| `shell` | HOLD |
| `subsystem: sftp` | DENY: default |
| `direct-tcpip: 10.0.1.5:5432` | DENY: default |

Edge cases the tests MUST also cover:

- An empty rule list denies everything.
- `**` as the resource, combined with a specific verb.
- `*` against `**` in paths (`/users` against `/users/x/y`).
- Method `*`.
- `re:` anchoring: `re:/users` must not match `/users/x`.
- Zero-width and bidi characters must not bypass a `deny`.
- Trailing-slash normalization agrees with docs/06 §5.2.
- The `k8s-node-maint` rules with `* secrets → deny` moved after
  `get,list,watch **` fail validation as a shadowed deny (§5.15.6). This
  is the regression vector for the ordering mistake found in review of
  PR #1. So does `get,list,watch ** -n kube-system → allow` placed
  before `* secrets → deny`. The same rules with `get secrets -n shop
  app-config → allow` placed first still validate, because that rule is
  a subset of the deny.
- `POST /realms/acme/** → allow` before `POST /realms/acme/users →
  confirm` fails validation as a shadowed hold.

### 5.9 The decision point (gate)

```go
package gate

type Permit struct{ grantID, opID string; via string } // unexported fields (D5)

// Authorize is the only producer of Permit. Every forwarder takes one.
func (g *Gate) Authorize(ctx context.Context, grant *grants.Active, op policy.Operation) (Permit, error)
```

`Authorize` does the following, in order:

1. Calls `policy.Evaluate`.
2. On DENY, returns a typed error (`codes.PolicyDenied`, `codes.OutOfScope`, …).
3. On HOLD, creates a step and hands it to the approval notifier
   (docs/04). It then waits until one of these happens:
   - the step is decided;
   - the 5 min timeout passes;
   - the grant context is cancelled, in which case it returns
     `codes.GrantNotActive`.
4. Appends `op.start` to the audit log. This must succeed, or the call
   returns `codes.AuditUnavailable` (INV-10).
5. Returns a Permit carrying the operation ID that `op.end` will
   reference.

The forwarder calls `gate.Finish(permit, result)` when the operation
ends, which appends `op.end`.

Review rule: an upstream dial or `RoundTrip` that is reachable without a
`Permit` in scope is a finding (CODE-REVIEW "bypass hunt").

### 5.10 Where R4 plugs in (not implemented here)

The AI assessment (R4) would run inside `Authorize`, between step 1 and
step 3. It sees the operation, the grant and recent history, and may only
move a decision *toward* human review: ALLOW → HOLD. Whether it may ever
satisfy a hold itself is R4's question to settle (CLAUDE.md, "the model
advises; policy decides"). Nothing in R2 reserves an interface for it.

### 5.11 Client identity and the internal CA

G runs an internal CA (ECDSA P-256), which signs G's agent-listener
server certificate and A's client certificates. It is generated by
`nyyrikki init-pki` (docs/09).

**Enrolment** (the key is generated on A and never leaves it):

1. On G: `nyyrikki client enroll cl_agent_vm_a` prints a one-time
   enrolment token `nye_<secret>` (TTL 30 min, stored hashed) and the
   internal CA's SHA-256 fingerprint.
2. On A: `nyyrikki-mcp enroll --server nyyrikki.internal:8443 --token nye_… --ca-sha256 <fp>`
   (docs/05) generates the key, pins the server certificate's chain to
   the fingerprint, and POSTs a CSR to `/v1/enroll`.
3. G checks the token (unused, unexpired, for this client), checks the
   CSR signature (M3), and signs a client certificate with CN `<client
   id>`, 90 days, ExtKeyUsage clientAuth. It records the serial and the
   SPKI SHA-256 in `client_certs` and marks the token used, all in one
   transaction.

**Renewal.** When less than 20% of the certificate's lifetime remains, A
POSTs a new CSR to `/v1/enroll/renew` over mTLS with its current
certificate. The old serial stays valid until its `not_after`. A disabled
client, or a revoked certificate, cannot renew.

**Checks on every connection and every request** (D7). The certificate
MUST:

- chain to the internal CA;
- carry a serial that is in `client_certs`, not revoked and in validity;
- map to a client that is `enabled` in config.

Additionally, the source address MUST be in the client's `source_cidrs`,
if set. The checks run in `VerifyConnection` and again per request
against the in-memory index. The index updates on revoke, disable and
reload. `SessionTicketsDisabled: true`.

### 5.12 Grant credentials

Grant credentials are minted at the first read after activation and
returned once (D9). An active grant whose `token_hash` is still `NULL`
accepts no token.

- **Bearer token**: `nyg_<grantId>_<secret>`, where `<secret>` is 32
  bytes from `crypto/rand` in Crockford base32. G stores
  `SHA-256(token)`. Lookup:
  1. parse the `grantId` out of the token;
  2. load the active grant;
  3. require `client_id` == the mTLS identity;
  4. compare the hashes with `subtle.ConstantTimeCompare`.

  Used as `Authorization: Bearer` for `/k8s/…`, `/u/…` and `extend`.
  `release` doesn't need it (D9).
- **Per-grant SSH key**: `nyyrikki-mcp` generates an ed25519 key pair on
  A when it requests a profile that has an `ssh` section, and sends the
  public key with the request. G indexes active grants by that key for
  the SSH listener (docs/08). The key authenticates A *to G* only and is
  never presented to a target.

### 5.13 Control API (`/v1`, agent listener `:8443`)

**Conventions**

- JSON in and out, strictly decoded (D17).
- Times are RFC 3339 UTC with milliseconds.
- Errors are `{"error":{"code":"snake_case","message":"…","retriable":bool}}`.
  The codes come from `internal/codes`.
- Every response carries `X-Nyyrikki-Request-Id` (a ULID), which audit
  events reference.

**Error codes**

| Code | HTTP | Meaning |
|---|---|---|
| `unauthenticated` | 401 | no valid client certificate, or bad token |
| `client_disabled` | 403 | |
| `profile_forbidden` | 403 | profile unknown or not permitted for this client (one code, so the response doesn't reveal which profiles exist) |
| `invalid_request` | 400 | |
| `grant_not_found` | 404 | unknown, or not this client's |
| `grant_not_active` | 409 | |
| `request_expired` | 410 | |
| `denied` | 403 | an approver denied it |
| `step_denied` / `step_expired` | 403 / 408 | |
| `extension_noop` | 409 | |
| `policy_denied` / `out_of_scope` | 403 | |
| `audit_unavailable` | 503 | INV-10, D4 |
| `busy` | 503 | audit back-pressure (docs/03 D5) |
| `rate_limited` | 429 | |

The protocol-specific codes are introduced in their docs:

- docs/06: `invalid_path`, `method_not_allowed`, `upstream_auth_failed`,
  `upstream_redirect_offsite`;
- docs/07: `spdy_exec_denied`.

Every code is a constant in `internal/codes`, and nowhere else (D13).

**Endpoints**

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/enroll`, `POST /v1/enroll/renew` | enrolment token / mTLS | §5.11 |
| `GET /v1/profiles` | mTLS | profiles this client may request: name, description, ttl, step, capability summary |
| `POST /v1/grants` | mTLS | request a grant (below) |
| `GET /v1/grants/{id}` | mTLS (owning client) | state, expiry, effective step, approvals, approval delivery status (docs/04 §5.9), and the one-time `credentials` |
| `GET /v1/grants/{id}/wait?since=<state>&timeout_ms=` | mTLS | long-poll, at most 55 000 ms. Returns on a state change or at the timeout, always with the current state |
| `POST /v1/grants/{id}/extend` | mTLS + token | `{ttl_minutes}`, returns `202 {extension}` |
| `POST /v1/grants/{id}/release` | mTLS (owning client) | active → released. Idempotent. No token, so a grant whose credentials were lost can still be ended (D9) |
| `GET /v1/grants/{id}/steps` | mTLS + token | pending steps, for the agent's visibility. **Cannot approve anything** |

**`POST /v1/grants` request**

```json
{ "profile": "k8s-node-maint",
  "reason": "Upgrade containerd on prod nodes one by one",
  "label": "thread: prod containerd upgrade",
  "ttl_minutes": 60,
  "want_step": false,
  "ssh_pubkey": "ssh-ed25519 AAAA… nyyrikki-grant" }
```

Rules:

- `ttl_minutes` is clamped to `[1, ttl.max]`.
- `ssh_pubkey` is required if and only if the profile has an `ssh`
  section, and it MUST be ed25519.
- `reason` and `label` are capped at 4 KiB each, and the body at 64 KiB.

Response `201`:

```json
{"grant":{"id":"gr_…","state":"pending","approvals_required":1},
 "approval":{"channel":"telegram"},"poll_after_ms":1000}
```

**Credentials** come back in the first `GET`/`wait` response after
activation, and never again:

```json
"credentials": {
  "token": "nyg_gr_…_…",
  "k8s":  [{"cluster":"prod","server":"https://nyyrikki.internal:8443/k8s/prod"}],
  "http": [{"upstream":"keycloak-admin","base":"https://nyyrikki.internal:8443/u/keycloak-admin"}],
  "ssh":  {"proxy":"nyyrikki.internal:2222","host_key":"ssh-ed25519 AAAA…","targets":["node-1"]} }
```

The read that delivers them runs one transaction: a compare-and-set on
`credentials_delivered_at IS NULL` (D3) that also sets `token_hash` to
the SHA-256 of a freshly generated token. Only the request that wins the
compare-and-set gets the plaintext, and only after the commit. If the
transaction fails, no token exists, and the next read tries again. If
the response is lost after the commit, the token is unrecoverable by
design, and A releases (D9).

**Limits**

- A per-client token bucket on `POST /v1/grants`: 10 per minute, burst 5.
- `wait` requests are capped at 32 concurrent per client.
- Handlers run under the grant context, so teardown interrupts them.

### 5.14 Admin socket

The admin socket is `/run/nyyrikki/admin.sock`, mode `0660`, group
`nyyrikki-admin`. It speaks newline-delimited JSON RPC, and the
`nyyrikki` CLI is its client.

| Command | Effect |
|---|---|
| `status` | listeners, counts, versions, `audit_degraded` |
| `config.validate`, `config.reload` | §5.15.7 |
| `client.enroll {id}`, `client.list`, `client.disable {id}`, `client.revoke-cert {serial}` | clients |
| `approver.pair {id}`, `approver.list`, `approver.unpair {id}` | approvers ([docs/04](04-telegram-escalation.md) §5.2) |
| `grant.list {state?}`, `grant.revoke {id}` | revoke is de-escalating, audited with `by: "admin"` |
| `audit.verify {from,to}` | [docs/03](03-audit-log.md) §5.5 |

There is no command that activates a grant, approves a step, or widens
scope (INV-16). A test enumerates the command table to keep it that way.

### 5.15 Configuration

`nyyrikkid --config /etc/nyyrikki/nyyrikki.yaml`. This section defines
the core keys. The other docs define theirs: `audit` and `recordings` in
docs/03, `telegram` and `approvers` in docs/04, `http_upstreams` in
docs/06, `k8s_clusters` in docs/07, and `ssh_targets` plus
`pki.ssh_user_ca` in docs/08. docs/09 has a complete example.

#### 5.15.1 Top level

```yaml
server:   { ... }
storage:  { sqlite_path: "/var/lib/nyyrikki/nyyrikki.db" }
pki:      { internal_ca: { ... } }
timers:   { request: 15m, extension: 10m, step: 5m }
clients:  [ ... ]
profiles: [ ... ]
# + audit, recordings, telegram, approvers, http_upstreams, k8s_clusters, ssh_targets
```

#### 5.15.2 `server`

```yaml
server:
  agent_listener:    { addr: ":8443", server_name: "nyyrikki.internal" }
  ssh_listener:      { addr: ":2222" }          # docs/08
  admin_socket:      "/run/nyyrikki/admin.sock"
  metrics:           { enabled: true, addr: "127.0.0.1:9442" }
```

If `metrics.enabled` is set, `addr` MUST be loopback.

#### 5.15.3 `pki.internal_ca`

```yaml
pki:
  internal_ca:
    cert_file: "/etc/nyyrikki/pki/internal-ca.crt"
    key_file:  "/etc/nyyrikki/pki/internal-ca.key"   # 0600, owned by nyyrikki
    client_cert_ttl: 90d
    server_cert_ttl: 90d
```

#### 5.15.4 `clients`

```yaml
clients:
  - id: cl_agent_vm_a
    display_name: agent-vm-a
    enabled: true
    source_cidrs: ["10.20.0.5/32"]   # single addresses; required for ssh profiles
```

#### 5.15.5 `profiles`

```yaml
profiles:
  - name: k8s-node-maint
    description: "Drain, upgrade and uncordon prod nodes one at a time."
    clients: [cl_agent_vm_a]
    ttl: { default: 60m, max: 2h, max_total: 4h }
    step: optional
    k8s:
      clusters: [prod]
      impersonate: { user: "nyyrikki:k8s-node-maint", groups: ["nyyrikki:node-maint"] }   # docs/07
      rules:                                          # first match wins
        - { match: "* secrets",                 action: deny }      # before the read rule
        - { match: "get,list,watch **",         action: allow }
        - { match: "patch nodes",               action: allow }     # cordon / uncordon
        - { match: "create pods/eviction -n *", action: confirm }   # drain
    ssh:
      targets: [node-1, node-2]
      logins: [root]                                                # docs/08
      rules:
        - { match: "exec: apt-get -y upgrade*", action: confirm }
        - { match: "exec: systemctl restart *", action: confirm }
        - { match: "shell",                     action: confirm }

  - name: keycloak-users
    description: "Create and disable users, reset passwords in realm acme."
    clients: [cl_agent_vm_a]
    ttl: { default: 30m, max: 1h, max_total: 2h }
    step: required
    http:
      upstreams: [keycloak-admin]
      rules:
        - { match: "GET /realms/acme/users/**",                 action: allow }   # includes /realms/acme/users
        - { match: "POST /realms/acme/users",                   action: confirm }
        - { match: "PUT /realms/acme/users/*",                  action: confirm }
        - { match: "PUT /realms/acme/users/*/reset-password",   action: confirm }
        - { match: "DELETE **",                                 action: deny }
```

A missing section means "nothing in this protocol". There is no need to
write empty sections.

#### 5.15.6 Validation (MUST, at startup and on reload)

- **Decoding**: strict. An unknown key fails, at any level (D16).
- **Profiles**:
  - names are unique and match the §5.2 pattern;
  - every ID in `clients` exists;
  - every client named by a profile with an `ssh` section has
    `source_cidrs`, and every entry is a single address (`/32` or
    `/128`). The SSH listener has no client certificate, so the
    per-grant key alone authenticates, and the address is its only
    binding to A (docs/08 D2, SECURITY.md RR-1). `0.0.0.0/0` would meet
    a bare "required" without binding anything;
  - `approvals_required` ≥ 1 and ≤ the number of paired-or-configured
    approvers;
  - `ttl.default` ≤ `ttl.max` ≤ `ttl.max_total` ≤ 24h;
  - `step` is one of `off`, `optional`, `required`;
  - every cluster, upstream and target referenced exists;
  - every rule parses (§5.8.2);
  - a profile that allows nothing logs a warning.
- **Shadowed denies and holds**: with first match wins, an earlier
  `allow` or `confirm` takes precedence over a later `deny` for every
  operation they both match, and an earlier `allow` does the same to a
  later `confirm`. The approver would be shown a deny or a hold that is
  never enforced. G compares each `deny` with every earlier non-deny
  rule, and each `confirm` with every earlier `allow`, field by field:
  - **subset**: the earlier rule's verbs (k8s) or method (http) are
    among the later rule's, or the same SSH request type, and in every
    other field the later rule is at least as broad. A field is at
    least as broad as another when it is equal, a bare wildcard (`*`
    verbs or method, `**` resource, `*` namespace, name, command or
    host), omitted (`-n`, name), or a path ending in `/**` whose literal
    prefix the other path starts with;
  - **overlap**: the verbs or methods intersect (or the SSH type is the
    same), and in every other field one side is at least as broad as the
    other;
  - **undecided**: a field pair that neither rule covers by the above,
    because of partial globs or `re:`.

  The earlier rule passes if it is a **subset** of the later one: that
  is a deliberate carve-out, such as `get secrets -n shop app-config →
  allow` before `* secrets → deny`. Any other **overlap** fails
  validation, naming both rules. So `get,list,watch ** → allow` before
  `* secrets → deny` fails, because it allows `get secrets`. So does
  `get,list,watch ** -n kube-system → allow` before the same deny:
  being narrower in one field doesn't make a rule a subset.
  **Undecided** pairs log a warning. The lint is not a proof, which is
  why the §5.8.6 vectors
  exist.
- **Protocol-specific rules** live in docs/06–08.
- **Secrets**: a value ending in `_file` is a path, `_env` is an
  environment variable, and `_ref` is a `secret://<name>` reference
  resolved from `/etc/nyyrikki/secrets/<name>` (mode `0600`). Literal
  secrets in the YAML are not supported. Resolved values are held in
  memory and never logged or audited.
- **Files**: key and secret files MUST be mode `0600` and owned by the
  service user. G refuses to start otherwise.

#### 5.15.7 Reload

`nyyrikki config.reload` re-reads and re-validates the file. If it passes,
G atomically swaps clients, profiles, approvers and targets. Active
grants keep their snapshot (D10). If it fails, G keeps the running config
and returns the error.

Reload also re-resolves every secret reference that targets use: upstream
credentials (docs/06), cluster credentials (docs/07) and anything the
SSH targets reference (docs/08). A cached OAuth2 token is dropped when
its upstream's credential changes. A secret that no longer resolves fails
the reload, like any other validation error.

These need a restart, which keeps active grants (docs/09 D6):

- listener addresses;
- the PKI: the internal CA, G's server certificate, the SSH user CA and
  the SSH proxy host key;
- the Telegram bot token, because G checks it with `getMe` and the
  webhook check at startup (docs/04 §5.1).

#### 5.15.8 Knobs and where they are consumed

| Key | Consumed by (production call site) |
|---|---|
| `server.agent_listener.addr`, `.server_name` | `server.Run` → `controlapi.Listen` |
| `server.admin_socket` | `server.Run` → `adminapi.Listen` |
| `server.metrics.*` | `server.Run` → `metrics.Listen` |
| `storage.sqlite_path` | `store.Open` |
| `pki.internal_ca.*` | `pki.LoadInternalCA` → `controlapi` TLS config, `pki.SignClientCSR` |
| `timers.request`, `timers.extension`, `timers.step` | `grants.Manager` (request, extension) and `steps.Broker` (step) |
| `clients[]` | `identity.Index` (per-request check) and `grants.Manager.Request` |
| `profiles[]` | `config.Snapshot` → `grants.Manager.Request` (snapshot) → `policy.Compile` |

There are no flags or environment variables besides `--config`. Every
key above has a test asserting that changing it changes behaviour at its
call site (CODE-REVIEW "knobs fully plumbed").

### 5.16 Data model

SQLite in WAL mode, `foreign_keys=ON`, `busy_timeout=5000`. Times are
INTEGER Unix milliseconds. Migrations are embedded, forward-only and
gated by `schema_meta.version`. If the DB is newer than the binary, G
refuses to start. This doc owns migration `0001_core.sql`. docs/04 owns
`0002_telegram.sql`.

```sql
CREATE TABLE clients_runtime (         -- runtime state; identity is in config
  id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);

CREATE TABLE client_certs (
  serial TEXT PRIMARY KEY, client_id TEXT NOT NULL,
  not_before INTEGER NOT NULL, not_after INTEGER NOT NULL,
  spki_sha256 TEXT NOT NULL, revoked_at INTEGER, created_at INTEGER NOT NULL);
CREATE INDEX idx_cc_client ON client_certs(client_id);

CREATE TABLE enrollments (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL);

CREATE TABLE grants (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, profile TEXT NOT NULL,
  profile_snapshot TEXT NOT NULL,                   -- JSON (D10)
  reason TEXT, label TEXT, requested_ttl_ms INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','active','denied','request_expired','expired','revoked','released')),
  step INTEGER NOT NULL DEFAULT 0, approvals_required INTEGER NOT NULL DEFAULT 1,
  token_hash TEXT, ssh_pubkey TEXT, credentials_delivered_at INTEGER,
  created_at INTEGER NOT NULL, activated_at INTEGER, expires_at INTEGER,
  ended_at INTEGER, end_reason TEXT);
CREATE INDEX idx_grants_client_state ON grants(client_id, state);
CREATE INDEX idx_grants_state_exp ON grants(state, expires_at);
CREATE UNIQUE INDEX idx_grants_active_sshkey ON grants(ssh_pubkey) WHERE state = 'active';

CREATE TABLE grant_approvals (
  grant_id TEXT NOT NULL REFERENCES grants(id), approver_id TEXT NOT NULL,
  decided_at INTEGER NOT NULL, PRIMARY KEY (grant_id, approver_id));

CREATE TABLE extensions (
  id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id),
  requested_ms INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','expired')),
  old_expiry INTEGER, new_expiry INTEGER, decided_by TEXT,
  created_at INTEGER NOT NULL, decided_at INTEGER);

CREATE TABLE steps (
  id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id), session_id TEXT,
  kind TEXT NOT NULL, summary TEXT NOT NULL, detail TEXT,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','expired')),
  decided_by TEXT, via_allowance TEXT, created_at INTEGER NOT NULL, decided_at INTEGER);
CREATE INDEX idx_steps_grant_state ON steps(grant_id, state);

CREATE TABLE allowances (
  id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id),
  kind TEXT NOT NULL, matcher TEXT NOT NULL, rule_index INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id),
  kind TEXT NOT NULL, target TEXT NOT NULL, opened_at INTEGER NOT NULL,
  closed_at INTEGER, close_reason TEXT, recording_path TEXT);

CREATE TABLE schema_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
```

**Rules for the DB layer**

- Handlers never issue raw `UPDATE`s. Transitions go through
  `store.Transition…`, which performs the compare-and-set (D3) and the
  audit ordering (D4).
- Only hashes of tokens are stored.
- Grant, step, extension and session rows are never deleted.

**Janitor**, every 10 minutes:

- expires active grants past `expires_at` (a backstop to the timer);
- expires pending steps and extensions;
- deletes used or expired enrolment rows older than 7 days.

**On-disk layout**

```
/etc/nyyrikki/      nyyrikki.yaml, pki/, secrets/
/var/lib/nyyrikki/  nyyrikki.db (+ -wal, -shm), audit/, recordings/   (docs/03)
/run/nyyrikki/      admin.sock
```

Directories are mode `0700` and files `0600`, owned by `nyyrikki`. The
admin socket is the exception (§5.14).

### 5.17 Concurrency and teardown

- `grants.Manager` owns the in-memory index of active grants, keyed by
  ID, by token hash and by SSH key, along with a per-grant
  `context.CancelFunc`.
- Every privileged action runs under `Manager.Context(grantID)`.
- An event bus fans out per-grant events to `wait` long-polls and to the
  approval notifier.
- **Teardown** (D15) runs in this order:
  1. commit the state with a compare-and-set;
  2. remove the token and SSH-key index entries;
  3. cancel the context, which makes the copy loops in sessions return;
  4. close the sessions;
  5. audit `grant.ended`.

  The whole sequence MUST complete within 2 s (INV-07).
- **Restart**: G reloads active grants from the DB and rebuilds the index
  and timers. Pending grants and pending extensions keep their windows,
  and their timers are rebuilt too: A's `wait` reconnects. Sessions that
  were open are recorded as closed with `close_reason: restart`.
- **Pending steps are expired on startup** (`step_expired`, reason
  `restart`), and their prompts are retired (docs/04 D9). The connection
  that was holding the operation died with the old process, so an
  approval could no longer let anything through, and "Approve + allow"
  would create an allowance with no live operation behind it.

## 6. Security considerations

- **New trust boundaries and inputs.** Everything from A is untrusted:
  the TLS client certificate, the token, and every request field. Where
  each is validated:
  - the certificate: §5.11, on every connection and every request;
  - the token: §5.12;
  - request bodies: strict decoding, caps, and escaping where rendered
    (docs/04);
  - the profile name: checked against the client's permitted profiles;
  - TTL: clamped.

  A cannot influence scope, impersonation identity, upstreams or targets
  (INV-18). Config is trusted (root on G) but still strictly validated,
  so mistakes fail closed.
- **How each dependency failure ends in deny.**
  - SQLite: an error returns a typed code, and nothing transitions.
  - Audit: D4, plus `audit_degraded`.
  - Timer scheduler: the janitor is the backstop, and `Evaluate` step 2
    checks expiry on every operation regardless of timers.
  - Approval channel down: grants stay pending and expire, with no
    implicit allow (docs/04 §6).
  - Clock skew: absolute expiry uses NTP-synced wall time (docs/09
    monitors it).
- **What reaches the model, the audit log and Telegram.**
  - The model: nothing yet (R4).
  - Audit (docs/03): grant fields, parsed operations and decisions.
    Never tokens, keys or resolved secrets.
  - Telegram (docs/04): profile, client display name, the untrusted
    `reason` and `label` (escaped), step summaries.
- **New ways to reach an upstream.** None in this doc. It defines the
  gate that every proxy must pass through (D5).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. Config validation rejects every malformed case in §5.15.6, unknown keys and shadowed denies and holds included, and G refuses to start | table-driven test with one fixture per rule (`internal/config`) |
| G2. Only enrolled, enabled, in-CIDR clients with an unrevoked certificate connect. A revoked certificate is rejected on a resumed TLS session and on a kept-alive connection (INV-06) | integration tests: revoke mid-connection, then the next request is 401; resume after revoke is rejected |
| G3. Enrolment tokens are single-use and expire. The key never leaves A (INV-01) | integration test (concurrent double use → one success); a test asserting the server API never accepts a private key |
| G4. Grant tokens are stored hashed, bound to the client certificate, and unusable after the grant leaves `active` (INV-06, INV-09) | integration tests: wrong client certificate with a valid token → 401; after release, revoke or expiry → 401 |
| G5. Approve, deny, expire and revoke racing on one grant produce exactly one outcome (D3) | concurrency test over N rounds with the race detector |
| G6. A transition that grants access fails when the audit append fails. A transition that removes access succeeds and sets `audit_degraded`, which then blocks escalations (D4, INV-10) | integration test with an injectable failing audit sink |
| G7. Policy: every vector in §5.8.6 passes, and an empty or non-matching rule set denies (INV-08) | `internal/policy` table tests, plus a fuzz test that no random operation is allowed without a matching rule |
| G8. No forwarder can reach an upstream without a `gate.Permit` (D5) | compile-time (unexported constructor), plus an AST check in CI that `Permit{` appears only in package `gate` |
| G9. A step approval authorizes only its own operation. An allowance covers only its matcher and lifetime (INV-17) | broker tests: approval for operation A presented for operation B → deny; an expired or narrow allowance doesn't cover a broader operation |
| G10. Teardown completes within 2 s with a watch, a held step and a long-poll in flight (INV-07). A restart expires pending steps and retires their prompts, and keeps pending grants decidable | integration test with a timing assertion; a restart test with a pending step and a pending grant |
| G11. A cannot widen scope through any request field. TTL is clamped. A reload doesn't change a live grant (INV-18, D10) | API tests over every field; a reload test |
| G12. The admin socket has no command that grants or widens access (INV-16) | a test that enumerates the command table against an allowlist |
| G13. Credentials are minted and returned exactly once. A restart between activation and the first read still delivers them. `release` works without the token (D9) | a concurrent double-`wait` test across activation; a restart test in that window; a release test with mTLS only |
| G14. Every config knob in §5.15.8 changes behaviour at its call site | one test per knob |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **GC1** | `internal/config`: schema, strict decoding, validation, secret references, snapshot | G1 |
| **GC2** | `internal/store`: SQLite, `0001_core.sql`, the `Transition` compare-and-set helpers, janitor | G5 |
| **GC3** | `internal/pki` (internal CA), enrolment, the agent listener with mTLS and the per-request identity index | G2, G3 |
| **GC4** | `internal/grants`: lifecycle, timers, event bus, teardown, restart reload; token issuance | G4, G6, G10, G13 |
| **GC5** | `internal/controlapi`: `/v1` endpoints, error mapping, limits | G4, G11, G13 |
| **GC6** | `internal/policy`: grammar, matcher, `Evaluate`, `Describe`, vectors, fuzzing | G7 |
| **GC7** | `internal/gate` and `internal/steps`: the decision point, step broker, allowances | G8, G9 |
| **GC8** | `internal/adminapi` and the `nyyrikki` CLI | G12, G14 |

Ordering notes:

- docs/01 FN1 (skeleton and gates) lands first.
- docs/03 AU1 (the audit writer) must land before GC4, because the
  grant lifecycle can't exist unaudited.
- GC6 has no dependencies and can be built in parallel with GC2–GC5.
- GC7 needs GC4 and GC6. The approval side of a HOLD needs docs/04 TG3.
  Until it lands, GC7's tests decide steps through the broker's test
  hook, which is only reachable from tests (`export_test.go`).

## 9. Risks and open questions

- **RR-1 in SECURITY.md still applies**: while a grant is active,
  anything on A can use it. This doc bounds the risk with short TTLs,
  narrow profiles, step mode and instant revoke. It doesn't remove it.
- **The k8s grammar can't express label selectors or field-level
  rules.** Whether that matters will only show with real profiles.
  Kubernetes RBAC remains the hard boundary (docs/07).
- **Moderated mode is deferred** (D12). If step mode turns out too
  coarse for interactive shells, R7 picks it up.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
