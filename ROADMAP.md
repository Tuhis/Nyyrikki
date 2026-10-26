# Roadmap

What Nyyrikki builds, in what order, and why.

**How this document is used**: each item below is deliberately high-level.
When an item is picked up, it gets its own numbered design doc in
`docs/NN-*.md` (decisions, rejected alternatives, chunks, acceptance
criteria; see [`docs/README.md`](docs/README.md)). This file then tracks
only that item's status and links to the doc. The ordering is a proposal
based on dependencies and risk, not a contract. Reordering should still be
a conscious decision, because later items assume earlier ones.

Status values: 💡 proposed · 📝 designing · 🔧 designed / in progress ·
✅ done · ⏸️ deferred · ❌ rejected. Note the date on every status change
and say what is still open. "Implemented, but the manual verification
hasn't been run" is a different status from "done".

| # | Item | Status |
|---|------|--------|
| R1 | [Foundations: architecture, threat model, toolchain](#r1--foundations) | 📝 designing 2026-10-25: [docs/01](docs/01-foundations.md) drafted. OD1 and OD2 decided; OD3 (licence) and the owner's approval of the decisions are open |
| R2 | [Grant core: agent identity, grants, policy, one decision point](#r2--grant-core) | 📝 designing 2026-10-25: [docs/02](docs/02-grant-core.md) drafted; decisions await approval |
| R3 | [Audit log and session recordings](#r3--audit-log-and-session-recordings) | 📝 designing 2026-10-25: [docs/03](docs/03-audit-log.md) drafted; decisions await approval |
| R4 | [AI risk assessment](#r4--ai-risk-assessment) | 💡 proposed 2026-10-25 |
| R5 | [Telegram escalation](#r5--telegram-escalation) | 📝 designing 2026-10-25: [docs/04](docs/04-telegram-escalation.md) drafted; OD1 (what Telegram may see) and OD2 (dual control) open |
| R6 | [Packaging and deployment](#r6--packaging-and-deployment) | 📝 designing 2026-10-25: [docs/09](docs/09-packaging-and-deployment.md) drafted; OD1 (where G runs) and OD2 (anchor sink) open |
| R7 | [Operator surface](#r7--operator-surface) | 💡 proposed 2026-10-25 |
| R8 | [Agent integration (`nyyrikki-mcp`)](#r8--agent-integration) | 📝 designing 2026-10-25: [docs/05](docs/05-agent-integration.md) drafted; decisions await approval |
| R9 | [HTTP admin-API proxy](#r9--http-admin-api-proxy) | 📝 designing 2026-10-25: [docs/06](docs/06-http-proxy.md) drafted; decisions await approval |
| R10 | [Kubernetes API proxy](#r10--kubernetes-api-proxy) | 📝 designing 2026-10-25: [docs/07](docs/07-kubernetes-proxy.md) drafted; OD1 (clusters older than 1.35) open |
| R11 | [SSH proxy](#r11--ssh-proxy) | 📝 designing 2026-10-25: [docs/08](docs/08-ssh-proxy.md) drafted; decisions await approval |
| R12 | [Human access through OIDC](#r12--human-access-through-oidc) | ⏸️ deferred 2026-10-25: [docs/01](docs/01-foundations.md) OD1 put agents first |

**Build order** (decided 2026-10-25, when the Warden design was adapted
into this repository): R1 → R2 → R3 → R5 → R8 → R9 → R10 → R11 → R6, then
R4 and R7. R12 is deferred.

- R3's audit writer (docs/03 AU1) lands before R2's grant lifecycle
  (docs/02 GC4), because nothing may run unaudited.
- R5 comes before any proxy, because in an agent-first design nothing
  happens without an approval.
- R9 is the first end-to-end slice: an agent creates a Keycloak user
  after a Telegram tap.
- R4 moved after the proxies, because it assesses operations that only
  exist once they do.

---

## R1 — Foundations

**Why**: every later item depends on decisions nobody has made yet:
language and runtime, how the gateway is deployed relative to the agent
and the services it protects, who the requester is, how approvals reach
a human, and what Nyyrikki defends against.

**Scope**: the architecture and its rejected alternatives, the threat
model (which also fills in `SECURITY.md`), repository layout, the gates and
CI, the dependency licence policy. The design doc ends by populating the
"Architecture (locked in)" section of `CLAUDE.md`.

**Done when**: the owner has approved the doc. The repository has CI
running the gates on an empty skeleton.

## R2 — Grant core

**Why**: every protocol needs the same things underneath: who A is, what
it was approved for, until when, and a single place that says yes or no
to each operation. The AI path, when it comes, has to sit on something
that already denies correctly.

**Scope**: client identity (mTLS, enrolment), profiles, grants and their
lifecycle, default-deny policy, step mode and allowances, the one
decision point every proxied operation passes through, the control API,
the admin socket, and fail closed on every dependency error.

*Revised 2026-10-25*: this item originally read "OIDC sign-in, sessions,
per-route allow and deny rules". docs/01 OD1 made agents the v1
requesters, so human sign-in moved to R12. Per-route rules became the
policy engine here.

## R3 — Audit log and session recordings

**Why**: once something other than a human acts with admin rights, "why
was this allowed?" has to be answerable after the fact. This lands
before R4 so that the first AI decision is already recorded.

**Scope**: an append-only record of every decision, with identity,
request, outcome, reason and decider. Tamper evidence, redaction,
retention and where the log lives. Recordings of terminal and exec
streams.

## R4 — AI risk assessment

**Why**: the reason Nyyrikki exists. Static rules can't tell a routine
operation inside a grant from an unusual one made with the same
credentials.

**Scope**: what context the model sees, the response schema (allow,
deny, escalate, with a reason), which decisions the model may make alone
and which need a human (a policy question, settled here),
prompt-injection defences, latency budget, caching, cost, behaviour when
the model is unavailable (fail closed), and the evaluation set that
measures it. docs/02 §5.10 marks where it plugs into the decision point:
there, the model may move a decision toward human review, and this item
decides whether it may ever do more.

## R5 — Telegram escalation

**Why**: "escalate" needs a human who can answer within seconds from a
phone.

**Scope**: the approver bot, an approve or deny message carrying enough
context to decide without leaking secrets, grants bound to request, scope
and expiry, replay protection, timeout as deny, approver allow-list, and
what the waiting requester sees. It also covers step-mode holds,
extensions and revoke.

## R6 — Packaging and deployment

**Why**: Nyyrikki is meant to run in front of real self-hosted services,
not just in tests.

**Scope**: images, deployment manifests or charts, secrets handling,
versioning and release automation, an upgrade path. docs/09 settles on a
dedicated VM with systemd and tarballs, and covers bootstrap, backup,
rotation and break-glass.

## R7 — Operator surface

**Why**: editing policy and reviewing audit and escalations through files
and logs alone won't scale past the first few services.

**Scope**: decided when R2–R5 show what operators actually need.
Candidates already known: moderated mode and a live session view
(deferred from docs/02 D12), and a recording viewer.

## R8 — Agent integration

**Why**: the agent must be able to ask for elevation from the thread
it's working in, and use the result with the tools it already knows.

**Scope**: `nyyrikki-mcp`, a stdio MCP server on A with tools to list,
request, wait, check, extend and release grants (and none to approve).
Enrolment, credential files for `kubectl`, `curl` and `ssh`, and
registration in Claude Code, Codex and T3 Code.

## R9 — HTTP admin-API proxy

**Why**: admin APIs such as Keycloak's are guarded by all-or-nothing
client secrets that must not live on A.

**Scope**: fixed upstreams, strict path normalization, method and path
rules, credential injection on G (OAuth2 client credentials, bearer,
basic, header), Keycloak as the reference upstream.

## R10 — Kubernetes API proxy

**Why**: imperative `kubectl` and node maintenance need cluster rights
that today would mean a powerful kubeconfig on A.

**Scope**: a reverse proxy that parses requests as the apiserver does,
impersonates a fixed per-profile user (RBAC stays the hard boundary),
records exec, and handles the WebSocket and SPDY streaming paths.

## R11 — SSH proxy

**Why**: SSH admin access is the most absolute and least observable kind
of access.

**Scope**: a terminating SSH proxy with per-grant keys, per-channel
policy, ephemeral certificates to targets, host-key pinning, recording
and instant teardown.

## R12 — Human access through OIDC

**Why**: the original IAP idea. Human users signing in to self-hosted
services through an identity provider, with the same policy and audit.

**Scope**: to be designed if it is picked up. *Deferred 2026-10-25* by
docs/01 OD1. Agents come first.
