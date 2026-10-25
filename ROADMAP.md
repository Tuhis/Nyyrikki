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
| R1 | [Foundations: architecture, threat model, toolchain](#r1--foundations) | 💡 proposed 2026-10-25 |
| R2 | [Proxy core: authenticate and authorize every request](#r2--proxy-core) | 💡 proposed 2026-10-25 |
| R3 | [Audit log](#r3--audit-log) | 💡 proposed 2026-10-25 |
| R4 | [AI risk assessment](#r4--ai-risk-assessment) | 💡 proposed 2026-10-25 |
| R5 | [Telegram escalation](#r5--telegram-escalation) | 💡 proposed 2026-10-25 |
| R6 | [Packaging and deployment](#r6--packaging-and-deployment) | 💡 proposed 2026-10-25 |
| R7 | [Operator surface](#r7--operator-surface) | 💡 proposed 2026-10-25 |

---

## R1 — Foundations

**Why**: every later item depends on decisions nobody has made yet:
language and runtime, how the proxy is deployed relative to the services it
protects (reverse proxy, forward-auth for an existing ingress, or both),
which identity providers are supported, and what Nyyrikki defends against.

**Scope**: the architecture and its rejected alternatives, the threat
model (which also fills in `SECURITY.md`), repository layout, the gates and
CI, the dependency licence policy. The design doc ends by populating the
"Architecture (locked in)" section of `CLAUDE.md`.

**Done when**: the owner has approved the doc. The repository has CI
running the gates on an empty skeleton.

## R2 — Proxy core

**Why**: an IAP without AI is still useful, and the AI path has to sit on
something that already denies correctly.

**Scope**: OIDC sign-in, sessions, per-route allow and deny rules, fail
closed on every dependency error, one decision point that every request
passes through.

## R3 — Audit log

**Why**: once a model is making decisions, "why was this allowed?" has to
be answerable after the fact. This lands before R4 so that the first AI
decision is already recorded.

**Scope**: an append-only record of every decision, with identity,
request, outcome, reason and decider. Includes redaction, retention and
where the log lives.

## R4 — AI risk assessment

**Why**: the reason Nyyrikki exists. Static rules can't tell a routine
request from an unusual one made with the same credentials.

**Scope**: what context the model sees, the response schema (allow, deny,
escalate, with a reason), which decisions the model may make alone and
which need a human (a policy question, settled here), prompt-injection
defences, latency budget, caching, cost, behaviour when the model is
unavailable (fail closed), and the evaluation set that measures it.

## R5 — Telegram escalation

**Why**: "escalate" needs a human who can answer within seconds from a
phone.

**Scope**: the approver bot, an approve or deny message carrying enough
context to decide without leaking secrets, grants bound to request, scope
and expiry, replay protection, timeout as deny, approver allow-list, and
what the waiting requester sees.

## R6 — Packaging and deployment

**Why**: Nyyrikki is meant to run in front of real self-hosted services,
not just in tests.

**Scope**: images, deployment manifests or charts, secrets handling,
versioning and release automation, an upgrade path.

## R7 — Operator surface

**Why**: editing policy and reviewing audit and escalations through files
and logs alone won't scale past the first few services.

**Scope**: decided when R2–R5 show what operators actually need.
