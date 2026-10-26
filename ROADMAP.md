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

**Re-planned 2026-10-26 (owner decision).** This roadmap replaces the
plan adapted from the Warden design on 2026-10-25 (items R1–R12, design
docs 01–09). Nothing had been built, so that plan and its docs were
removed rather than kept; they are in git history. The R numbers below
are new and don't refer to the Warden items.

Nyyrikki is now an MCP gateway that lets AI agents run privileged
requests against target systems, each covered by a human approval on
Telegram (see `CLAUDE.md`, "Explicitly set aside"). Agents' requests pass
through to the target's own API, and Nyyrikki acts as the human the
agent works for. The first version has no model in the loop: AI risk
assessment is R8 and deferred. The measured facts in the removed docs
(Kubernetes, SSH, Telegram and MCP client behaviour) can be mined from
history, but each is re-checked before a new decision leans on it.

| # | Item | Status |
|---|------|--------|
| R1 | [Foundations: architecture, threat model, toolchain](#r1--foundations) | 💡 proposed 2026-10-25, re-scoped 2026-10-26 |
| R2 | [Gateway core: MCP tools, identity, targets, one decision point](#r2--gateway-core) | 💡 proposed 2026-10-26 |
| R3 | [Audit log](#r3--audit-log) | 💡 proposed 2026-10-25, re-scoped 2026-10-26 |
| R4 | [Pass-through, identity propagation and credential custody](#r4--pass-through-identity-propagation-and-credential-custody) | 💡 proposed 2026-10-26 |
| R5 | [Telegram escalation: one-off approvals and time-boxed elevation](#r5--telegram-escalation) | 💡 proposed 2026-10-25, re-scoped 2026-10-26 |
| R6 | [Packaging and deployment](#r6--packaging-and-deployment) | 💡 proposed 2026-10-25, re-scoped 2026-10-26 |
| R7 | [Operator surface](#r7--operator-surface) | 💡 proposed 2026-10-25 |
| R8 | [AI risk assessment](#r8--ai-risk-assessment) | ⏸️ deferred 2026-10-26 (owner decision: not in the first version) |

R2–R5 together make the first usable version. Before R5 lands, nothing
privileged can run, because nothing can be approved.

---

## R1 — Foundations

**Why**: every later item depends on decisions nobody has made yet:
language and runtime; which MCP transports Nyyrikki serves (local stdio,
remote HTTP, or both) and which MCP spec revision it targets; how an
agent proves who it is and which human it acts for; where Nyyrikki's
high-privilege credentials live and how they are protected; which kind
of target system comes first (for example Kubernetes); and what Nyyrikki
defends against, starting with its own compromise, since it holds access
to everything behind it.

**Scope**: the architecture and its rejected alternatives, the threat
model (which also fills in `SECURITY.md`), repository layout, the gates and
CI, the dependency licence policy. Claims about the MCP specification
and client behaviour are measured, not assumed (`docs/README.md`, step 3).
The design doc ends by populating the "Architecture" section of
`CLAUDE.md` with what was locked in.

**Done when**: the owner has approved the doc. The repository has CI
running the gates on an empty skeleton.

## R2 — Gateway core

**Why**: every request has to pass one place that decides correctly,
before anything can run.

**Scope**: the MCP server and its three tools:

- **List targets**: the target systems this agent may ask for, with no
  approval needed.
- **Run one request with a one-off escalation**: one request to one
  target, which waits for a human's answer unless an elevation already
  covers it.
- **Request time-boxed elevation**: a window of up to 30 minutes on one
  or more targets. Once it is approved, the agent's requests to those
  targets run without asking again until it expires.

Also: agent authentication and binding each agent to the human it acts
for; the target registry (which targets exist, and which agents and
humans may ask for each); the elevation model (scope, expiry, the 30
minute hard cap, ending early); and one decision point that every
request passes. A request is allowed only by a one-off approval of
exactly that request, or by a live elevation that matches agent, human
and target. Everything else is denied, including on any dependency
error. MCP features beyond these tools (resources, prompts, sampling)
are off.

## R3 — Audit log

**Why**: once requests run on real systems, "who asked for this, who
approved it, and what did it do?" has to be answerable after the fact.
This lands before R4 so that the first request that runs is already
recorded.

**Scope**: an append-only record of every request: agent, human
principal, target, the exact request, the identity it ran as on the
target, what covered it (which one-off approval or elevation), outcome
and result. It also records every elevation (asked for, granted, ended,
expired) and every temporary credential issued and revoked. Requests
under an elevation are recorded individually. Because the target's own
logs show the human, this log is what ties each request back to the
agent that made it. Includes redaction, retention and where the log
lives.

## R4 — Pass-through, identity propagation and credential custody

**Why**: this is what agents come to Nyyrikki for. It is also where a
mistake does damage, so it gets its own design instead of riding along
with R2.

**Scope**:

- **Pass-through**: the form an agent's request takes (for example a
  raw Kubernetes API request, or a CLI command line), how Nyyrikki
  parses it into the canonical form that approvals bind to, and how it
  forwards exactly that and nothing else. No shell, no interpolation.
  Streaming and long-lived requests (watch, exec, port-forward) are cut
  when what covers them expires.
- **Identity propagation**: acting as the exact human through
  impersonation or delegation (for example Kubernetes impersonation)
  wherever the target allows it, and what attribution looks like where
  it doesn't.
- **Credential custody**: how Nyyrikki stores the high-privilege
  credentials it holds, and how each one's blast radius is limited.
- **Issued credentials**: creating temporary credentials on a target
  when needed (an elevation window is a natural lease): scope, lifetime,
  revocation on every path, cleanup after a crash, and keeping them
  inside Nyyrikki.
- **Responses**: which part of a target's response goes back to the
  agent, and how secrets in it are redacted. Also timeouts, and what
  happens when a request partly succeeds.

## R5 — Telegram escalation

**Why**: every privileged request needs a human who can answer within
seconds from a phone, while the agent's tool call waits.

**Scope**: the approver bot; two message kinds, a one-off request
(showing the exact request as it will be forwarded) and an elevation
(showing targets, duration, agent and human); the agent's stated reason
shown as the agent's claim, never as fact; grants bound to the exact
request or elevation, the agent and an expiry; replay protection;
timeout as deny; the approver allow-list; whether the human an agent
acts for may approve that agent's requests; what the approver sees while
an elevation is live, and whether they can end it early from the chat;
and what the waiting agent sees (MCP progress or a timeout, decided
against what clients support).

## R6 — Packaging and deployment

**Why**: Nyyrikki is meant to run next to real clusters and services,
used by real agents, not just in tests.

**Scope**: images, deployment manifests or charts, how Nyyrikki's
high-privilege credentials are provisioned, granted on each target
(including the right to impersonate or issue credentials) and rotated,
how agents are given access, versioning and release automation, an
upgrade path.

## R7 — Operator surface

**Why**: editing targets and policy, and reviewing audit, approvals and
live elevations, through files and logs alone won't scale past the
first few agents and targets.

**Scope**: decided when R2–R6 show what operators actually need.

## R8 — AI risk assessment

**Deferred 2026-10-26 (owner decision)**: the first version is a plain
escalation gateway, with a human approving every privileged request. A
model is not planned until the owner picks this item up again.

**Why it may come back**: with a human approving every request,
approvals could get routine enough to be rubber-stamped. A model could
pre-screen requests, flag unusual ones, or decide routine ones under
policy.

**Scope, if picked up**: what the model sees; a strict response schema;
which requests it may decide alone (a policy question, settled in the
doc); prompt-injection defences against the agent and against what the
agent read; latency and cost; fail closed when the model is unavailable;
and the evaluation set that measures it.
