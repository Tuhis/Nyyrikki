# Project: Nyyrikki — privilege escalation gateway for AI agents

## Purpose & Context
Nyyrikki lets AI agents carry out privileged actions they can't do on their
own, such as `kubectl delete pod`. An agent reaches Nyyrikki through an
**MCP server** or an equivalent **CLI**: both offer the same operations,
and the CLI lets an agent pipe output through its shell. Nyyrikki holds high-privilege credentials for the target
systems, and the agent never sees them. Where a target supports it,
Nyyrikki uses impersonation or delegation so that the target system sees
the **exact human** the agent acts for, not Nyyrikki. When needed,
Nyyrikki also creates temporary credentials on a target system. Those
stay inside Nyyrikki too.

The agent's requests **pass through** Nyyrikki to the target's own API.
Nyyrikki doesn't offer one tool per action. Every privileged request
needs a human's approval on Telegram, given in one of two ways:

- **One-off escalation**: the approver sees that exact request and
  approves or denies it. The call waits for the answer or fails.
- **Time-boxed elevation**: the approver grants the agent a window of at
  most 30 minutes on one or more named target systems. Within that
  window, the agent's requests to those systems run without asking again.

Listing the available target systems needs no approval. Nothing else runs
without one.

Nyyrikki is a security component. A bug that runs a request it shouldn't
is the worst outcome, worse than any outage. Rules, reviews and design docs
follow from that.

Re-planned on 2026-10-26 by owner decision; see `ROADMAP.md` and
"Explicitly set aside" below.

## Where the detail lives: read these, don't mirror them here
This file holds only what a session **cannot** derive from the repo:
locked-in decisions, rationale, gotchas and prohibitions. Everything else
has one authoritative home. Read it there.

| You want | Read | Never |
|---|---|---|
| Status of every roadmap item | `ROADMAP.md` status table | copy status here |
| What to build next, and in what order | `ROADMAP.md` milestones (M0–M4) | implement a milestone before the previous one is done |
| Design and decisions for an item | its `docs/NN-*.md` | summarise it here |
| How to write a design doc | `docs/README.md` and `docs/TEMPLATE.md` | restate it here |
| What each design doc covers | `docs/README.md` (the index) | keep a second list |
| Consolidated gotchas | `docs/gotchas.md` | duplicate them here |
| Measured facts from the replaced plan | `docs/measured.md` | rely on one without re-checking it |
| Open confirmed bugs | `BUGS.md` | list them here |
| Coding and review rules, the gates | `CODE-REVIEW.md` | restate them here |
| Commit types and scopes, PR etiquette | `CONTRIBUTING.md` | restate them here |
| Threat model, reporting a vulnerability | `SECURITY.md` | restate it here |

**This table is a rule, not a courtesy.** In the sibling project `gawk`,
CLAUDE.md grew to ~1,800 lines mirroring the roadmap, the README and the
design docs. Every copy drifted: it missed shipped milestones and
contradicted itself. If you find yourself writing roadmap narrative here,
put it in the doc and link to it.

## Architecture (nothing locked in yet)
No language, framework, MCP transport, agent or human identity scheme,
credential store, impersonation or credential-issuing mechanism,
pass-through request format, or first target system type has been
chosen. Those decisions belong to R1
(`ROADMAP.md`) and its design doc, `docs/01-*.md`. When R1 locks them in,
record **only the decisions and the reasons for them** here, in the
shape of a "locked in" list, and link to the doc.

Until then, **do not write application code.** The repository holds
process and design documents only. A code change without a design doc
behind it is out of order, however small.

## Key constraints / principles to respect
- **Fail closed.** Any error, timeout, unparseable response or unreachable
  dependency (identity, Telegram, credential store, credential issuance,
  target system, audit sink) ends in deny, never allow. An approver who
  doesn't answer has denied.
- **No approval, no request.** Every privileged request is covered either
  by a one-off approval of that exact request, or by a live elevation
  window for this agent, this human and this target. There is no third
  path, and no standing allow.
- **The agent is untrusted.** Assume it is already steered by an attacker
  through a poisoned issue, log line or web page. Its requests and its
  stated reasons are input to check, never evidence that an action is
  safe.
- **Approvals come from outside the agent's reach.** Never put an
  approval surface, the Telegram bot token, or any target-system,
  admin or approval-capable credential on the machine the agent runs on
  (the agent's own token for authenticating to Nyyrikki is expected
  there: it can't approve anything or reach a target directly), and never log in to Telegram on anything the
  agent can control. Any of these lets the agent approve itself. No MCP
  tool or CLI command approves, denies or ends anything.
- **MCP and CLI are thin clients of one API.** Neither makes decisions,
  holds target credentials or offers anything the other doesn't. A
  capability added to one is added to both, and both reach the same
  decision point.
- **An approval covers exactly what it says.** A one-off approval covers
  one request, forwarded exactly as the approver saw it. An elevation
  covers the named targets, for the named agent and human, until its
  expiry, and never longer than 30 minutes. Neither is widened afterwards.
- **What the approver sees is the request itself.** The Telegram message
  shows the request as it will be forwarded, plus the agent's stated
  reason, clearly marked as the agent's claim. It never shows a
  paraphrase.
- **Telegram updates are untrusted.** A callback is not an approval until
  it is checked against the approver, the request or elevation, and its
  expiry.
- **Nyyrikki holds the target credentials; the agent never does.** That
  covers every credential for a target system or for approving,
  including the temporary credentials Nyyrikki creates on targets. The
  only credential the agent holds is its own token for authenticating to
  Nyyrikki.
  None of them is ever handed to an agent, directly, in a result or in
  an error.
  Issued credentials are scoped as narrowly and live as briefly as works,
  and they are revoked on every path.
- **The target sees the real user.** Wherever the target can impersonate
  or delegate, requests run as the human the agent is bound to. That also
  caps an elevation's blast radius at that human's own permissions. Who to
  act as comes from the authenticated binding, never from the agent.
- **Nyyrikki is the crown jewel.** It holds high-privilege access to
  everything behind it, so its own compromise is the worst case. Its
  attack surface, its dependencies and the blast radius of each
  credential are first-class design concerns, not afterthoughts.
- **Every decision is auditable.** Every request is recorded with the
  agent, the human it acts for, the target, the exact request, what
  covered it (which approval or elevation), and what it did. Requests
  made under an elevation are recorded one by one, like any others.
- **Secrets never reach logs or Telegram messages.** That covers tokens,
  kubeconfigs, API keys and the contents of secret resources.
- **Target responses reach the agent unredacted.** The response to an
  approved request is the agent's to read, as it would be for the human
  it acts for. Redacting secrets in responses is a possible future,
  optional feature (owner decision 2026-10-26, `ROADMAP.md` R9), not part
  of the first version. Nyyrikki's own credentials are a different
  matter: they never appear in a response or an error.
- **Bug fixes are test-first**: write the failing test, watch it fail, then
  fix. See `CODE-REVIEW.md`. Every rule there exists because its absence
  cost a real bug.

## Rejected: don't re-propose without new evidence
When an approach is investigated and settled against, add it here with
one line of why and a link to the doc that has the reasoning. Re-deriving
a settled question costs a whole cycle.

These four were settled on 2026-10-25 under the earlier Warden plan.
Their reasoning holds for the current plan too, so they stand. The
links point to the removed docs at the commit they were written in.

- **Passkey (WebAuthn) approval**, either always or only for high-risk
  requests. The owner chose one Telegram tap for every decision, for UX
  ([docs/01](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/01-foundations.md) OD2, 2026-10-25).
- **Approval inside the coding tool's UI**, such as a button in the T3
  Code thread. It renders on the agent's machine, which the agent
  controls ([docs/01](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/01-foundations.md) rejected alternatives).
- **Admin credentials or "checking" wrapper CLIs on the agent's
  machine.** Any process there can read or bypass them
  ([docs/01](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/01-foundations.md) rejected alternatives).
- **Telegram webhooks.** An inbound endpoint is a second way to inject
  updates. Long polling only
  ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) D2).

## Conventions
- **Design doc before code.** Every roadmap item is designed in its own
  numbered doc (`docs/NN-short-slug.md`) before implementation starts. The
  owner approves the doc's decisions; the code follows them. See
  `docs/README.md`.
- **Every design doc defines explicit acceptance criteria**: a goal →
  verified-by table, and a per-chunk "done when" column. A doc that lists
  proposed changes without them is how a critical review finding gets
  missed: nothing forces the "does this actually reach production?" question.
- **Chunk prefixes are two letters** from the start (e.g. `GW1`, `TG1`).
  `gawk` used up single letters A–Z and had to switch mid-way.
- **Decisions are revised in place with a dated note**, never silently
  rewritten. The doc is a record of what was decided and why.
- **Owner decisions are recorded as such** (`OD1`, `OD2`, … with the date)
  so they can be told apart from decisions the author made.
- **Commit messages and PR titles are Conventional Commits.** PRs land by
  squash merge, so the PR title becomes the commit subject on `main`. Type
  and scope table: `CONTRIBUTING.md`.
- **README.md is for humans browsing the repo.** No status tracking (that
  is `ROADMAP.md` and `BUGS.md`), no hardcoded counts that drift, plain
  matter-of-fact tone.
- Keep `docs/gotchas.md` in sync when a new gotcha lands in a doc. Remove
  `BUGS.md` entries when they are fixed.

## Explicitly set aside (don't suggest reintroducing without discussion)
- **The Warden-based plan** (2026-10-25): profile-based grants of up to
  hours, with the agent holding a per-grant token and
  running unmodified `kubectl` or `ssh` against protocol proxies, and
  impersonating a fixed per-profile user. Replaced on 2026-10-26 by owner
  decision with the plan in `ROADMAP.md`: requests passed through via
  MCP or the CLI, one-off approvals or elevations of at most 30
  minutes, acting as the exact human.
- **An HTTP identity-aware proxy in front of web services for people in
  browsers** (OIDC sign-in, sessions, per-route rules). The project's
  first framing, set aside before the Warden plan.
- **A fixed catalogue of typed tools, one per action** (e.g. a
  `delete_pod` tool). Set aside on 2026-10-26 by owner decision in favour
  of passing the agent's requests through to the target's API.
- **A model judging each request in the first version.** Deferred on
  2026-10-26 by owner decision: the first version is a plain escalation
  gateway. The item is R8 in `ROADMAP.md`.
