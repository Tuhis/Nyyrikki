# Project: Nyyrikki — AI-native identity-aware proxy

## Purpose & Context
Nyyrikki is an identity-aware proxy (IAP) that sits in front of self-hosted
services. It authenticates every request against an identity provider and
authorizes it against policy. The "AI-native" part: a model reads the
request in context (who, what, from where, how unusual) and either allows
it, denies it, or **escalates** it. An escalation goes to a human approver
on Telegram, who approves or denies it from the chat. The request waits
for that answer or fails.

Nyyrikki is a security component. A bug that grants access it shouldn't
is the worst outcome, worse than any outage. Rules, reviews and design docs
follow from that.

## Where the detail lives: read these, don't mirror them here
This file holds only what a session **cannot** derive from the repo:
locked-in decisions, rationale, gotchas and prohibitions. Everything else
has one authoritative home. Read it there.

| You want | Read | Never |
|---|---|---|
| Status of every roadmap item | `ROADMAP.md` status table | copy status here |
| Design and decisions for an item | its `docs/NN-*.md` | summarise it here |
| How to write a design doc | `docs/README.md` and `docs/TEMPLATE.md` | restate it here |
| What each design doc covers | `docs/README.md` (the index) | keep a second list |
| Consolidated gotchas | `docs/gotchas.md` | duplicate them here |
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
No language, framework, deployment shape or identity provider has been
chosen. Those decisions belong to R1 (`ROADMAP.md`) and its design doc
`docs/01-*.md`. When R1 locks them in, record **only the decisions and the
reasons for them** here, in the shape of a "locked in" list, and link to
the doc.

Until then, **do not write application code.** The repository holds
process and design documents only. A code change without a design doc
behind it is out of order, however small.

## Key constraints / principles to respect
- **Fail closed.** Any error, timeout, unparseable response or unreachable
  dependency (IdP, policy store, model, Telegram) ends in deny, never allow.
  "The model didn't answer" is a deny or an escalation, not a pass.
- **The model advises; policy decides.** What the model may decide on its
  own, and what always needs a human, is a policy question settled in a
  design doc. It is never left implicit in a prompt.
- **Everything the model reads is untrusted input.** Request paths,
  headers, bodies and user-supplied fields can carry prompt injection.
  The same applies to Telegram updates: a callback is not an approval
  until it is checked against the approver, the request and its expiry.
- **Every decision is auditable.** Allow, deny and escalation outcomes are
  recorded with the identity, the request, the reason and who or what
  decided.
- **Secrets never reach logs, prompts or Telegram messages.** That covers
  tokens, cookies, session IDs and authorization headers.
- **Bug fixes are test-first**: write the failing test, watch it fail, then
  fix. See `CODE-REVIEW.md`. Every rule there exists because its absence
  cost a real bug.

## Rejected: don't re-propose without new evidence
Nothing yet. When an approach is investigated and settled against, add it
here with one line of why and a link to the doc that has the reasoning.
Re-deriving a settled question costs a whole cycle.

## Conventions
- **Design doc before code.** Every roadmap item is designed in its own
  numbered doc (`docs/NN-short-slug.md`) before implementation starts. The
  owner approves the doc's decisions; the code follows them. See
  `docs/README.md`.
- **Every design doc defines explicit acceptance criteria**: a goal →
  verified-by table, and a per-chunk "done when" column. A doc that lists
  proposed changes without them is how a critical review finding gets
  missed: nothing forces the "does this actually reach production?" question.
- **Chunk prefixes are two letters** from the start (e.g. `PX1`, `TG1`).
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
Nothing yet.
