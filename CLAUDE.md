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
| What the first version consists of | `ROADMAP.md` milestones (M0–M4) | copy their scope here |
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

## Architecture (locked in by R1, 2026-10-26)
Decisions and their reasons only. The detail, the owner decisions
(OD1–OD16) and the measurements are in
[`docs/01`](docs/01-foundations.md). Don't restate more of it here.

- **Go**, floor `go 1.26.0`, one module, two binaries: `nyyrikkid`
  (server) and `nyyrikki` (CLI). The apiserver's request parser and the
  MCP SDK are Go (D1, D2).
- **A standalone service deployed with its own Helm chart**, one pod,
  publishable as open source under **Apache-2.0**. Nothing assumes the
  owner's environment (OD2, OD10, D3).
- **One external API: remote MCP over Streamable HTTP at `/mcp`.** The
  CLI is an MCP client of it, not of a second API. Only R2's tools are
  offered; resources, prompts, sampling and elicitation are off (D4).
- **MCP sessions carry no authority**; stateless mode. Approvals and
  elevations key on the agent's identity (D5).
- **Nyyrikki is an OAuth resource server only.** Tokens come from an
  external authorization server, Keycloak as the reference, using its
  supported features only: DCR for MCP clients, the device grant for
  the CLI with DPoP required, an audience scope, introspection, no
  `offline_access` (D6, D7).
- **Human = token `sub` from the configured issuer, looked up in the
  human registry. Agent = one sign-in: (issuer, `azp`, `cnf.jkt`) for
  the CLI, whose tokens are DPoP-bound to a key made per
  `nyyrikki login`; (issuer, `azp`, `sid`) for MCP clients, which may
  merge several sign-ins (accepted risk).** Keycloak's `sid` is the
  browser's SSO session, so it alone doesn't separate sign-ins. Nothing
  the client says identifies it (D7, D8, OD5, OD12, OD14).
- **An elevation covers a request only if the request carries its
  handle**, a secret returned by `elevate`, stored hashed, never logged.
  This is what keeps the elevations of sessions sharing one agent key
  apart (D24, OD15).
- **MCP harnesses sign in through their own OAuth flow, or through a
  repository `.mcp.json` whose `headersHelper` runs
  `nyyrikki mcp-headers`; each `nyyrikki login --mcp` registers its
  own client, so it is its own agent.** No long-lived token in an
  environment variable (D25, OD16).
- **Every call validates the JWT locally, in Nyyrikki's own middleware
  (the go-sdk's takes only `Bearer`); run and elevate also
  introspect.** Keycloak unreachable means deny. A DPoP-bound token is
  never accepted as `Bearer`, and which rule applies is decided by the
  token's claims, not the client's chosen scheme (D9, OD13).
- **Listeners: `:8443` HTTPS (`/mcp`, protected-resource metadata), TLS
  terminated in-process; `:8081` health only, no data** (D10).
- **SQLite (WAL, `modernc.org/sqlite`) on a PVC, one replica,
  `Recreate`**; audit also to stdout as JSON lines; static binaries
  (D11).
- **Config is one strict YAML file from the chart's ConfigMap, holding
  no secrets** (D12).
- **First target: Kubernetes, in-cluster and remote, 1.35 and newer**
  (OD9, D13).
- **Credentials are Secrets mounted as files, never env vars.**
  Nyyrikki's ServiceAccounts can only impersonate the registry's humans
  (D15).
- **Everything Nyyrikki logs is agent-readable**: the agents share its
  cluster with cluster-wide read (OD7, D16).
- **Gates and CI** as in docs/01 §5.6, each with a canary; actions
  pinned to SHAs (D17, D18).

Application code is written only for chunks of a design doc whose
decisions the owner has approved; `ROADMAP.md` says which are open. A
code change without a design doc behind it is out
of order, however small.

## Key constraints / principles to respect
- **Fail closed.** Any error, timeout, unparseable response or unreachable
  dependency (identity, Telegram, credential store, credential issuance,
  target system, audit sink) ends in deny, never allow. An approver who
  doesn't answer has denied.
- **No approval, no request.** Every privileged request is covered either
  by a one-off approval of that exact request, or by a live elevation
  window for this agent, this human and this target, presented with its
  handle. There is no third path, and no standing allow.
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
  covers the named targets, for the named agent and human, and only
  requests carrying its handle, until its expiry, and never longer than
  30 minutes. Neither is widened afterwards.
- **What the approver sees is the request itself.** The Telegram message
  shows the request as it will be forwarded, plus the agent's stated
  reason, clearly marked as the agent's claim. It never shows a
  paraphrase.
- **Telegram updates are untrusted.** A callback is not an approval until
  it is checked against the approver, the request or elevation, and its
  expiry.
- **Nyyrikki holds the target credentials and never hands them to the agent.** That
  covers every credential for a target system or for approving,
  including the temporary credentials Nyyrikki creates on targets. The
  only credential the agent holds is its own token for authenticating to
  Nyyrikki.
  Nyyrikki never hands one to an agent, directly, in a result or in an
  error. An approved request that itself reads them, because the human
  it runs as can, is an accepted risk (owner decision 2026-10-27,
  `docs/04` OD3, SECURITY.md).
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
  matter: Nyyrikki never puts them in a response or an error itself; a
  target response that contains them because the human can read them
  is the accepted risk above.
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

Settled on 2026-10-26 in [docs/01](docs/01-foundations.md):

- **Nyyrikki as its own OAuth authorization server.** Token minting
  would sit next to the credentials it protects (OD3).
- **Local-only JWT checks for run and elevate.** A revoked agent would
  keep working until its token expired (OD13).
- **An MCP server on the agent's machine (stdio)**, or **a second API
  for the CLI** next to `/mcp`. One more thing on the machine the agent
  controls; a second decision path to keep in step (OD6, D4).
- **MCP session IDs as identity or as the key of an elevation.** A
  client-chosen bearer value is not an identity (D5).

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
