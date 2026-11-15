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
assessment is R8 and deferred. The facts measured for it (Kubernetes, SSH,
Telegram, MCP clients, Go libraries) are kept in `docs/measured.md` and
`docs/gotchas.md`. Each is re-checked before a new decision leans on it.

| # | Item | Status |
|---|------|--------|
| R1 | [Foundations: architecture, threat model, toolchain](#r1--foundations) | 🔧 in progress 2026-10-27: [docs/01](docs/01-foundations.md) approved; FD1 (skeleton) and FD2 (gates, canaries, CI) implemented, G3–G6 verified in CI; open: FD3 measurements M9–M11 (G7) |
| R2 | [Gateway core: MCP and CLI, identity, targets, one decision point](#r2--gateway-core) | 🔧 implemented 2026-10-27, [docs/02](docs/02-gateway-core.md) approved: GW1–GW6 with integration tests against a test authorization server and fakes; verified end to end with Keycloak 26.8.1 2026-10-27; open: the rest of docs/01 M9 (DCR policies, refresh, two logins in one browser) |
| R3 | [Audit log](#r3--audit-log) | 🔧 implemented 2026-10-27, [docs/03](docs/03-audit-log.md) approved |
| R4 | [Pass-through, identity propagation and credential custody](#r4--pass-through-identity-propagation-and-credential-custody) | 🔧 implemented 2026-10-27, [docs/04](docs/04-kubectl-passthrough.md) approved: PT1–PT5 done: tested against a fake apiserver, and end to end on kind with Keycloak (test/e2e, 2026-10-27) |
| R5 | [Telegram escalation: one-off approvals and time-boxed elevation](#r5--telegram-escalation) | 🔧 implemented 2026-10-27, [docs/05](docs/05-telegram-escalation.md) approved: TG1–TG4 tested against a fake Bot API; G8 verified 2026-10-29 by the owner on a real phone against the owner's cluster (approve, deny, an elevation and End now) |
| R6 | [Packaging and deployment](#r6--packaging-and-deployment) | 🔧 implemented 2026-10-27, [docs/06](docs/06-packaging-and-deployment.md) approved: image, chart, setup docs, release workflow; G5 done (0.1.0 2026-10-27; 0.2.0 2026-10-28 also publishes the chart to GHCR as OCI); G4 2026-10-29: deployed on the owner's cluster by Flux from chart 0.2.0, one-off and elevation verified by the owner; open: G4's agent holding nothing but its Nyyrikki token (see M4) |
| R7 | [Operator surface](#r7--operator-surface) | 💡 proposed 2026-10-25 |
| R8 | [AI risk assessment](#r8--ai-risk-assessment) | ⏸️ deferred 2026-10-26 (owner decision: not in the first version) |
| R9 | [Optional response redaction](#r9--optional-response-redaction) | ⏸️ deferred 2026-10-26 (owner decision: future, and optional) |
| R10 | [SSH target](#r10--ssh-target) | 🔧 implemented 2026-10-30, [docs/07](docs/07-ssh-target.md) approved (#25): SH1–SH6, unit and in-process tests against a fake SSH host, `test/ssh-host` runs the setup script in Debian, Ubuntu (24.04, and 22.04 with OpenSSH 8.9 since OD7, 2026-11-01), Rocky and Alpine containers, e2e on kind against an OpenSSH container set up by the served script; open: G12 (a real command on a real host, approved on a real phone, set up with the script), and session kill measured only on Debian and Ubuntu, not Rocky (§2 M18). Not in the first version |
| R11 | [SSH CA hardening](#r11--ssh-ca-hardening) | 💡 proposed 2026-10-29, after R10; the pull of trust material is taken over by R12 (signed in the pod, docs/08 OD3), the external signer stays open |
| R12 | [SSH onboarding and upkeep](#r12--ssh-onboarding-and-upkeep) | 🔧 [docs/08](docs/08-ssh-onboarding.md) approved 2026-10-31 (#40); SE1–SE6 implemented: SE1 2026-10-31 (#42: CA keys through `internal/sshca`, `nyyrikkid ssh-ca`, the CA Secret mounted whole, the install hook and rotation CronJobs), SE2 2026-10-31 (#43: defaults, groups, global host CAs, `nyyrikki ssh`), SE3 2026-11-01 (#45: the signed trust bundle), SE4 2026-11-01 (#46: host verification by `host-ca`, the host check before approval), SE5 2026-11-01 (#47: enrollment tokens and endpoints, the host certificate, the check after enrollment), SE6 2026-11-01 (the setup script's trust pull, enrollment and `--status`, Alpine, the setup docs' three paths, NOTES.txt, e2e of enrollment and a rotation reaching a host by its pull); open: G14 (a real host enrolled and rotated, manual by the owner) |
| R13 | [Public release readiness](#r13--public-release-readiness) | 🔧 implemented 2026-11-02, [docs/09](docs/09-public-release.md) (OD1 2026-11-01): PB1 (#51), PB2 (#52), PB3 (#54), PB4 (#53, #57), PB5 (#56) and PB6 (#51) merged; open: PB7, the repository settings after the visibility flip (owner), and the manual checks G4 (verify the next release's signatures) and G6 (the quickstart with a real bot) |
| R14 | [SOPS target](#r14--sops-target) | 🔧 implemented 2026-11-13, [docs/10](docs/10-sops-target.md) approved (#74): SO1–SO5, unit and in-process tests against a fake Cloud KMS and token service, and against the `sops` program pinned at the library's version (files it encrypts are decrypted, files Nyyrikki returns are read back by it); G9 and M12 checked by hand on the owner's cluster on 2026-11-14 and 2026-11-15 (release 0.6.0, Workload Identity Federation, the real Cloud KMS: encrypt and decrypt approved on a real phone, the service account and the reason in Google's log); open: G9's denied request against the real Cloud KMS. Not in the first version |

## Milestones to the first version

Adopted 2026-10-26 (owner decision). The R items above split the work
by subsystem. The milestones below cut across them into vertical slices
that each run end to end and can be demonstrated. Implementation works
toward them. **All five done means the first version is done.**

The numbering follows the natural dependencies, but it is **not a
required order**. Which milestone to work on, and whether several go in
parallel, is the owner's call case by case. A later milestone may be
asked for before an earlier one is done. When that happens, the parts
of earlier milestones it depends on are built as far as it needs them,
following the same design docs, and the earlier milestone's own "done
when" still has to be met before it is marked done. A
milestone's status changes like an R item's: dated, and saying what is
still open.

The milestones don't replace design docs. Code for a milestone starts
only once the design docs it draws from have their relevant decisions
approved and their chunks defined (`docs/README.md`). A milestone's
"done when" is met by those docs' acceptance criteria, verified,
including the manual ones. Where a milestone needs only part of an R
item, the doc's chunks say which part.

| # | Milestone | Draws from | Status |
|---|---|---|---|
| M0 | [Decisions locked](#m0--decisions-locked) | R1 | done when this lands 2026-10-27: docs/01 approved, CLAUDE.md lists what it locked, CI runs the gates on the skeleton and every gate fails on its canary; FD3 (needed by M1 at the latest) is still open |
| M1 | [Walking skeleton that only says no](#m1--walking-skeleton-that-only-says-no) | R2, R3 | ✅ done 2026-10-27: verified by integration tests and end to end on kind with Keycloak 26.8.1 (test/e2e): listing through MCP and the CLI, unauthenticated and revoked sessions denied, each audited |
| M2 | [One-off escalation, end to end, on one target](#m2--one-off-escalation-end-to-end-on-one-target) | R2, R4, R5 | ✅ done 2026-10-29: verified end to end on kind with Keycloak 2026-10-27 (test/e2e: approve, deny, refused requests, runs as the human per the apiserver, interactive exec); manual checks by the owner 2026-10-29 on a real phone against the owner's cluster: an approved request ran as the human and returned its output, a denied one never ran, both audited. That cluster's apiserver keeps no audit log, so "the target's logs show the human" rests on the e2e test |
| M3 | [Time-boxed elevation](#m3--time-boxed-elevation) | R2, R4, R5 | ✅ done 2026-10-29: verified end to end on kind with Keycloak 2026-10-27 (test/e2e: covered requests without prompts, an exec stream cut at expiry, End now, a foreign handle denied); manual checks by the owner 2026-10-29 on the owner's cluster: two requests under one elevation ran without prompts, each audited; after End now the next request went back to a one-off approval |
| M4 | [Running against a real target](#m4--running-against-a-real-target) | R6 (minimal) | 🔧 deployed 2026-10-29 on the owner's cluster (Flux, chart 0.2.0, its own Keycloak realm, behind an internal gateway that re-encrypts), released (0.1.0, 0.2.0), M2's and M3's manual checks run there; open: real tasks by an agent on its own machine holding nothing but its Nyyrikki token. The checks ran from a machine that also holds an admin kubeconfig |

**Not in the first version**, so no milestone covers it: a second target
type, such as SSH (R10) or SOPS (R14); temporary credentials issued on targets, unless
the first target can't impersonate; the operator surface (R7); AI risk
assessment (R8); response redaction (R9).

### M0 — Decisions locked

**Goal**: nothing in M1–M4 is blocked on an architectural question.

**Includes**: R1's design doc, approved by the owner. It settles the
language and runtime, the MCP transport and spec revision, how an agent
authenticates and how it is bound to a human, where Nyyrikki's
credentials live, the threat model (which fills in `SECURITY.md`), the
gates and CI, and **the first target type**. Recommendation: Kubernetes.
Its impersonation is built in, so no credential issuing is needed, and
most of the facts in `docs/measured.md` and `docs/gotchas.md` are about
it.

**Done when**: the owner has approved R1's doc, `CLAUDE.md` lists what
it locked in, and CI runs the gates on an empty skeleton.

### M1 — Walking skeleton that only says no

**Goal**: prove the single decision point and the audit log before
anything privileged exists.

**Includes**: the Nyyrikki API; the MCP server and the CLI as thin
clients of it; agent authentication and the agent-to-human binding; the
target registry; the list-targets operation; and the decision point, at
this stage with no way to allow anything (R2). The audit log, recording
every request and every deny (R3).

**Done when**: an agent lists its targets through MCP and through the
CLI. Every run and every elevation request is denied, through both, and
each deny is in the audit log with the agent and the human. An
unauthenticated client, an agent asking for a target it may not use,
and every dependency failure all end in deny, each with a test.

### M2 — One-off escalation, end to end, on one target

**Goal**: the core of the product. An agent gets one privileged request
done, approved by a human.

**Includes**: pass-through for the first target: the request form, the
canonical parse, forwarding exactly the approved form, acting as the
exact human through impersonation, and returning the response as sent
(R4). The Telegram bot with one-off approvals: the message shows the
exact request and who it runs as, the agent's reason is marked as its
claim, the callback is bound and checked, and timeout means deny (R5).
The decision point now allows a request covered by a one-off approval
(R2).

**Done when**: an agent runs, for example, `nyyrikki run prod-k8s --
delete pod api-7f -n shop`. The approver gets the exact request on
Telegram. After the tap it runs on the target as the bound human, the
target's own logs show that human, and the response comes back to the
agent (on stdout for the CLI). A refusal, no answer, a replayed or
foreign callback, and a request that differs from what was approved all
end in deny, each with a test. Every step is audited.

**Open questions it needs answered**: whether the human an agent works
for may approve that agent's requests (R5's doc; with one human in v1,
[docs/01](docs/01-foundations.md) OD1 means they must); whether the request is
a raw API request or a CLI line (R4's doc).

### M3 — Time-boxed elevation

**Goal**: an agent can do a burst of work without a tap per request.

**Includes**: the elevate operation through MCP and the CLI; elevations
of at most 30 minutes, on one or more named targets, for one agent and
human, each with a handle that requests must carry
([docs/01](docs/01-foundations.md) D24) (R2); the elevation approval
message, and ending an elevation early from the chat if R5's doc
decides approvers can (R5); cutting
streaming and long-lived requests when an elevation ends (R4).

**Done when**: after one tap, the agent's requests to the named targets
run without asking again, each one audited. A request after expiry, to
a target the elevation doesn't name, from another agent, or without the
elevation's handle goes back to one-off escalation, and one with a
handle never issued to its agent is denied, as
[docs/01](docs/01-foundations.md) D24 says. An open stream (exec,
watch) is cut at expiry. Asking for more than 30 minutes gives 30. If R5's doc allows
ending early from the chat, that works and ends the elevation at once.
Each has a test.

**Open questions it needs answered**: whether an approver can end an
elevation early from the chat (R5's doc).

### M4 — Running against a real target

**Goal**: the owner uses Nyyrikki for real work.

**Includes**: the minimal part of R6: an image and a way to deploy it;
granting Nyyrikki its rights on the target (for Kubernetes, the right
to impersonate) and nothing more; provisioning and rotating its
credentials; enrolling agents and approvers; versioned releases.

**Done when**: Nyyrikki runs in front of a real target, an agent on its
own machine (holding nothing but its Nyyrikki token) completes real
tasks through both one-off escalation and an elevation, and the owner
has run the manual checks from M2 and M3 against that deployment.

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

**Scope**: three operations, offered both as MCP tools and as commands
of a CLI. Some agents work better with a CLI, and a CLI lets them pipe
and filter output with their shell tools. Both are thin clients of the
same API and reach the same decision point:

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
are off. The CLI writes the target's response to stdout and Nyyrikki's
own messages to stderr, has exit codes that tell denied, timed out and
failed apart, and blocks while an approval is pending. How it
authenticates as the agent, and that it holds no target credential and
can't approve anything, is settled here too.

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
- **Responses**: the target's response goes back to the agent as it
  came, unredacted (redaction is R9, deferred). Nyyrikki never puts its
  own credentials or leases in a response or an error (a request, one-off
  or under an elevation, that reads them because the human can is
  docs/04 OD3's accepted risk). Also
  timeouts, and what happens when a request partly succeeds.

## R5 — Telegram escalation

**Why**: every privileged request needs a human who can answer within
seconds from a phone, while the agent's call waits.

**Scope**: the approver bot; two message kinds, a one-off request
(showing the exact request as it will be forwarded) and an elevation
(showing targets, duration, agent and human); the agent's stated reason
shown as the agent's claim, never as fact; grants bound to the exact
request or elevation, the agent and an expiry; replay protection;
timeout as deny; the approver allow-list; whether the human an agent
acts for may approve that agent's requests; what the approver sees while
an elevation is live, and whether they can end it early from the chat;
and what the waiting agent sees (MCP progress or a timeout, decided
against what clients support; for the CLI, what it prints while it
blocks).

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

## R9 — Optional response redaction

**Deferred 2026-10-26 (owner decision)**: in the first version, the
response to an approved request reaches the agent as the target sent it.
Redaction is a possible future enhancement, and even then optional, on
by configuration per target.

**Why it may come back**: an approved request can return secret material
(for example `kubectl get secret`), which then sits in the agent's
context and, through it, at the model provider.

**Scope, if picked up**: what counts as a secret per target type; how
redaction is configured and switched on; how the agent and the approver
can tell a redacted response from an original; and a test asserting the
redacted form for each target type.

## R10 — SSH target

**Proposed 2026-10-29 (owner request)**, after the first version.

**Why**: not everything an agent has to fix is in Kubernetes. Restarting
a service on a VM, reading its journal or changing a file under `/etc`
needs a command on a host, and today that means handing the agent an SSH
key that works forever, with nothing approved and nothing recorded.

**Scope**: commands on Linux hosts with OpenSSH, through the same `run`
and `elevate` operations, one-off approvals and elevations as for
Kubernetes; interactive sessions over `/stream`. SSH can't impersonate,
so this is the first target with credentials issued on it: a short-lived
SSH certificate per run, from a user CA that only Nyyrikki holds, for an
account on the host that belongs to the human and that only those
certificates reach. Root, where a host allows it, through passwordless
sudo on that account. Host keys are pinned or come from a host CA, never
trusted on first use. Setting a host up is one command (a setup script)
or the documented manual steps; Nyyrikki never configures its own trust.
Not in scope: running unmodified `ssh`, scp or ansible from the agent's
machine (the set-aside Warden model), and port forwarding (docs/07 OD5).

## R11 — SSH CA hardening

**Proposed 2026-10-29**, after R10 ([docs/07](docs/07-ssh-target.md) §9).

**Why**: with R10, rotating or revoking the SSH user CA means re-running
the setup on every host, which is slow exactly when speed matters, after
a leak. And the CA key sits in Nyyrikki's pod, so a compromise of the
pod can copy it out and use it for as long as hosts trust it.

**Scope**, one or both: hosts that pull their trusted CA keys and
revocation list from Nyyrikki on a timer, accepting a new list only if a
key they already trust signed it, so rotation and revocation reach every
host without a visit; and an external signer (Vault's SSH engine,
step-ca, a cloud KMS) that holds the CA key and enforces principals,
lifetime and source address itself, so there is no key in the pod to
copy.

## R12 — SSH onboarding and upkeep

**Proposed 2026-10-31 (owner request)**, after R10
([docs/08](docs/08-ssh-onboarding.md)).

**Why**: with R10, bringing a host on board takes a hand-made CA, two
rollouts and facts copied back into the values, and every CA rotation,
revocation or removed human means visiting every host again.

**Scope**: CA keys made in the cluster by the chart and rotated without a rollout,
public keys derived from them; enrollment with one command on the host
and one tap on Telegram, after which Nyyrikki trusts the host by a
host certificate it signed, so a target needs only its address; hosts
with cron pulling a signed trust bundle every 15 minutes; defaults,
global host CAs and groups in the values; `nyyrikki ssh`. Everything
stays in the Helm values: Nyyrikki stores no registry (docs/08 OD1).

## R13 — Public release readiness

**Proposed 2026-11-01 (owner request)** ([docs/09](docs/09-public-release.md)).

**Why**: the owner wants the repository public. An outsider meets a
README with no status and no way to try it, a security policy with no
reporting channel, binaries without their dependencies' licence texts,
unsigned releases and an unprotected `main`.

**Scope**: the README, private vulnerability reporting, licence notices
in the image and the release, key-less signed releases, a coverage
gate, a local quickstart on Linux with a real Telegram bot, Renovate's
`go mod tidy`, and the repository settings the owner applies after the
flip. Nothing on the decision path changes.

## R14 — SOPS target

**Proposed 2026-11-12 (owner request)** ([docs/10](docs/10-sops-target.md)).

**Why**: secrets kept in git are encrypted with SOPS, with the key in
Google Cloud KMS. An agent can't read one that isn't deployed, change a
value or add a file without a Google credential that can use the key,
which works forever, on every file, with nothing approved and nothing
recorded.

**Scope**: SOPS operations on a file the agent sends, through the same
`run` and `elevate` operations as the other targets: decrypting,
changing one value, and encrypting a new file. Nyyrikki unwraps the
file's data key with its own Google credential and does the work in the
pod; the data key and the credential never reach the agent. The
approver sees what is asked: the operation, the path it names, which
file and the KMS key. Cloud KMS can't act as a human, so every call
carries a request reason that names the run and the human. Not in
scope: other SOPS key types, Google Cloud in general, and unmodified
`sops` on the agent's machine.
