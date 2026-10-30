# Security Policy

Nyyrikki is a gateway that forwards AI agents' privileged requests to
target systems: its whole job is to make sure only requests a human
approved run, as the right user, with credentials Nyyrikki never hands to
the agents (see Accepted risks for what an approved request, or one under
an elevation, can still read). It holds
high-privilege access to every system behind it, which makes it a
high-value target in its own right. It is maintained by one person,
on a best-effort basis.

## Reporting a vulnerability

Don't open an issue or a pull request. Contact the maintainer privately,
and include what you found, how to reproduce it and what it lets an
attacker do. You'll get an acknowledgement, and the fix will be
coordinated with you before anything is disclosed.

## Threat model

Written for R1 on 2026-10-26 ([`docs/01`](docs/01-foundations.md)). It
replaces the threat model drafted for the Warden plan (2026-10-25),
which is in git history. Each invariant below is tested by an
acceptance criterion in the design doc named next to it. A change that
weakens one is a security change, whatever else it does.

### What Nyyrikki protects

- **Target access**: the credentials Nyyrikki holds for target systems
  (its ServiceAccount tokens, which can impersonate), and through them
  everything the human can do on those targets.
- **The approval channel**: the Telegram bot token, and the state that
  says what is pending, approved and live (approvals, elevations).
- **Its Keycloak credential** for token introspection.
- **The audit log**: what happened, who asked, who approved.

### What it assumes (the trust base)

- **The Kubernetes cluster Nyyrikki runs in**, its control plane, its
  nodes and its administrators. Whoever can exec into Nyyrikki's pod,
  read its Secrets or change its Deployment owns everything behind it.
- **The authorization server** (Keycloak). Its compromise lets an
  attacker act as an agent of the human, which means *asking*, not
  approving: every privileged request still needs a tap.
- **Telegram**: its servers see every message and could in principle
  forge an update. A bot cannot check that an approver uses 2-Step
  Verification; the operator's setup requires it.
- **The approver's phone and Telegram account.**
- **The build and release path**: GitHub, the Go module proxy and
  checksum database, the container registry.

### Who it defends against

- **The agent, steered by an attacker** (the main adversary). It holds
  its own OAuth tokens and can reach Nyyrikki's HTTPS endpoint. In the
  owner's deployment it runs in the same cluster with cluster-wide read
  access, excluding Secrets and RBAC objects (docs/01 OD7). So it can
  read Nyyrikki's pod spec, ConfigMap, events and logs, and it knows the
  cluster's state. It can say anything in its stated reasons, and it can
  sign in again to start new sessions, but only with the human signing
  in.
- **Other workloads in the cluster**, compromised or hostile, on the
  network.
- **Anyone on the network path** to Nyyrikki, the authorization server,
  Telegram or the targets.

Out of scope: a malicious cluster administrator or node (but note that an
agent with one approval, or under an elevation, borrows the human's own
rights, which may be an administrator's: Accepted risks), a compromised
authorization-server administrator acting beyond what is said above,
Telegram itself turning hostile, and an approver who approves something
on purpose.

### Deployment requirements

Nyyrikki's guarantees hold only if these are true (and see the accepted
risks of docs/04 OD3 for what the human's own rights expose), and its documentation
says so:

- Agents can't read Secrets, can't create, change or delete anything in
  Nyyrikki's namespace, and can't exec into, attach to, port-forward to
  or proxy to its pod (`pods/exec`, `pods/attach`, `pods/portforward`,
  `pods/proxy`, `services/proxy`). Read access elsewhere is allowed.
  (docs/01 M11 checks this.)
- Nyyrikki's credentials are Secrets mounted as files, never
  environment variables or ConfigMap values.
- Nyyrikki's ServiceAccounts can impersonate only the configured
  humans' identities and have no other rights.
- The CLI's client in the authorization server requires DPoP-bound
  tokens (docs/01 D7).
- Each agent has its own login file (`nyyrikki login`, and separately
  `nyyrikki login --mcp`), readable by no other agent: whoever can read
  it is that agent (docs/01 §5.4, D25).
- An agent's elevation handles are readable by no other agent: its
  harness transcripts and its stdout (which become pod logs) are not
  readable by other agents, and `NYYRIKKI_ELEVATION` is never set in a
  pod spec, ConfigMap or anything else shared (docs/01 D24).
- Anything that terminates TLS in front of Nyyrikki (an Ingress) logs
  neither the `Authorization` nor the `DPoP` header.
- The NetworkPolicy shipped with the chart is enforced by the cluster's
  network plugin.
- The approver's Telegram account uses 2-Step Verification and a
  passcode lock.

### Invariants

| # | Invariant | Designed in |
|---|---|---|
| INV-01 | No request reaches a target unless a one-off approval of exactly that request, or a live elevation for this agent, human and target, carrying its handle (docs/01 D24), covers it. Listing targets is the only operation that needs neither. | R2 |
| INV-02 | A request is parsed once into a canonical form. The approver is shown that form, the approval binds to it, and exactly that form is forwarded. | R4, R5 |
| INV-03 | An elevation lasts at most 30 minutes by the server's clock, covers only its named targets, one agent key (docs/01 D8) and one human, and only requests that carry its handle (docs/01 D24). It is never widened. Long-lived requests under it are cut when it ends. | R2, R4 |
| INV-04 | An approval counts only if it comes from a configured approver's Telegram account, in their private chat with the bot, before it expires, and only once. No MCP tool or CLI command approves, denies or ends anything. | R5 |
| INV-05 | Requests run on the target as the human the agent is bound to, taken from the human registry, never from anything in the request. | R4 |
| INV-06 | Only access tokens from the configured issuer, with Nyyrikki as audience, unexpired, for a known human are accepted, and a DPoP-bound or CLI token only with a valid proof (docs/01 D9). Run and elevate also need the session to be live by introspection. No token is passed on to a target. | docs/01 D9, R2 |
| INV-07 | Any error, timeout or unreachable dependency ends in deny. | every doc |
| INV-08 | Nyyrikki never puts its own credentials in a response, an error, a log or a Telegram message. (A target's response to a request, approved or under an elevation, that reads them because the human can is an accepted risk below.) | R4 |
| INV-09 | Logs and audit records are treated as readable by the agent: no credential, no secret value, no approval material in them. | docs/01 D16, R3 |
| INV-10 | Every request, decision, approval, elevation and dependency failure is audited. A failed audit write doesn't turn into an allow. | R3 |
| INV-11 | Nyyrikki listens only on its HTTPS port and its health port, and the health port serves no data. | docs/01 D10, R6 |

INV-01, -02 and -10 stop holding for a target, for as long as a stolen or
minted credential lives, in the two cases under Accepted risks (docs/04
OD3). They are what Nyyrikki guarantees for requests that pass through it.

### In scope

These kinds of issue are always in scope:

- Running a request that no one-off approval or live elevation covers,
  through any MCP tool or method, CLI command, transport or request
  encoding.
- Running a different or wider request than the one that was approved:
  request smuggling, a parse that differs between what the approver saw
  and what is forwarded, extra requests riding along, redirects to
  another target, or a change between check and forwarding.
- Using an elevation beyond its scope: on a target it doesn't name, for
  another agent or human, without its handle, after it expired or was
  ended, through a streaming connection that outlives it, or for longer
  than 30 minutes.
- Any path where an error, timeout or malformed response leads to allow
  instead of deny.
- An agent posing as another agent (beyond the accepted case of MCP
  sessions sharing an agent key, under Accepted risks), acting for a
  human it isn't bound to, or getting Nyyrikki to impersonate a
  different user on the target.
- Temporary credentials that Nyyrikki issued outliving their purpose
  (not revoked after an error, a timeout or a crash) or being wider than
  needed.
- Compromise of Nyyrikki itself, or of where its credentials are stored,
  which exposes everything behind it, other than through a request the
  human could run themselves, approved one-off or under an elevation
  (Accepted risks).
- Producing an approval from anything the agent controls: an approval
  surface, a bot token, a Telegram session or a credential on the
  agent's machine. An approval means something only if the agent can't
  produce it.
- Forging, replaying or reusing a Telegram approval, approving from an
  account that isn't an approver, or getting an approver to approve
  something other than what runs (for example with a misleading stated
  reason or a request that renders deceptively).
- Getting Nyyrikki's credentials or the temporary credentials it issues
  into the agent's hands, through responses, errors or messages, other
  than through a request the human could run themselves, approved
  one-off or under an elevation (Accepted risks).
- Leaking tokens, kubeconfigs, API keys or secret contents into logs,
  audit records or Telegram messages.
- Tampering with or suppressing audit records.
- Supply-chain issues in the build and release path.

### Accepted risks

- **Responses are unredacted.** The response to an approved request
  reaches the agent as the target sent it, including any secret
  material it returns. Optional redaction is deferred (`ROADMAP.md` R9).
- **One approved request, or any request under an elevation on that
  target, can hand the agent Nyyrikki's own credentials** when the human
  it runs as can reach them (docs/04 OD3, owner decision 2026-10-27,
  reconfirmed the same day for elevations). Examples: `get secret -n
  <nyyrikki-namespace>`, `create token <nyyrikki-serviceaccount>`, `exec`
  into Nyyrikki's pod, a pod that mounts its ServiceAccount or Secrets,
  or the node paths below, as a cluster admin can. What that costs, for
  as long as the stolen credential lives:
  - a **target token** (a remote target's, or one minted for Nyyrikki's
    ServiceAccount) gives direct API access that can impersonate the
    human with no Nyyrikki in the path: INV-01 and INV-10 no longer hold
    for that target, and the 30-minute bound of INV-03 means nothing
    there;
  - the **Telegram bot token** lets the agent edit Nyyrikki's pending
    messages, so the approver could see a harmless command while the
    buttons settle the real request, or relabel the buttons so that
    tapping "Deny" approves (the edit returns the buttons' callback data);
    both break INV-02. It can also strip the "End now" button from a live
    elevation; calling `getUpdates` or setting a
    webhook with it stops Nyyrikki's poller (fail closed: every
    escalation is denied). A tap still counts only from the approver's
    own chat, once, in time (INV-04 holds);
  - the **introspection secret** is lost.

  The defence is the approver's tap: on the exact request, or, under an
  elevation, on the elevation that covers it, with no message per
  request. Withholding rights from the human narrows it, best effort:
  no write of any kind and no Secret read in Nyyrikki's namespace (and in
  `nyyrikki-system` on remote targets); no `nodes/proxy`; no node
  debugging; no privileged or `hostPath` pods anywhere (for example Pod
  Security `restricted` on every namespace the human can write to); no
  RBAC `bind`, `escalate` or `impersonate`; no admission webhooks or
  mutating admission policies; no `persistentvolumes` write (a `hostPath`
  PV bound to a PVC reaches the node); no CSR approval
  (`certificatesigningrequests/approval`, `signers` `approve`), which can
  issue a client certificate for Nyyrikki's ServiceAccount. The list is
  best effort: a controller the human can feed objects to (GitOps, an
  operator) acts with its own rights. What
  closes it is running Nyyrikki on a cluster the human doesn't
  administer, with remote targets only.
- **One approved request, or a request under an elevation, can mint a
  standing credential on a target**: `create token <any-sa>
  --duration=…`, or a CSR created and then approved with `certificate
  approve`. That gives direct API access with no Nyyrikki in the path,
  so INV-01 and INV-10 hold for a cluster only while the human can't
  obtain such a credential there, which in practice means while the
  human isn't its administrator. INV-03 bounds elevations, not what one
  request returns. The defence is the approver's tap.
- **The human approves their own agents' requests.** In the first
  version there is one human, who is also the approver (docs/01 OD1).
  The defence is a message that shows exactly what will run (R5).
- **The agents can read most of the cluster Nyyrikki runs in**
  (docs/01 OD7), including Nyyrikki's configuration and logs.
- **An agent's displayed name is its own claim.** Agents are told
  apart by their sign-in, not by what they call themselves (docs/01
  D8).
- **MCP sessions can share an agent.** Every harness session using one
  MCP sign-in is the same agent, and two sign-ins of one MCP client
  registration in one browser session may be too. A steered agent can
  cause the second case on purpose, by getting the owner to sign in
  with another agent's client ID. Elevation handles keep such sessions
  from using each other's elevations, but the joining agent's requests
  are shown and audited under the other agent's name (docs/01 OD15).
  Each `nyyrikki login --mcp` is its own agent (docs/01 OD16).
  CLI sign-ins are separate as long as each login file is private to
  its agent (docs/01 OD14).
- **Releases are built on self-hosted runners.** In the owner's
  deployment the release job, which pushes the image Nyyrikki runs as,
  runs on cluster nodes that also run other repositories' privileged
  Docker-in-Docker CI jobs. The runners are ephemeral (one pod per job),
  but a job that escapes to a node could tamper with a build running
  there, or use that job's token while it runs. The release token can
  push any tag of the repository's ghcr.io packages (the image and the
  Helm chart), create, edit or delete releases with their assets and
  notes (including the image digest users are told to pin), and push to
  unprotected refs; release-please's can also open and edit pull
  requests. The Claude review
  workflows' secrets are on the same nodes. Base images are pinned by
  digest and actions by commit SHA, so a tampered registry cache can't
  swap them (docs/01 D18).
- **One replica.** When Nyyrikki is down, nothing privileged runs.
