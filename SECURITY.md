# Security Policy

Nyyrikki is a gateway that forwards AI agents' privileged requests to
target systems: its whole job is to make sure only requests a human
approved run, as the right user, with credentials the agents never see. It holds
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

Out of scope: a malicious cluster administrator or node, a compromised
authorization-server administrator acting beyond what is said above,
Telegram itself turning hostile, and an approver who approves something
on purpose.

### Deployment requirements

Nyyrikki's guarantees hold only if these are true, and its documentation
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
- The NetworkPolicy shipped with the chart is enforced by the cluster's
  network plugin.
- The approver's Telegram account uses 2-Step Verification and a
  passcode lock.

### Invariants

| # | Invariant | Designed in |
|---|---|---|
| INV-01 | No request reaches a target unless a one-off approval of exactly that request, or a live elevation for this agent, human and target, covers it. Listing targets is the only operation that needs neither. | R2 |
| INV-02 | A request is parsed once into a canonical form. The approver is shown that form, the approval binds to it, and exactly that form is forwarded. | R4, R5 |
| INV-03 | An elevation lasts at most 30 minutes by the server's clock, covers only its named targets, one agent (one sign-in) and one human, and is never widened. Long-lived requests under it are cut when it ends. | R2, R4 |
| INV-04 | An approval counts only if it comes from a configured approver's Telegram account, in their private chat with the bot, before it expires, and only once. No MCP tool or CLI command approves, denies or ends anything. | R5 |
| INV-05 | Requests run on the target as the human the agent is bound to, taken from the human registry, never from anything in the request. | R4 |
| INV-06 | Only access tokens from the configured issuer, with Nyyrikki as audience, unexpired, for a known human are accepted. Run and elevate also need the session to be live by introspection. No token is passed on to a target. | docs/01 D9, R2 |
| INV-07 | Any error, timeout or unreachable dependency ends in deny. | every doc |
| INV-08 | Nyyrikki's own credentials never reach the agent: not in a response, an error, a log or a Telegram message. | R4 |
| INV-09 | Logs and audit records are treated as readable by the agent: no credential, no secret value, no approval material in them. | docs/01 D16, R3 |
| INV-10 | Every request, decision, approval, elevation and dependency failure is audited. A failed audit write doesn't turn into an allow. | R3 |
| INV-11 | Nyyrikki listens only on its HTTPS port and its health port, and the health port serves no data. | docs/01 D10, R6 |

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
  another agent or human, after it expired or was ended, through a
  streaming connection that outlives it, or for longer than 30 minutes.
- Any path where an error, timeout or malformed response leads to allow
  instead of deny.
- An agent posing as another agent, acting for a human it isn't bound
  to, or getting Nyyrikki to impersonate a different user on the target.
- Temporary credentials that Nyyrikki issued outliving their purpose
  (not revoked after an error, a timeout or a crash) or being wider than
  needed.
- Compromise of Nyyrikki itself, or of where its credentials are stored,
  which exposes everything behind it.
- Producing an approval from anything the agent controls: an approval
  surface, a bot token, a Telegram session or a credential on the
  agent's machine. An approval means something only if the agent can't
  produce it.
- Forging, replaying or reusing a Telegram approval, approving from an
  account that isn't an approver, or getting an approver to approve
  something other than what runs (for example with a misleading stated
  reason or a request that renders deceptively).
- Getting Nyyrikki's credentials or the temporary credentials it issues
  into the agent's hands, through responses, errors or messages.
- Leaking tokens, kubeconfigs, API keys or secret contents into logs,
  audit records or Telegram messages.
- Tampering with or suppressing audit records.
- Supply-chain issues in the build and release path.

### Accepted risks

- **Responses are unredacted.** The response to an approved request
  reaches the agent as the target sent it, including any secret
  material it returns. Optional redaction is deferred (`ROADMAP.md` R9).
- **The human approves their own agents' requests.** In the first
  version there is one human, who is also the approver (docs/01 OD1).
  The defence is a message that shows exactly what will run (R5).
- **The agents can read most of the cluster Nyyrikki runs in**
  (docs/01 OD7), including Nyyrikki's configuration and logs.
- **An agent's displayed name is its own claim.** Agents are told
  apart by their sign-in, not by what they call themselves (docs/01
  D8).
- **One replica.** When Nyyrikki is down, nothing privileged runs.
