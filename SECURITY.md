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

To be written as part of R1 ([`ROADMAP.md`](ROADMAP.md)). The threat
model drafted for the Warden plan (2026-10-25, with assets and
invariants `INV-xx`) was replaced on 2026-10-26 along with that plan.
It is in git history. It will state
what Nyyrikki defends against, what it assumes about its deployment, and
what is in and out of scope. The kinds of issue that will certainly be in
scope:

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

Accepted in the first version: the response to an approved request
reaches the agent unredacted, including any secret material the request
returns. Optional redaction is deferred (`ROADMAP.md` R9).
