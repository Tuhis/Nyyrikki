# Security Policy

Nyyrikki is an identity-aware proxy: its whole job is to keep the wrong
requests away from the services behind it. It is maintained by one person,
on a best-effort basis.

## Reporting a vulnerability

Don't open an issue or a pull request. Contact the maintainer privately,
and include what you found, how to reproduce it and what it lets an
attacker do. You'll get an acknowledgement, and the fix will be
coordinated with you before anything is disclosed.

## Threat model

To be written as part of R1 ([`ROADMAP.md`](ROADMAP.md)). It will state
what Nyyrikki defends against, what it assumes about its deployment, and
what is in and out of scope. The kinds of issue that will certainly be in
scope:

- Reaching a protected upstream without passing authentication and
  authorization.
- Any path where an error, timeout or malformed response leads to allow
  instead of deny.
- Steering the AI assessment toward allow with content the requester
  controls (prompt injection).
- Forging, replaying or reusing a Telegram approval, or approving from an
  account that isn't an approver.
- Leaking tokens, cookies or session identifiers into logs, prompts, audit
  records or Telegram messages.
- Tampering with or suppressing audit records.
- Supply-chain issues in the build and release path.
