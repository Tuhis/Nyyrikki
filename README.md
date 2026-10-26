# Nyyrikki

A gateway that lets AI agents run privileged actions through MCP or a
CLI, with each escalation approved by a human on Telegram.

An agent connects to Nyyrikki as an MCP server, or calls its command-line
client from a shell, and asks it to do things the agent can't do itself, such as deleting a pod with `kubectl`.
Nyyrikki passes the agent's request through to the target system, using
credentials that only Nyyrikki holds. Nothing privileged runs without a
person's approval. The agent can ask for one request to be approved, or
ask for a short window (up to 30 minutes) on one or more systems, during
which its requests to those systems run without asking again. The
approver gets a Telegram message showing exactly what was asked for, and
answers from their phone. No answer means no.

Wherever the target system allows it, Nyyrikki acts as the person the
agent works for, so the target's own logs show that person rather than a
shared service account. When it needs to, Nyyrikki creates short-lived
credentials on the target. Those stay inside Nyyrikki, like all the
others: the agent never sees a credential.

The project is in design. No code has been written yet. What is planned,
and in what order, is in [ROADMAP.md](ROADMAP.md).

## Documentation

- [ROADMAP.md](ROADMAP.md): what's planned and the status of each item
- [docs/](docs/README.md): one design doc per roadmap item, and how they are written
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes are made
- [CODE-REVIEW.md](CODE-REVIEW.md): coding and review rules
- [SECURITY.md](SECURITY.md): reporting a vulnerability
