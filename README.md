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
others: Nyyrikki never hands a credential to the agent. (A request you
approve, or one under an elevation you grant, runs with your rights, so
it can read whatever you can read;
see [SECURITY.md](SECURITY.md).)

The first target is Kubernetes. An agent sends a kubectl command line,
the approver sees that command line, and Nyyrikki runs exactly it as the
person, through Kubernetes impersonation. Interactive `exec` and `attach`
work through the CLI.

The server, `nyyrikkid`, runs in Kubernetes from a Helm chart. Agents
sign in through an OAuth authorization server (Keycloak is the reference).
Status and plans are in [ROADMAP.md](ROADMAP.md).

## Documentation

- [docs/setup/](docs/setup/README.md): installing Nyyrikki and signing agents in
- [ROADMAP.md](ROADMAP.md): what's planned and the status of each item
- [docs/](docs/README.md): one design doc per roadmap item, and how they are written
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes are made
- [CODE-REVIEW.md](CODE-REVIEW.md): coding and review rules
- [SECURITY.md](SECURITY.md): reporting a vulnerability
