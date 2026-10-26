# Nyyrikki

An AI-native identity-aware proxy (IAP) for self-hosted infrastructure,
with escalation handling through Telegram.

AI coding agents are useful until a task needs admin access: an
imperative `kubectl`, a root shell on a server, a call to the Keycloak
admin API. Nyyrikki lets an agent ask for that access for a limited time,
from the thread it is working in.

An approver gets a Telegram message with the context, and approves or
denies the request from their phone. While the grant lasts, Nyyrikki
holds the real credentials and passes every operation through policy:

- routine operations go straight through;
- operations that need a closer look wait for another tap;
- everything is recorded.

When the grant ends, so does the access. Anything Nyyrikki can't decide
is denied.

The project is in design. No code has been written yet. What is planned,
and in what order, is in [ROADMAP.md](ROADMAP.md).

## Documentation

- [ROADMAP.md](ROADMAP.md): what's planned and the status of each item
- [docs/](docs/README.md): one design doc per roadmap item, and how they are written
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes are made
- [CODE-REVIEW.md](CODE-REVIEW.md): coding and review rules
- [SECURITY.md](SECURITY.md): the threat model, and reporting a vulnerability
