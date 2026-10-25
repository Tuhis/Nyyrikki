# Nyyrikki

An AI-native identity-aware proxy (IAP) for self-hosted services, with
escalation handling through Telegram.

Nyyrikki sits in front of your services and checks every request: who is
asking, whether policy allows it, and whether the request looks like
something that person normally does. Routine requests go straight
through. Unusual ones are escalated: an approver gets a Telegram message
with the context and approves or denies the request from their phone.
Anything Nyyrikki can't decide is denied.

The project is in design. No code has been written yet. What is planned,
and in what order, is in [ROADMAP.md](ROADMAP.md).

## Documentation

- [ROADMAP.md](ROADMAP.md): what's planned and the status of each item
- [docs/](docs/README.md): one design doc per roadmap item, and how they are written
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes are made
- [CODE-REVIEW.md](CODE-REVIEW.md): coding and review rules
- [SECURITY.md](SECURITY.md): reporting a vulnerability
