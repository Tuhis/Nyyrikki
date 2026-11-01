# Setting up Nyyrikki

To try Nyyrikki on one Linux machine before deploying it, see
[Try it locally](quickstart.md).

In order:

1. [Keycloak](keycloak.md): the realm, the clients and the audience scope.
2. [Telegram](telegram.md): the bot, and the approver's account.
3. [Install](install.md): Secrets, values, the chart, remote targets.
4. [Agents](agents.md): signing agents in through the CLI or an MCP harness.
5. [SSH hosts](ssh-hosts.md), if any target is an SSH host: the user CA,
   and setting up each host.

Before going live, check the deployment requirements in
[SECURITY.md](../../SECURITY.md#deployment-requirements). Nyyrikki's guarantees
hold only if they are true.
