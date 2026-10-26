# Keycloak

Nyyrikki is an OAuth resource server; it issues no tokens
([docs/01](../01-foundations.md) D6). Keycloak 26.4 or newer is needed for
DPoP. The setup below uses supported features only (docs/01 D7).

Write `NYYRIKKI` for Nyyrikki's canonical URL, e.g.
`https://nyyrikki.example.com`.

## Realm

- Create a realm, e.g. `nyyrikki`. The issuer is then
  `https://<keycloak>/realms/nyyrikki`.
- **Sessions** (Realm settings → Sessions): SSO Session Max a working day
  or less (e.g. 10 h). Agents sign in again after it.
- **No offline access**: remove `offline_access` from the realm's default
  scopes, so no client gets an offline token.

## The audience scope

Client scopes → Create `nyyrikki`, type **Optional**, protocol OpenID
Connect. Mappers → By configuration → **Audience**, "Included Custom
Audience" = `NYYRIKKI/mcp`, add to access token on. Nyyrikki accepts only
tokens whose `aud` is exactly that URL. Add the scope as an **optional**
client scope to every client below.

Make sure the scope's tokens carry `sid` (Keycloak's "basic" scope does).

## The CLI client

Clients → Create:

- Client ID `nyyrikki-cli`, client authentication **off** (public).
- Authentication flow: only **OAuth 2.0 Device Authorization Grant**.
- Advanced → **Require DPoP bound tokens: on**. Required: without it, CLI
  logins in one browser would be one agent (docs/01 OD14), and Nyyrikki
  refuses CLI tokens without `cnf.jkt`.
- Client scopes: `nyyrikki` as optional; remove `offline_access`.

## Dynamic Client Registration, for MCP harnesses

Clients → Client registration → Anonymous access policies:

- **Trusted Hosts**: off for host checks, but keep "Client URIs Must Match".
- Allowed redirect URIs: loopback only (`http://127.0.0.1/*`,
  `http://localhost/*`).
- **Allowed Client Scopes**: add `nyyrikki`.
- Leave the default "Consent Required" policy on; the owner sees each new
  client.

Each harness sign-in and each `nyyrikki login --mcp` registers its own
client (docs/01 OD16). `login --mcp` asks for the device grant; allow it
in the registration policies.

## The introspection client

Clients → Create `nyyrikki-introspect`, client authentication **on**, no
flows enabled (it only introspects). Put its secret in the Secret named by
the chart's `secrets.introspection`.

## Revoking an agent

Users → the owner → Sessions → sign the session out. Nyyrikki introspects
on every run and elevate, so the agent is cut off at once (docs/01 OD13).
