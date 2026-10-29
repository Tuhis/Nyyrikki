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

**Remove the `roles` client scope** from the default scopes of every
client that signs in to Nyyrikki. Its audience-resolve mapper adds
`account` to `aud`, and Nyyrikki accepts only tokens whose `aud` is
exactly its own URL (docs/01 D9). Nyyrikki doesn't use roles.

## The CLI client

Clients → Create:

- Client ID `nyyrikki-cli`, client authentication **off** (public).
- Authentication flow: only **OAuth 2.0 Device Authorization Grant**.
- Advanced → **Require DPoP bound tokens: on**. Required: without it, CLI
  logins in one browser would be one agent (docs/01 OD14), and Nyyrikki
  refuses CLI tokens without `cnf.jkt`.
- Client scopes: `nyyrikki` as optional; remove `offline_access`.

## Dynamic Client Registration, for MCP harnesses

MCP harnesses register their own client (docs/01 D25, OD16), anonymously,
so anyone who can reach Keycloak can register one. A registration alone
grants nothing: a token still needs the owner's sign-in and consent, and
Nyyrikki accepts only the human in its registry. The settings below are
measured by the e2e test (`test/e2e`, docs/01 M9).

**What a registered client gets.** It gets the realm's default scopes:
Client scopes → set `roles` and `offline_access` to **None** (not Default
or Optional) and `nyyrikki` to **Optional**.

**Anonymous access policies** (Clients → Client registration):

- **Trusted Hosts**: "Host Sending Client Registration Request Must
  Match" **off**, "Client URIs Must Match" **on**, Trusted Hosts
  `localhost` and `127.0.0.1`. Redirect URIs then have to be on loopback,
  so a sign-in's code can only go back to the machine it started on.
- **Allowed Client Scopes**: add `nyyrikki`.
- Leave **Consent Required** on (the owner sees each new client by name)
  and **Max Clients** as it is.

**PKCE for every client** (docs/01 D7). Realm settings → Client
policies:

- Profiles → Create `nyyrikki-pkce`, executor **pkce-enforcer** with
  Auto-configure on.
- Policies → Create `nyyrikki-pkce`, condition **any-client**, profile
  `nyyrikki-pkce`.

Registered clients then get PKCE S256 set, and Keycloak refuses their
authorization requests without it. It requires PKCE in their device grant
too, which the CLI sends from the first release after 0.2.0. Older CLIs
fail there with `Missing parameter: code_challenge_method`: in
`nyyrikki login --mcp`, and, not measured, in `nyyrikki login` too if
`nyyrikki-cli` is saved in the admin console after the policy exists
(auto-configure runs when a client is created or updated).

**Expose registration only where your agents are.** If Keycloak is on the
internet but your agents aren't, allow
`/realms/<realm>/clients-registrations/` only from your own networks at
the proxy in front of Keycloak.

What the e2e test found that the policies don't stop, and why it is safe:

- A registered client may ask for the password grant; Keycloak issues it
  no token.
- A registered confidential client gets a client-credentials token with
  Nyyrikki's audience. Its `sub` is a service account, not a human in the
  registry, so Nyyrikki answers 401.

## The introspection client

Clients → Create, with **Client ID equal to Nyyrikki's audience**,
`NYYRIKKI/mcp` (the same URL as the audience mapper above). Client
authentication **on**, no flows enabled: it only introspects.

Keycloak 26.8 introspects a token only for a client that is in the
token's audience (it logs `Client '…' is not in the token audience` and
answers `active: false` otherwise). Naming the introspection client after
the audience keeps `aud` exactly one value, as Nyyrikki requires, and
satisfies that check. The chart uses this client ID by default
(`auth.introspectionClientID` empty). Put its secret in the Secret named
by the chart's `secrets.introspection`.

## Revoking an agent

Users → the owner → Sessions → sign the session out. Nyyrikki introspects
on every run and elevate, so the agent is cut off at once (docs/01 OD13).
