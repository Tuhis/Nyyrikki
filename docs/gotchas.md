# Gotchas

Hard-won lessons, each of which cost real debugging time. This file is the
consolidated list. The details live in the linked design docs. The rule in
[CLAUDE.md](../CLAUDE.md) is that a gotcha has exactly one home, here,
rather than being restated in the doc that discovered it.

The entries below were found while writing the design docs of the
replaced Warden plan (2026-10-25). They are facts about Kubernetes, Go,
Telegram, Keycloak and MCP clients, so they still apply. Their links
point to those docs as of the commit they were written in, where the
evidence is. The measurements behind them are also in
[`measured.md`](measured.md).

Add to it when a new gotcha lands in `docs/`. Group entries under a bold
heading per area, one bullet each: the trap, why it bites, and a link to
the doc.

---

**Kubernetes**

- **`RequestInfo` doesn't produce `exec`, `attach`, `portforward` or
  `proxy` verbs.** It reports the HTTP-method verb plus the
  subresource, so a WebSocket exec is `get pods` with subresource
  `exec`, and it passes as a read unless the verb is overridden.
  ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M1, D4)
- **kubectl ≥ 1.30 retries over SPDY after any refused WebSocket
  upgrade**, a 403 included. Every exec denial shows up twice, and SPDY
  must be refused as well. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M3)
- **Before 1.35, the apiserver has no `create` check for WebSocket
  exec.** On those versions, `get pods/exec` alone permits exec, so a
  broad `get *` RBAC role grants it. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md)
  M5, OD1)
- **For `nodes/<n>/proxy/<path>`, the proxied path only appears in
  `RequestInfo.Parts`**, not in `Name` or `Subresource`, so policy can't
  see it. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M2)
- **Every impersonated user is also in `system:authenticated`.** The
  apiserver adds the group itself, so anything a cluster binds to it is
  part of every profile's RBAC. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M9)
- **`SelfSubjectRulesReview` never comes back empty, and it sees one
  namespace.** Every identity gets the bootstrap discovery and
  self-review rules, and `spec.namespace` is required, so a RoleBinding
  in a namespace you didn't ask about is invisible.
  ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M10, D11)
- **A RoleBinding can name a ServiceAccount as `kind: User`**, with the
  username `system:serviceaccount:<ns>:<name>`. An audit that looks only
  for `kind: ServiceAccount` subjects misses it.
  ([docs/09](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/09-packaging-and-deployment.md) §5.4)
- **Client-side `kubectl apply` copies the whole object into the
  `kubectl.kubernetes.io/last-applied-configuration` annotation**, as a
  JSON string. Redacting a Secret's `data` but keeping its metadata
  still leaks the values through it. ([docs/03](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/03-audit-log.md) §5.9)

- **kubectl ≥ 1.33 reads a kuberc preferences file** (`~/.kube/kuberc`,
  or `$KUBERC`) that can define aliases and default flags, so the same
  argv can mean something else on another machine. Turn it off with
  `KUBERC=off` and refuse `--kuberc`. ([docs/04](04-kubectl-passthrough.md) M3)
- **kubectl reads files and URLs from the machine it runs on**: `-f`
  paths and URLs, `-k`, `--from-file`, `--from-env-file`,
  `-o jsonpath-file=`, `debug --custom`. Server-side, those are
  Nyyrikki's disk. ([docs/04](04-kubectl-passthrough.md) M7)

**Go: TLS and HTTP**

- **`tls.Config.VerifyPeerCertificate` is not called on resumed
  connections.** Revocation checks belong in `VerifyConnection`, which
  runs on every connection, and in a per-request check, because a
  kept-alive connection outlives a revocation.
  ([docs/02](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/02-grant-core.md) M2, D7)
- **`httputil.ReverseProxy.Director` can be defeated by the client**,
  which can list any header in `Connection` and so strip headers the
  proxy added. Use `Rewrite`. ([docs/06](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/06-http-proxy.md) M1)
- **`http.DefaultTransport` honours `HTTP(S)_PROXY`.** Upstream
  transports need `Proxy: nil`, or an environment variable on G can
  redirect privileged traffic. ([docs/06](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/06-http-proxy.md) M2)
- **`url.PathEscape("..")` is `".."`.** A dot-segment check on raw
  segments, followed by decoding and re-encoding, forwards `%2e%2e` as a
  literal `..`. Decode first, then check. ([docs/06](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/06-http-proxy.md)
  M4)

**Telegram Bot API**

- **`callback_data` is client-controlled.** A modified client can send
  any bytes for any message it can see, so it can only ever be an opaque
  key to server-side state. ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M2)
- **`getUpdates` fails while a webhook is set.** Unconfirmed updates are
  kept for only 24 h, and a crash between processing an update and
  confirming it redelivers it. ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M5)
- **A `409 Conflict` from `getUpdates` means someone else is using the
  token**, through a webhook or a second poller. Backing off and
  retrying hands them the approvals. Stop instead.
  ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M17)
- **Bots can delete only messages younger than 48 h, but can edit
  without a time limit.** Retire prompts by editing them.
  ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M8)

**Keycloak**

- **`PUT …/users/{id}/reset-password` sends the new password as a bare
  `{"type":"password","value":"…"}`**, with `value` at the root, so
  redacting only `credentials[].value` leaks it.
  ([docs/03](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/03-audit-log.md) §5.9)
- **`sid` is the browser's SSO session, not one sign-in.** Every sign-in
  in the same browser session shares it, and very likely so does a
  sign-in that made the user authenticate again (`prompt=login`, or no
  Cookie authenticator). Keying an agent on it merges sign-ins.
  ([docs/01](01-foundations.md) OD14)

- **Keycloak 26.8 introspects a token only for a client in the token's
  audience.** Any other client gets `active: false`, logged as `Client '…'
  is not in the token audience`, which looks exactly like a revoked
  session. Name the introspection client after the resource's audience.
  ([docs/01](01-foundations.md) M9, D7)
- **Keycloak's default `roles` client scope adds `account` to `aud`**
  (through its audience-resolve mapper), so a resource that requires a
  single audience refuses every token. Remove the scope from the clients.
  ([docs/01](01-foundations.md) M9)
- **A client registered through DCR gets the realm's default scopes**,
  not the ones a client set up by hand has. Take `roles` and
  `offline_access` out of the realm's defaults, or every registered client
  gets them. ([docs/01](01-foundations.md) M9)
- **Keycloak requires PKCE in the device grant for a client with PKCE
  set**, which the pkce-enforcer client policy does for every registered
  client: without `code_challenge` the device authorization request fails
  with `Missing parameter: code_challenge_method`. Send PKCE there too.
  ([docs/01](01-foundations.md) M9)
- **Any registered confidential client gets a client-credentials token
  carrying your audience.** Its `sub` is a service account; only a check
  of `sub` against the human registry refuses it. Never accept a token on
  audience alone. ([docs/01](01-foundations.md) M9, D8)

**MCP**

- **The go-sdk's `auth.RequireBearerToken` accepts only the `Bearer`
  scheme**, and turns any verifier error that isn't `ErrInvalidToken`
  into a 500. DPoP-bound tokens need your own middleware.
  ([docs/01](01-foundations.md) M2)
- **Claude Code reads credential-like variables as empty in a remote
  server's `url` and `headers`, and strips variables whose names contain
  `TOKEN`, `SECRET`, `PASSWORD`, `KEY` or `AUTH` from a project
  `.mcp.json`'s `headersHelper`.** Name the helper's variables
  accordingly. ([docs/01](01-foundations.md) M14)

**Tooling and dependencies**

- **`gopkg.in/yaml.v3` has been unmaintained since 2022.** Use
  `go.yaml.in/yaml/v3`. ([docs/01](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/01-foundations.md) M4)
- **Claude Code never reads `mcpServers` from `settings.json`.** Servers
  live in `~/.claude.json` or `.mcp.json`. Also, `claude mcp add`
  rejects the server name if it directly follows `--env`.
  ([docs/05](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/05-agent-integration.md) M1, M2)
- **Codex's MCP timeout defaults differ between its docs and its
  source.** Set `startup_timeout_sec` and `tool_timeout_sec` explicitly.
  ([docs/05](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/05-agent-integration.md) M5)
- **asciicast v3 (the asciinema 3.x default) isn't readable by
  asciinema 2.x**, and its timestamps are relative intervals rather than
  absolute times. ([docs/03](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/03-audit-log.md) M2)
