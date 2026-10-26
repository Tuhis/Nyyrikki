# Gotchas

Hard-won lessons, each of which cost real debugging time. This file is the
consolidated list. The details live in the linked design docs. The rule in
[CLAUDE.md](../CLAUDE.md) is that a gotcha has exactly one home, here,
rather than being restated in the doc that discovered it.

Add to it when a new gotcha lands in `docs/`. Group entries under a bold
heading per area, one bullet each: the trap, why it bites, and a link to
the doc.

---

**Kubernetes**

- **`RequestInfo` doesn't produce `exec`, `attach`, `portforward` or
  `proxy` verbs.** It reports the HTTP-method verb plus the
  subresource, so a WebSocket exec is `get pods` with subresource
  `exec`, and it passes as a read unless the verb is overridden.
  ([docs/07](07-kubernetes-proxy.md) M1, D4)
- **kubectl ≥ 1.30 retries over SPDY after any refused WebSocket
  upgrade**, a 403 included. Every exec denial shows up twice, and SPDY
  must be refused as well. ([docs/07](07-kubernetes-proxy.md) M3)
- **Before 1.35, the apiserver has no `create` check for WebSocket
  exec.** On those versions, `get pods/exec` alone permits exec, so a
  broad `get *` RBAC role grants it. ([docs/07](07-kubernetes-proxy.md)
  M5, OD1)
- **For `nodes/<n>/proxy/<path>`, the proxied path only appears in
  `RequestInfo.Parts`**, not in `Name` or `Subresource`, so policy can't
  see it. ([docs/07](07-kubernetes-proxy.md) M2)
- **Every impersonated user is also in `system:authenticated`.** The
  apiserver adds the group itself, so anything a cluster binds to it is
  part of every profile's RBAC. ([docs/07](07-kubernetes-proxy.md) M9)
- **`SelfSubjectRulesReview` never comes back empty, and it sees one
  namespace.** Every identity gets the bootstrap discovery and
  self-review rules, and `spec.namespace` is required, so a RoleBinding
  in a namespace you didn't ask about is invisible.
  ([docs/07](07-kubernetes-proxy.md) M10, D11)
- **A RoleBinding can name a ServiceAccount as `kind: User`**, with the
  username `system:serviceaccount:<ns>:<name>`. An audit that looks only
  for `kind: ServiceAccount` subjects misses it.
  ([docs/09](09-packaging-and-deployment.md) §5.4)
- **Client-side `kubectl apply` copies the whole object into the
  `kubectl.kubernetes.io/last-applied-configuration` annotation**, as a
  JSON string. Redacting a Secret's `data` but keeping its metadata
  still leaks the values through it. ([docs/03](03-audit-log.md) §5.9)

**Go: TLS and HTTP**

- **`tls.Config.VerifyPeerCertificate` is not called on resumed
  connections.** Revocation checks belong in `VerifyConnection`, which
  runs on every connection, and in a per-request check, because a
  kept-alive connection outlives a revocation.
  ([docs/02](02-grant-core.md) M2, D7)
- **`httputil.ReverseProxy.Director` can be defeated by the client**,
  which can list any header in `Connection` and so strip headers the
  proxy added. Use `Rewrite`. ([docs/06](06-http-proxy.md) M1)
- **`http.DefaultTransport` honours `HTTP(S)_PROXY`.** Upstream
  transports need `Proxy: nil`, or an environment variable on G can
  redirect privileged traffic. ([docs/06](06-http-proxy.md) M2)
- **`url.PathEscape("..")` is `".."`.** A dot-segment check on raw
  segments, followed by decoding and re-encoding, forwards `%2e%2e` as a
  literal `..`. Decode first, then check. ([docs/06](06-http-proxy.md)
  M4)

**Telegram Bot API**

- **`callback_data` is client-controlled.** A modified client can send
  any bytes for any message it can see, so it can only ever be an opaque
  key to server-side state. ([docs/04](04-telegram-escalation.md) M2)
- **`getUpdates` fails while a webhook is set.** Unconfirmed updates are
  kept for only 24 h, and a crash between processing an update and
  confirming it redelivers it. ([docs/04](04-telegram-escalation.md) M5)
- **A `409 Conflict` from `getUpdates` means someone else is using the
  token**, through a webhook or a second poller. Backing off and
  retrying hands them the approvals. Stop instead.
  ([docs/04](04-telegram-escalation.md) M17)
- **Bots can delete only messages younger than 48 h, but can edit
  without a time limit.** Retire prompts by editing them.
  ([docs/04](04-telegram-escalation.md) M8)

**Keycloak**

- **`PUT …/users/{id}/reset-password` sends the new password as a bare
  `{"type":"password","value":"…"}`**, with `value` at the root, so
  redacting only `credentials[].value` leaks it.
  ([docs/03](03-audit-log.md) §5.9)

**Tooling and dependencies**

- **`gopkg.in/yaml.v3` has been unmaintained since 2022.** Use
  `go.yaml.in/yaml/v3`. ([docs/01](01-foundations.md) M4)
- **Claude Code never reads `mcpServers` from `settings.json`.** Servers
  live in `~/.claude.json` or `.mcp.json`. Also, `claude mcp add`
  rejects the server name if it directly follows `--env`.
  ([docs/05](05-agent-integration.md) M1, M2)
- **Codex's MCP timeout defaults differ between its docs and its
  source.** Set `startup_timeout_sec` and `tool_timeout_sec` explicitly.
  ([docs/05](05-agent-integration.md) M5)
- **asciicast v3 (the asciinema 3.x default) isn't readable by
  asciinema 2.x**, and its timestamps are relative intervals rather than
  absolute times. ([docs/03](03-audit-log.md) M2)
