# Measured facts carried over

Facts that were tested or sourced from a primary source while writing the
design docs of the replaced Warden plan (2026-10-25). The plan and its
docs were removed on 2026-10-26 (`ROADMAP.md`), but these measurements
are about Kubernetes, SSH, Telegram, MCP clients and Go libraries, not
about that plan, so they are kept here.

How to use them:

- A new design doc that leans on one of these copies it into its own
  "Measured and verified" table **after re-checking it** against the
  current version, and records the new date and version
  (`docs/README.md`, step 3). These rows are a starting point, not
  evidence for a new decision.
- The "Result" column sometimes names decisions (`D4`), chunks or
  sections of the removed docs. Those references are to the old plan.
  The linked source doc, kept at the commit it was written in, has the
  context and the code or output each claim came from.
- Traps worth remembering on their own are in
  [`gotchas.md`](gotchas.md).

## Foundations, toolchain and Go libraries

From [docs/01](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/01-foundations.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Latest Go is 1.27.3 (2026-10-19). A major release is supported until two newer majors exist, so 1.26 and 1.27 are supported today. The local toolchain (1.26.8) is two security releases behind. | [go.dev/doc/devel/release](https://go.dev/doc/devel/release), `go.dev/dl/?mode=json` | Confirmed. Drives D4 |
| M2 | `k8s.io/apiserver` and `k8s.io/apimachinery` v0.37.1, `golang.org/x/crypto` v0.58.0 and `modernc.org/sqlite` v1.61.0 all declare `go 1.26.0` | ran `go mod tidy` and `go build` with Go 1.26.8 | Confirmed: Go ≥ 1.26 is the floor |
| M3 | `modernc.org/sqlite` v1.61.0 is pure Go: it builds and runs with `CGO_ENABLED=0`, and WAL works. Licence BSD-3-Clause. | ran a test, `PRAGMA journal_mode=WAL` returned `wal` | Confirmed. Static binaries (D6) |
| M4 | `gopkg.in/yaml.v3` (go-yaml/yaml) is archived ("THIS PROJECT IS UNMAINTAINED"), with the last release v3.0.1 on 2022-05-27. The maintained successor is `go.yaml.in/yaml/v3` v3.0.5 (2026-07-26): a frozen API, security fixes only, licence MIT and Apache-2.0. | GitHub API, both READMEs, proxy.golang.org | Confirmed. Drives D7 |
| M5 | `golang.org/x/crypto/ssh` v0.58.0 (BSD-3-Clause) supports both the server side (`ServerConfig`, `NewServerConn`) and the client side, including `Certificate.SignCert` and `CertChecker` | pkg.go.dev; ran a test with a CA-signed host certificate verified through `CertChecker` | Confirmed. The SSH proxy needs no other library (docs/08) |
| M6 | `github.com/oklog/ulid/v2` v2.1.2 (Apache-2.0); `github.com/coder/websocket` v1.8.15 (ISC) | proxy.golang.org, LICENSE files | Confirmed |
| M7 | `github.com/modelcontextprotocol/go-sdk` v1.8.0 (2026-09-04) is v1 with a compatibility promise, has a stdio transport, and supports MCP spec revision 2026-07-28. Its licence is mid-transition: MIT and Apache-2.0 for code, CC-BY-4.0 for docs. | module source, README, LICENSE; compile test | Confirmed. D9 allows CC-BY-4.0 for documentation files only |
| M8 | Kubernetes libraries are Apache-2.0 | kubernetes/kubernetes `LICENSE` | Confirmed |
| M9 | Versions and exact command-line flags of the gate tools (staticcheck, govulncheck, go-licenses, gitleaks), and `go mod tidy -diff`; how `go-licenses` classifies the MCP go-sdk (M7) | **Not yet measured.** FN2 pins the versions, checks the flags in §5.8 against each tool's help output, runs `go-licenses report` on the go-sdk, and records all three here | — |

## Go TLS and grant mechanics

From [docs/02](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/02-grant-core.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | With `modernc.org/sqlite`, a compare-and-set `UPDATE grants SET state=? WHERE id=? AND state='pending'` run concurrently by three goroutines has exactly one winner (`RowsAffected()==1`), so the DB row can be the single authoritative signal for racing transitions (D3) | Ran a test, 2026-10-25: Go 1.26.8, `modernc.org/sqlite` v1.61.0, WAL, `busy_timeout=5000`. 200 rounds × 3 concurrent transitions (`active`, `denied`, `request_expired`) on one row | Confirmed: exactly one winner in every round. WAL mode reported by `PRAGMA journal_mode` |
| M2 | Go's `crypto/tls` does **not** call `Config.VerifyPeerCertificate` on resumed connections; `Config.VerifyConnection` runs on every connection, resumptions included | `go doc crypto/tls.Config`, Go 1.26.8, 2026-10-25 | Confirmed, quoted: "This callback is not invoked on resumed connections" (VerifyPeerCertificate); "This callback will run for all connections, including resumptions" (VerifyConnection). Drives D7 and a gotcha |
| M3 | The stdlib covers the internal CA: `x509.ParseCertificateRequest`, `(*CertificateRequest).CheckSignature`, `x509.CreateCertificate`; constant-time compare via `crypto/subtle.ConstantTimeCompare` | `go doc`, Go 1.26.8, 2026-10-25 | Confirmed. No third-party PKI library is needed |
| M4 | `encoding/json.Decoder.DisallowUnknownFields` exists for strict request decoding | `go doc`, Go 1.26.8 | Confirmed |
| M5 | ULID and YAML library status and licences | [docs/01](01-foundations.md) §2 | See docs/01 M-rows (single home) |

## Audit and recordings

From [docs/03](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/03-audit-log.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Go's `encoding/json` sorts map keys when marshaling. `Encoder.SetEscapeHTML(false)` turns off the `<`, `>`, `&` escaping. | `go doc encoding/json.Marshal`, `go doc encoding/json.Encoder.SetEscapeHTML`, Go 1.26.8, 2026-10-25 | Confirmed. The canonical form in §5.2 relies on both |
| M2 | asciicast **v2** is still parsed by the current asciinema player (v3.17.0) and by CLI 3.x (v3.2.1), which can also still write it (`--output-format asciicast-v2`). CLI 3.x writes **v3** by default. v3 is not backward compatible: it uses relative event intervals, a `term` header object and an `x` exit event. | [docs.asciinema.org asciicast v2 and v3](https://docs.asciinema.org/manual/asciicast/v3/), CLI `src/cli.rs`, player `src/parser/asciicast.js`, 2026-10-25 | Confirmed. Drives D7 |
| M3 | OpenSSH's sshd logs the user certificate's key ID on login, for example `Accepted publickey for alice … ED25519-CERT SHA256:… ID <keyid> (serial N) CA ED25519 SHA256:…` | ran OpenSSH 10.3p1 in docker, 2026-10-25 | Confirmed. Target logs can be correlated with `ss_` IDs (docs/08 §5.9) |
| M4 | `crypto/ed25519` is in the standard library | `go doc crypto/ed25519` | Confirmed. Anchors need no dependency |

## Telegram Bot API

From [docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `callback_data` is 1–64 bytes | [Bot API: InlineKeyboardButton](https://core.telegram.org/bots/api#inlinekeyboardbutton) | Confirmed: "1-64 bytes" |
| M2 | Callback `data` is **not** checked by Telegram against the buttons on the message. A modified client can send any bytes for any message it can see. | [Bot API: CallbackQuery](https://core.telegram.org/bots/api#callbackquery); [MTProto messages.getBotCallbackAnswer](https://core.telegram.org/method/messages.getBotCallbackAnswer) (takes `peer`, `msg_id`, arbitrary `data:bytes`) | Confirmed. The Bot API says "the message originated the query can contain no callback buttons with this data". D5 treats `data` as an opaque lookup key and nothing more. |
| M3 | `CallbackQuery.message` may be an `InaccessibleMessage` (fields `chat`, `message_id`, and `date` = 0) when the message was deleted or is otherwise inaccessible | Bot API: MaybeInaccessibleMessage | Confirmed. `chat.id` and `message_id` are still present, so D5's checks still work |
| M4 | Clients show a progress indicator until the bot calls `answerCallbackQuery` | Bot API: CallbackQuery | Confirmed |
| M5 | `getUpdates` long polling: `timeout` in seconds. An update is confirmed once `getUpdates` is called with a higher `offset`. It doesn't work while a webhook is set. Unconfirmed updates are kept for at most 24 h. `allowed_updates` persists between calls. | [Bot API: getUpdates](https://core.telegram.org/bots/api#getupdates) | Confirmed. Consequences: D2 (no webhook), D3 (offset committed with the effects), D12 (24 h loss is harmless because decisions expire within minutes) |
| M6 | `sendMessage` has `protect_content` ("Protects the contents of the sent message from forwarding and saving") and `link_preview_options.is_disabled`. Text is 1–4096 characters after entity parsing. | Bot API: sendMessage | Confirmed |
| M7 | HTML parse mode: every `<`, `>` and `&` that is not part of a tag or entity must be escaped. Named entities supported: only `&lt; &gt; &amp; &quot;`. `<pre>`, `<code>`, `<blockquote>` and `<blockquote expandable>` are supported. | [Bot API: HTML style](https://core.telegram.org/bots/api#html-style) | Confirmed. Drives §5.7 |
| M8 | A bot can edit its own messages without a time limit. The 48 h limit applies only to some business messages. **Deleting** is limited to messages less than 48 h old. | Bot API: editMessageText, editMessageReplyMarkup, deleteMessage | Confirmed. Prompts are retired by editing, never by deleting (D9) |
| M9 | Bots can't start a conversation. Deep link `t.me/<bot>?start=<param>`: up to 64 characters of `A-Z a-z 0-9 _ -`, arriving as the message `/start <param>` | [Bots: deep linking](https://core.telegram.org/bots/features#deep-linking) | Confirmed. Drives pairing (§5.2) |
| M10 | A forwarded copy of a message keeps its inline keyboard only if the keyboard has nothing but URL or login buttons, so callback buttons are stripped | [Bot API changelog, 4.3 (2019-05-31)](https://core.telegram.org/bots/api-changelog) | Confirmed in the changelog only, not in the current reference. Not relied on: D5 checks `from.id` regardless |
| M11 | `keyboardButtonCallback.requires_password` (the user re-enters their 2FA password before the tap reaches the bot) is not exposed to Bot API bots | MTProto constructor docs; the Bot API reference has no such field | Confirmed absent. So a 2FA-on-tap step-up is not available (RR-3 in SECURITY.md) |
| M12 | Bot chats are cloud chats: Telegram's servers see message content | [telegram.org/faq](https://telegram.org/faq) ("Server-client encryption is used in Cloud Chats (private and group chats)") | Confirmed. Telegram is in the trust base (SECURITY.md RR-6, OD1) |
| M13 | Rate limits: about 1 message per second per chat; about 30 per second overall | [Bots FAQ](https://core.telegram.org/bots/faq) | Confirmed. The per-chat send queue in §5.8 respects these |
| M14 | Telegram accounts support 2-Step Verification (a cloud password in addition to the SMS code), a local passcode lock, and a list of active sessions that can be terminated. "whoever has the number, has the account" without 2SV. | telegram.org/faq | Confirmed. The approver setup in §5.2 requires the first two. A bot cannot check either (D13) |
| M15 | `User.id` has at most 52 significant bits (safe in int64). In a private chat, the chat ID equals the user's ID. | Bot API: User; [MTProto bot IDs](https://core.telegram.org/api/bots/ids) | `User.id`: confirmed. The private-chat equality is only indirect ("MTProto user IDs are equal to bot API user dialog IDs"). D4 therefore checks `chat.id == from.id` explicitly and doesn't assume it |
| M16 | Do Telegram clients auto-link `/commands`, URLs and `@mentions` inside `<pre>` and `<code>`? | **Not yet verified.** Measure in TG5 with a real bot and the official Android and iOS clients | D7 makes the answer non-critical: no text command escalates |
| M17 | `getUpdates` fails with `409 Conflict` while another `getUpdates` poller is running on the same token, or while a webhook is set. | Bot API reference ("will not work if an outgoing webhook is set up"); python-telegram-bot maps 409 to `telegram.error.Conflict` for both cases | Partly: the webhook case is documented, the competing-poller case is library behaviour. **TG1 measures both** against the real Bot API and records the error descriptions |

## MCP clients (Claude Code, Codex)

From [docs/05](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/05-agent-integration.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Claude Code stores MCP servers per scope:<br>• local: `~/.claude.json` under `projects["<path>"].mcpServers`<br>• user: `~/.claude.json`, top-level `mcpServers`<br>• project: `.mcp.json` at the repository root<br>`mcpServers` is **not** read from any `settings.json`. | [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp) (installation scopes), [debug-your-config](https://code.claude.com/docs/en/debug-your-config): "`settings.json` does not read an `mcpServers` key" | Confirmed. The Warden design was wrong on this point |
| M2 | `claude mcp add [options] <name> -- <command> [args…]` with `-s/--scope local\|project\|user`, `-e/--env KEY=value` and `-t/--transport stdio`. **Gotcha**: if the server name comes directly after `--env`, the CLI parses it as another `KEY=value` and rejects it. | code.claude.com/docs/en/mcp | Confirmed. §5.7 never puts the name after `--env` |
| M3 | Claude Agent SDK (which T3 Code's Claude adapter uses): `settingSources: "project"` loads `.mcp.json`. `~/.claude.json` is read whatever `settingSources` says. The SDK also accepts servers programmatically through `options.mcpServers`. | code.claude.com/docs/en/agent-sdk/mcp, …/agent-sdk/claude-code-features | **Partly**: that user-scope servers from `~/.claude.json` reach a T3 Code thread is inferred from these docs, **not tested**. AG4 measures it |
| M4 | Claude Code: `MCP_TIMEOUT` (server startup, default 30 000 ms) and `MCP_TOOL_TIMEOUT` (default 100 000 000 ms). Stdio servers "have no per-request timer". Calls still running after 2 min move to the background. | code.claude.com/docs/en/env-vars, …/mcp#time-limits-on-mcp-tool-calls | Confirmed. A 55 s long-poll per call (D6) is safe |
| M5 | Codex reads `[mcp_servers.<name>]` from `~/.codex/config.toml`, with `command`, `args`, `env`, `env_vars`, `startup_timeout_sec` and `tool_timeout_sec`. `codex mcp add <name> -- <cmd…>` writes the user config and has no timeout flags. The **defaults conflict**: the docs say 10 s startup and 60 s per tool, but source release rust-v0.164.0 (2026-10-23) uses 30 s and 300 s. | learn.chatgpt.com config reference; github.com/openai/codex `codex-rs/codex-mcp/src/rmcp_client.rs`, `codex-rs/cli/src/mcp_cmd.rs` | Partly. §5.7 sets both timeouts explicitly |
| M6 | MCP progress notifications (`notifications/progress` with `progressToken`) exist in the current spec revision **2026-07-28**. That revision replaces the `initialize` handshake with `server/discover`. | [modelcontextprotocol.io/specification/2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/utilities/progress) | Confirmed |
| M7 | `github.com/modelcontextprotocol/go-sdk` v1.8.0 supports spec 2026-07-28 and provides a stdio transport | docs/01 M7 | Confirmed |

## Go HTTP reverse proxying

From [docs/06](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/06-http-proxy.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `httputil.ReverseProxy.Director` is unsafe for this purpose. Hop-by-hop headers are removed *after* `Director` runs, so a client can list any header in `Connection` and strip headers the proxy added. `Rewrite` runs after that removal, and also drops inbound `Forwarded` and `X-Forwarded-*`. | `go doc net/http/httputil.ReverseProxy`, Go 1.26.8, 2026-10-25 | Confirmed, quoted: "this permits a malicious client to remove any headers that may be added by Director … Rewrite addresses these issues." Drives D3, and a gotcha |
| M2 | `http.DefaultTransport` uses `ProxyFromEnvironment`. A `Transport` with `Proxy: nil` uses no proxy. | `go doc net/http.Transport`, `go doc net/http.DefaultTransport` | Confirmed. Drives D7: environment variables on G can't redirect upstream traffic |
| M3 | Keycloak 26.8.1 (2026-10-13): the admin REST API can be called by a confidential client that has *Client authentication* and *Service account roles* enabled, using `grant_type=client_credentials`. The realm-management client roles include `view-users`, `query-users` and `manage-users`. The documented example uses the **master** realm with the full `admin` role. | keycloak.org server_development guide ("Authenticating with a service account"), server_admin guide | Partly. The mechanism is confirmed. The least-privilege shape (§5.7: a client in the target realm with only realm-management user roles) is assembled from separate pages, so HP4 measures it against a real Keycloak |
| M4 | `url.PathEscape` leaves `.` and `..` unescaped, and `url.Parse` decodes `%2e%2e` to `..` in `URL.Path`. A dot-segment check on raw segments, followed by decode and re-encode, forwards a literal `..`. | `go run` against Go 1.26.8, 2026-10-26: `PathEscape("..") == ".."`; `Parse(".../users/%2e%2e/%2e%2e/master").Path == ".../users/../../master"` | Confirmed (found in review of PR #1). Drives the order in §5.2: decode first, then check |

## Kubernetes API

From [docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `RequestInfoFactory` (k8s.io/apiserver v0.37.1) reports the **HTTP-method verb** for connect subresources, never `exec`, `attach`, `portforward` or `proxy`. WebSocket `GET …/exec` comes out as `get pods` with subresource `exec`, whatever the `Upgrade` headers say. | Ran code: k8s.io/apiserver and apimachinery v0.37.1, Go 1.26.8. Outputs below | Confirmed. Drives D4, and a gotcha |
| M2 | For `GET /api/v1/nodes/node-1/proxy/metrics`, the proxied path (`metrics`) is not in `Name` or `Subresource`. It appears only in `Parts`. | same test | Confirmed. Policy can't see proxied paths, so `proxy` is deny-by-default (§5.4) |
| M3 | kubectl uses WebSockets by default for exec, attach and cp since **1.30**, and for port-forward since **1.31**. If the WebSocket handshake fails (any non-101 reply, a 403 included), **kubectl falls back to SPDY**. The server-side gates are still beta in 1.37 and GA in 1.38. | kubectl `exec.go` and `portforward.go` (release-1.29 to 1.31); `kube_features.go` (release-1.37, master); KEP-4006 `kep.yaml` | Confirmed. Drives D9: every denial is seen twice, once per transport |
| M4 | The exec WebSocket client offers only the `v5.channel.k8s.io` subprotocol. Channels: 0 stdin, 1 stdout, 2 stderr, 3 error, 4 resize, 255 close (sent as `[255, streamID]`). Port-forward uses the subprotocol `SPDY/3.1+portforward.k8s.io`, which is SPDY tunnelled through a WebSocket. | `apimachinery/pkg/util/remotecommand/constants.go`, `client-go/tools/remotecommand/websocket.go`, `util/portforward/constants.go` (release-1.37) | Confirmed. Drives §5.7 |
| M5 | `AuthorizePodWebsocketUpgradeCreatePermission`: for a WebSocket `GET` on exec, attach or portforward, the apiserver performs an extra authorization check with verb `create`, so both `get` and `create` are required. Beta and on by default since **1.35**. The code is absent in 1.33 and 1.34. | `pkg/registry/core/pod/rest/authorize.go`, `kube_features.go` | Confirmed. On 1.34 and older, `get pods/exec` alone permits WebSocket exec (OD1) |
| M6 | Impersonation headers: `Impersonate-User`, `Impersonate-Group`, `Impersonate-Uid`, `Impersonate-Extra-<key>`. RBAC: verb `impersonate` on `users`, `groups` and `serviceaccounts` (core group), and on `uids` and `userextras/<key>` (`authentication.k8s.io`). `resourceNames` restricts which identities may be impersonated. **KEP-5284 constrained impersonation** is beta and on by default since 1.36. It adds verbs such as `impersonate:user-info` and `impersonate-on:user-info:<verb>`, with the legacy verb as a fallback. | [User impersonation](https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/), `kube_features.go` | Confirmed. The exact constrained-impersonation rule shape is measured in KP5 (D12) |
| M7 | Supported Kubernetes releases: 1.37 (latest 1.37.1), 1.36 and 1.35. 1.34 reaches end of life on 2026-10-27. | [kubernetes.io/releases](https://kubernetes.io/releases/) | Confirmed. OD1 |
| M8 | kubeconfig `AuthInfo.tokenFile` exists. client-go re-reads it periodically, and it takes precedence over `token`. | `go doc k8s.io/client-go/tools/clientcmd/api.AuthInfo`, client-go v0.37.1 | Confirmed. The token stays out of the kubeconfig (§5.10) |
| M9 | The apiserver adds `system:authenticated` to every impersonated non-anonymous user, unless the request names `system:authenticated` or `system:unauthenticated` itself. | `pkg/endpoints/filters/impersonation/impersonation.go` and `mode.go`, k8s.io/apiserver v0.37.1, 2026-10-26 | Confirmed (found in review of PR #1). Whatever a cluster binds to `system:authenticated` is part of every profile's effective RBAC (§5.11) |
| M10 | Bootstrap RBAC (release-1.37) binds three ClusterRoles to `system:authenticated`: `system:basic-user` (`create` on `selfsubjectaccessreviews`, `selfsubjectrulesreviews`, `selfsubjectreviews`), `system:discovery` and `system:public-info-viewer` (`get` on `/livez`, `/readyz`, `/healthz`, `/version`, `/version/`, `/openapi`, `/openapi/*`, `/api`, `/api/*`, `/apis`, `/apis/*`). ServiceAccounts also get `system:service-account-issuer-discovery` (`get` on `/.well-known/openid-configuration[/]`, `/openid/v1/jwks[/]`) and, when the ClusterTrustBundle gate is on, `get,list,watch clustertrustbundles`. `SelfSubjectRulesReview.spec.namespace` is required: the review returns cluster-wide rules plus that one namespace's. | `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go` (release-1.37); `go doc` of `SelfSubjectRulesReviewSpec`, k8s.io/api v0.36.4, 2026-10-26 | Confirmed from source (found in review of PR #1). Drives D11's allowlist and its namespace list. KP3 measures the live result on each supported version, including k3s's additions |

## SSH

From [docs/08](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/08-ssh-proxy.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `golang.org/x/crypto/ssh` v0.58.0 (BSD-3-Clause, needs Go 1.26) covers the server side (`ServerConfig`, `NewServerConn`), the client side, certificate signing (`Certificate.SignCert`, `NewCertSigner`) and certificate checking (`CertChecker`, `FixedHostKey`) | pkg.go.dev; ran a handshake test with a CA-signed host certificate | Confirmed |
| M2 | `golang.org/x/crypto/ssh/knownhosts` supports `@cert-authority` and `@revoked` lines | knownhosts.go source at v0.58.0 (`markerCert`, `markerRevoked`) | Confirmed. Pins and a host CA come from one standard file (D6) |
| M3 | `ssh.Certificate` has `KeyId`, `ValidPrincipals`, `ValidAfter`, `ValidBefore` and `Permissions` (critical options and extensions) | `go doc golang.org/x/crypto/ssh.Certificate`, v0.58.0 | Confirmed |
| M4 | OpenSSH sshd (`TrustedUserCAKeys`, `AuthorizedPrincipalsFile`) logs the certificate key ID at INFO: `Accepted publickey for alice … ED25519-CERT SHA256:… ID <keyid> (serial N) CA ED25519 SHA256:…` | ran OpenSSH 10.3p1 in an Alpine container | Confirmed. `KeyId = nyyrikki:<grant>:<session>` links target logs to Nyyrikki's audit log |
| M5 | sshd only allows `direct-tcpip` for a certificate login if the certificate carries the `permit-port-forwarding` extension, and only allocates a PTY with `permit-pty` | sshd(8) "AUTHORIZED_KEYS FILE FORMAT" / ssh-keygen(1) "CERTIFICATES" | **Not yet measured** against a live sshd. SH3 measures it. D8 depends on it |

## Packaging and deployment

From [docs/09](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/09-packaging-and-deployment.md) of the replaced plan.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Static binaries build with `CGO_ENABLED=0` given the chosen dependencies | docs/01 M3 (`modernc.org/sqlite` ran with `CGO_ENABLED=0`) | Confirmed for SQLite. FN2's CI builds all three binaries this way |
| M2 | The hardening directives in §5.2 are accepted by the systemd on the target distribution, with an acceptable `systemd-analyze security` exposure score | **Not yet measured.** DP1 runs it on the chosen OS (OD1) and records the score here | — |
| M3 | GitHub artifact attestations (`actions/attest-build-provenance`) are available for this private repository's plan | **Not yet measured.** DP2 checks it. If they are unavailable, releases ship SHA256SUMS only | — |
