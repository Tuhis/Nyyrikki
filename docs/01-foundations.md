# R1 — Foundations: architecture, threat model, toolchain (docs/01)

**Status**: drafted 2026-10-26, owner decisions OD1–OD16 taken the same
day. Awaiting the owner's approval of the doc as a whole; merging the PR
that adds it is that approval. Status lives in
[`ROADMAP.md`](../ROADMAP.md). Still open after approval: the
measurements M9–M11, which FD3 makes before R2's and R4's docs lean on
them (§9), and M12, which FD2 makes.

Chunks **FD0–FD3** (`FD` = foundations; unused. The replaced plan's
`FN` is not reused, because `docs/measured.md` still refers to it).

**Relationship to earlier work**: replaces the replaced plan's
[docs/01](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/01-foundations.md)
(2026-10-25). Kept from it, after re-checking: Go, SQLite through a
pure-Go driver, strict YAML config, the gates and their canaries, pinned
CI actions, and the dependency policy. Changed: no dedicated gateway
host (Nyyrikki is a Helm-deployed service, OD2), human sign-in through
OAuth from the start instead of mTLS agent certificates (OD3), and one
remote MCP endpoint instead of an agent-side MCP binary (OD6).

---

## 1. Purpose

Every later item depends on choices nobody has made yet: what Nyyrikki
is written in, where it runs, how an agent proves who it is and which
human it acts for, how agents reach it, where its credentials live,
which target comes first, and what it defends against. Until those are
settled, R2–R6 can't be designed, and no code can be written
(`CLAUDE.md`).

When this doc is approved, an implementation agent can pick up any of
M1–M4 and find the architecture, the toolchain, the gates and the threat
model already decided, with the reasons.

### Non-goals

- The design of the operations, the decision point, pass-through,
  Telegram or the audit log. Those are R2–R5. This doc only fixes the
  frame they work in.
- More than one human, team or tenant (OD1). The data model keeps a
  "human" field everywhere so that more can be added later, but nothing
  in v1 is designed or tested for it.
- High availability. One replica (OD11).
- A web UI, an admin API or metrics. Configuration is the Helm values;
  the operator surface is R7.
- Target types other than Kubernetes (OD9).

## 2. Measured and verified before writing

All checked on 2026-10-26 unless stated otherwise.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Supported Go releases are 1.27 (latest 1.27.3) and 1.26 (latest 1.26.10) | `go.dev/dl/?mode=json` | Confirmed. Drives D1 |
| M2 | `github.com/modelcontextprotocol/go-sdk` v1.8.0 (2026-09-04) is the latest release. It serves Streamable HTTP (`mcp.NewStreamableHTTPHandler`, with a `Stateless` mode, DNS-rebinding protection on by default and `CrossOriginProtection`), offers `auth.RequireBearerToken` with a pluggable `TokenVerifier` that answers 401 with an RFC 9728 `resource_metadata` challenge, and has `oauthex.ProtectedResourceMetadata` and `oauthex.MatchesResource` for audience checks. `RequireBearerToken` accepts only the `Bearer` scheme (exactly two fields, the first `bearer` in any case), passes the verifier the token string and the request, and answers 500 for any verifier error that doesn't unwrap to `ErrInvalidToken`. Its client side targets spec 2026-07-28. | proxy.golang.org; read the v1.8.0 module source (`mcp/streamable.go`, `auth/auth.go` `verify`, `oauthex/`) | Confirmed. D6, D7. `RequireBearerToken` can't take a DPoP-bound token, so `/mcp` uses Nyyrikki's own authentication middleware (D9) |
| M3 | The go-sdk's licence is mid-transition from MIT to Apache-2.0 for code, with CC-BY-4.0 for documentation | `LICENSE` in the v1.8.0 module | Confirmed. D14 |
| M4 | MCP spec 2026-07-28, authorization: an HTTP MCP server is an OAuth 2.1 resource server and **MUST** publish RFC 9728 Protected Resource Metadata. The authorization server "may be hosted with the resource server or a separate entity". Client ID Metadata Documents are SHOULD; Dynamic Client Registration is MAY and "deprecated". Clients MUST send `resource` (RFC 8707). Servers MUST check that a token was issued for them as audience, "MUST only accept tokens that are valid for use with their own resources" and "MUST NOT accept or transit any other tokens". stdio servers SHOULD NOT use this flow. | [modelcontextprotocol.io/specification/2026-07-28/basic/authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Confirmed. D6, D7 |
| M5 | Keycloak 26.8.1 (2026-10-13) is the latest release | GitHub releases API | Confirmed |
| M6 | Keycloak's MCP guide lists RFC 8414 metadata, RFC 9207 issuer identification and Dynamic Client Registration as **supported**, and Client ID Metadata Documents (`--features=cimd`) and RFC 8707 resource indicators (`--features=resource-indicators`) as **experimental**. Without RFC 8707, an optional client scope with an Audience mapper puts the MCP server's URL in `aud`. The guide doesn't say which Keycloak version it documents. | [keycloak.org/securing-apps/mcp-authz-server](https://www.keycloak.org/securing-apps/mcp-authz-server) | Confirmed from the guide. Drives OD3's "if Keycloak supports it" and D7. FD3 checks it against a running 26.8.1 (M9) |
| M7 | Maintained Kubernetes releases are 1.37 (1.37.1), 1.36 (1.36.5) and 1.35 (1.35.9). 1.34 reaches end of life on 2026-10-27. | [kubernetes.io/releases](https://kubernetes.io/releases/) | Confirmed. D13 |
| M8 | `k8s.io/apiserver` v0.37.1 (2026-09-23) and `modernc.org/sqlite` v1.61.0 (2026-10-21) are the latest releases. Both need Go ≥ 1.26; the SQLite driver builds with `CGO_ENABLED=0` and supports WAL. | proxy.golang.org; the build facts are `docs/measured.md` (foundations M2, M3, 2026-10-25, same versions) | Versions confirmed. The CGO-free build is re-run by FD1's CI |
| M9 | Keycloak 26.8.1, with only its supported features: Dynamic Client Registration restricted by client registration policies (trusted hosts, loopback redirect URIs); the audience scope of M6; token introspection reporting `active: false` once the session is logged out; a `sid` claim in access tokens that stays the same across refreshes; the device authorization grant for a public client; a realm with `offline_access` unavailable to these clients; for the CLI client with "Require DPoP bound tokens" (M13): the access token carries `cnf.jkt` (also in the introspection answer), the refresh token is bound to the same key, and a refresh without a proof from that key is refused; two `nyyrikki login`s confirmed in the same browser get different `jkt` values and so are two agents even though they share `sid`; a DCR registration can't take the CLI client's `client_id` or turn DPoP off for it; client registration policies allow a dynamically registered client the device grant (for `nyyrikki login --mcp`, D25) and otherwise only the authorization-code grant with loopback redirects; and, recorded but not relied on, whether two sign-ins of one DCR client in one browser share a `sid` | Measured by the e2e test (`test/e2e`, 2026-10-27) against Keycloak 26.8.1 in a container, configured through its admin API as docs/setup/keycloak.md says | **Partly confirmed, 2026-10-27.** Confirmed: a CLI client with "Require DPoP bound tokens" issues access tokens with `typ: DPoP` and `cnf.jkt`, and introspection reports the same `cnf.jkt`, `client_id` and `sub`; access tokens carry `sid`; the device grant works for public clients; ending the user's sessions makes introspection answer `active: false`. **Differs**: (1) the default `roles` client scope adds `account` to `aud`, so the setup removes it from these clients; (2) Keycloak introspects a token only for a client in its `aud`, so the introspection client is named after Nyyrikki's audience (D7 note). Not yet measured: DCR and its client registration policies, two `nyyrikki login`s in one browser, refresh with and without the key, `offline_access`. *Revised 2026-10-29 (e2e, DCR set up as docs/setup/keycloak.md says)*: **confirmed**: an anonymous registration is public with consent required and PKCE S256 auto-set by a pkce-enforcer client policy; a non-loopback redirect URI is refused; a registration can't take `nyyrikki-cli`'s ID and an anonymous update can't change it (DPoP stays on); an authorization request without PKCE gets no code; two registered harnesses signed in from one browser differ in `azp` (they shared `sid` in this run), and so are two agents (one's elevation handle is `handle_unknown` to the other); `nyyrikki login --mcp` registers its own client each time and gets a token through the device grant. **Differs**: (3) Keycloak requires PKCE in the device grant for a client with PKCE set, so the CLI sends it (fixed in the first release after 0.2.0); (4) a registered client may ask for the password grant but gets no token; (5) a registered confidential client gets a client-credentials token with Nyyrikki's audience, whose `sub` is a service account, so Nyyrikki refuses it (the human registry, D8). Still not measured: two `nyyrikki login`s in one browser, refresh with and without the key, `offline_access` |
| M13 | DPoP (RFC 9449) is a fully supported Keycloak feature since 26.4, no feature flag. For a public client, both the access token and the refresh token are bound to the client's key, and a refresh needs a proof signed with that key; "Require DPoP bound tokens" on the client enforces it. 26.2.0 fixed a refresh that worked without a proof (#36475). | [keycloak.org/2025/10/dpop-support-26-4](https://www.keycloak.org/2025/10/dpop-support-26-4), [keycloak.org/securing-apps/dpop](https://www.keycloak.org/securing-apps/dpop), [26.4.0 release notes](https://www.keycloak.org/2025/09/keycloak-2640-released) | Confirmed from the docs; M9 checks it on 26.8.1. Drives D7, D8, OD14 |
| M10 | Claude Code and Codex, running in a pod with no local browser, can complete the DCR sign-in against Keycloak (Claude Code: `claude mcp login --no-browser`, M14) and call `/mcp`; Claude Code with a project `.mcp.json` using `headersHelper` (D25) connects and recovers from an expired token through its 401 retry | **Not yet measured.** FD3 | — |
| M14 | Claude Code: `.mcp.json` expands `${VAR}` and `${VAR:-default}` in `url` and `headers`, but reads credential-like variables (for example `ANTHROPIC_AUTH_TOKEN`) as empty there. `headersHelper` runs a command on each connection (session start, reconnect), which prints a JSON object of headers; after a 401 or 403 on a tool call it re-runs the helper and retries once; it gives up after 10 s; a helper from a project `.mcp.json` runs only in a trusted folder and gets environment variables whose names contain `TOKEN`, `SECRET`, `PASSWORD`, `KEY` or `AUTH` removed; the helper is given `CLAUDE_CODE_MCP_SERVER_NAME` and `CLAUDE_CODE_MCP_SERVER_URL`. OAuth sign-ins are stored per endpoint and reused by later sessions. CIMD and DCR are both supported. In a headless environment, `claude mcp login --no-browser` prints the URL and takes the pasted redirect URL. | [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp) | Confirmed from the docs. Drives D25 and OD15 |
| M11 | Which Kubernetes subresources the owner's agents can reach with their cluster-wide read (in particular `pods/log`, `pods/proxy`, `services/proxy`), and whether a `get` on `services/proxy` or `pods/proxy` reaches Nyyrikki's port despite its NetworkPolicy | **Not yet measured.** FD3, with `kubectl auth can-i --list` as an agent's identity and a probe through the apiserver proxy | — |
| M12 | Versions and exact flags of the gate tools (staticcheck, govulncheck, go-licenses, gitleaks, helm, kubeconform), and how `go-licenses` classifies the go-sdk (M3) | proxy.golang.org; ran each gate and its canary locally, 2026-10-26 | staticcheck v0.8.2, govulncheck v1.9.0, go-licenses v2.0.1 (`check --allowed_licenses=… --ignore …`), gitleaks v8.30.1 (`dir . --redact --config .gitleaks.toml`), kubeconform v0.8.0 (`-strict -kubernetes-version 1.35.0`), helm v3.19. go-licenses can't classify the go-sdk's transition LICENSE, so it is ignored by name and its LICENSE hash pinned (`scripts/pinned-licenses`, D14). govulncheck finds standard-library vulnerabilities in Go 1.26.8 that 1.26.10 fixes, so CI uses the latest patch (D1) |

## 3. Owner decisions

All taken by the owner on 2026-10-26, in the conversation that produced
this doc.

| # | Question | Decision |
|---|---|---|
| OD1 | Who does the first version serve? | **One human: the owner.** Several agents act for them, and they are the only approver. So in v1 the human an agent acts for also approves its requests. R5 records that as its answer for one human. |
| OD2 | Where does Nyyrikki run? | **A standalone service, deployed to Kubernetes with its own Helm chart**, developed so that it can later be published as open source. Nothing in the repository assumes the owner's environment. |
| OD3 | How does an agent prove who it is? | **The human signs in through OAuth, the way commercial MCP services and CLIs do.** Tokens come from an **external authorization server**, provided Keycloak supports what is needed. It does (M6), with the supported features only (D7); M9 confirms it against a running Keycloak. |
| OD4 | Which identity provider? | **Keycloak** (or Authentik). Keycloak is the reference that is documented and tested. Any authorization server meeting the contract in §5.4 works; Authentik is not verified against it. |
| OD5 | What is one "agent"? | **Each sign-in.** One OAuth sign-in, with the session and tokens that follow from it, is one agent. An approval or elevation for one sign-in doesn't cover another. *Revised 2026-10-26 by OD14 and OD15*: CLI sign-ins are always separate; MCP sign-ins of one client registration in one browser session may share an agent key, and what keeps their elevations apart is the elevation handle. |
| OD6 | How do agents reach Nyyrikki over MCP? | **Remote MCP served by Nyyrikki** over Streamable HTTP. No MCP process runs on the agent's machine. |
| OD7 | Where does the owner's deployment run? | **In the same cluster as the agents.** The agents' pods have cluster-wide read access today, excluding Secrets and RBAC objects; the owner doesn't consider that a concern. The threat model takes it as given (§6, SECURITY.md). |
| OD8 | Language? | **Go.** |
| OD9 | First target? | **Kubernetes, both the cluster Nyyrikki runs in and remote clusters**, in v1. |
| OD10 | Nyyrikki's licence? | **Apache-2.0.** Also settles the replaced plan's open OD3. |
| OD11 | Where does state live? | **SQLite on a PersistentVolumeClaim, one replica.** |
| OD12 | An agent using both MCP and the CLI? | **Two sign-ins, so two agents.** Each needs its own elevation. |
| OD13 | How are tokens checked? | **Local JWT validation for every call; token introspection as well for run and elevate**, so revoking a session in Keycloak takes effect at once. Keycloak unreachable means run and elevate are denied. |
| OD14 | Keycloak's `sid` is the browser's SSO session and is very likely shared by sign-ins made in the same browser (review of the FD0 PR). How is each sign-in kept a separate agent? | **DPoP for the CLI now.** Each `nyyrikki login` makes its own key pair, and the agent key includes the key's thumbprint. MCP clients keep (issuer, `azp`, `sid`): they are separated by their own client registration, and two sign-ins of the same MCP registration in one browser session may be one agent. Accepted in SECURITY.md. Owner decision, 2026-10-26, replacing a first fix that relied on removing Keycloak's Cookie authenticator, which very likely keeps the session anyway. |
| OD15 | A steered agent that knows another MCP agent's client ID can get the owner to sign in for it in the same browser session, and so share that agent's key and its elevation (review of the FD0 PR, round 2). Close it, or accept it? | **Accept it, and add an elevation handle** (D24): `elevate` returns a secret handle, and a request is covered by an elevation only when it carries that handle. The owner's words: "every Claude Code session I have has their own elevation handle", while all sessions may share one MCP configuration and sign-in, set up either by the harness's own OAuth sign-in or in the repository's `.mcp.json` with the credential coming from the environment (D25). The handle is a secret that only the session that asked for the elevation receives, so another session with the same agent key, accidental or deliberate, can't use it unless it learns the handle (SECURITY.md, deployment requirements). Owner decision, 2026-10-26. *Note 2026-10-26*: "the credential coming from the environment" is met by `headersHelper` (D25), not by a token in an environment variable, which D25 rejects; the owner chose that setup in the same conversation. |
| OD16 | With one shared client for `nyyrikki login --mcp`, every such login the owner confirms in one browser is the same agent, across pods and repositories (review of the FD0 PR, round 3). Separate them? | **Yes: one registration per login.** Each `nyyrikki login --mcp` registers its own client through DCR, so each login is its own agent: told apart on Telegram, and revoked on its own. All harness sessions using that one login remain one agent, kept apart by handles (OD15). Owner decision, 2026-10-26. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Go**, `go.mod` declaring `go 1.26.0`, the oldest supported major (M1, M8). CI tests the latest patch of both supported majors. The floor rises when a major drops out of support. | OD8. Kubernetes' own request parser (`k8s.io/apiserver`) and the official MCP SDK are Go, so Nyyrikki parses Kubernetes requests exactly as the apiserver does. |
| D2 | **One module**, `github.com/Tuhis/Nyyrikki`, **two binaries**: `nyyrikkid`, the server, and `nyyrikki`, the CLI on the agent's machine. | One set of types and gates. The CLI is small and needs nothing from the server but the protocol. |
| D3 | **Topology.** `nyyrikkid` runs as one pod in Kubernetes (OD2, OD11). It holds every target credential, the Telegram bot token and its Keycloak introspection credential. The agent's machine holds only its own OAuth tokens. Targets accept Nyyrikki's credentials, and nothing on the agent side can reach them. | `CLAUDE.md`: Nyyrikki holds the credentials; approvals come from outside the agent's reach. |
| D4 | **One external API: MCP over Streamable HTTP at `/mcp`** (OD6). The CLI is an MCP client of that same endpoint (go-sdk client), not a client of a second API. MCP resources, prompts, sampling and elicitation are off; only the tools R2 defines are offered. | "MCP and CLI are thin clients of one API": with one protocol and one endpoint, they can't drift apart, and there is one surface to harden. If R4 finds that a request kind can't go through a tool call (for example an interactive exec stream), its doc adds an endpoint under the same authentication and the same decision point, and records it here as a dated revision. *Revised 2026-10-26 by [docs/02](02-gateway-core.md) D10 (owner decision docs/02 OD3)*: interactive exec and attach can't go through a tool call, so `GET /stream` (a WebSocket under the same authentication) attaches to a run the decision point has already allowed, through a one-time ticket. It adds no decision of its own. |
| D5 | **MCP sessions carry no authority.** The server runs the go-sdk's Streamable HTTP handler in `Stateless` mode. Everything that grants anything (approvals, elevations) is keyed by the agent's identity (D8), never by an MCP session ID. The elevation handle (D24) only narrows: it never covers a request from any other agent key. | A session ID is a bearer value the client chooses or echoes; tying authority to it would add a second credential. Stateless mode also removes the GET and DELETE methods (M2). |
| D6 | **Nyyrikki is an OAuth resource server only.** It publishes RFC 9728 metadata at `/.well-known/oauth-protected-resource` naming one authorization server, answers 401 with the `resource_metadata` challenge (M2, M4), and issues no tokens itself. | OD3. Token minting stays out of the crown jewel. |
| D7 | **Authorization server contract**, met by Keycloak 26.8.1 with supported features only (M6, M9): OAuth 2.1 with PKCE; RFC 8414 or OIDC discovery; RFC 9207 `iss`; Dynamic Client Registration for MCP clients, restricted by client registration policies to loopback redirect URIs; a pre-registered public client for the CLI using the device authorization grant; for each `nyyrikki login --mcp`, a client of its own registered through DCR with only the device grant (D25, OD16); access tokens whose `aud` is Nyyrikki's canonical URI (Audience mapper on an optional scope); token introspection; a session ID claim (`sid`) stable across refreshes; DPoP (RFC 9449, supported since Keycloak 26.4, M13) required on the CLI client, binding its access and refresh tokens to the key of one `nyyrikki login`; no `offline_access`. CIMD and RFC 8707 are used once Keycloak promotes them out of experimental, by a dated revision here. | OD3, OD4: "if Keycloak supports everything needed". Experimental features may break between releases (M6), and a security component shouldn't depend on them. *Revised 2026-10-27 (M9)*: Keycloak 26.8 introspects a token only for a client in its audience, so the introspection client's ID is Nyyrikki's audience (`…/mcp`), which keeps `aud` a single value; and the `roles` scope is removed from Nyyrikki's clients, since it adds `account` to `aud`. |
| D8 | **Identities.** The **human** is the token's `sub` from the configured issuer, looked up in Nyyrikki's human registry (config), which gives their Kubernetes user and groups and their Telegram user ID. A `sub` not in the registry is denied. The **agent** is one sign-in (OD5, OD14). For the **CLI** (the configured CLI `client_id`) it is (issuer, `azp`, `cnf.jkt`): the key belongs to one `nyyrikki login`, so sign-ins that share a Keycloak session are still separate. A CLI token without `cnf.jkt` is denied. For **MCP clients**, including the per-login clients of `nyyrikki login --mcp` (D25), it is (issuer, `azp`, `sid`). `sid` is Keycloak's SSO session, so two sign-ins of the same client registration in one browser session may be the same agent, and all harness sessions sharing one sign-in certainly are (SECURITY.md, accepted risks); their elevations are kept apart by the handle (D24). Clients with different registrations are always separate. Nothing the client sends (its registered name, an MCP `clientInfo`, a tool argument) identifies it; such values are shown to the approver only as the agent's claim. | OD1, OD5. "Who to act as comes from the authenticated binding, never from the agent." |
| D9 | **Token checks** (OD13, OD14), done by Nyyrikki's own middleware in front of the MCP handler, since the go-sdk's accepts only `Bearer` (M2). **Every call**: exactly one `Authorization` header; signature against the issuer's JWKS with an allowlist of asymmetric algorithms; `iss`; `aud` equal to Nyyrikki's canonical URI; `exp` and `nbf` with at most 30 s skew; `sub` in the registry. **Which DPoP rule applies is decided by the token's claims, never by the scheme the client chose**: if `azp` is the CLI client, `cnf.jkt` must be present; if `cnf.jkt` is present, whatever the `azp`, the token must come as `Authorization: DPoP` with a proof, and a `Bearer` presentation is denied (RFC 9449 §7.1). **The proof** (RFC 9449 §4.3): exactly one `DPoP` header holding a well-formed JWS; `typ` is `dpop+jwt`; `alg` is on the asymmetric allowlist (never `none`, never `HS*`); the `jwk` header is a public key with no private members and the signature verifies with it; `htm` is the request method; `htu`, with query and fragment removed and RFC 3986 §6.2.2–6.2.3 normalisation, equals the configured canonical `/mcp` URL, never one built from `Host`, `X-Forwarded-*` or the request URL; `iat` no more than 60 s in the past or 30 s in the future, and not earlier than the process's start time; `jti` not seen within that window, kept in memory, and if the cache is full the request is denied rather than an entry evicted; `ath` equals the hash of the token; the RFC 7638 thumbprint of `jwk`, compared in constant time, equals `cnf.jkt`. The proof binds method and URL, which are the same for every call (`POST /mcp`), not the body, so `jti` is the only replay defence. **Run and elevate** also introspect the token and require `active: true`, and the answer's `client_id` and `cnf.jkt` (when present) to equal the token's; any introspection failure is a deny. Only tokens from the one configured issuer are accepted, and no token is ever forwarded to a target (M4). The DPoP header is the CLI's only departure from the MCP spec's `Bearer` header (M4); it affects only Nyyrikki's own client. | Revocation in Keycloak takes effect at once for anything privileged; listing targets stays available without a Keycloak round trip. DPoP makes the CLI's agent key fresh per login (OD14) and a copied token useless without its key. Rejecting proofs from before the process started closes replay across a restart without a persistent `jti` store. *Revised 2026-10-26 by [docs/02](02-gateway-core.md) D11*: a proof's `htu` is checked against the configured canonical URL of the endpoint it was sent to, `/mcp` or `/stream`, never one built from the request; `/stream` also introspects. *Revised 2026-10-27 by [docs/02](02-gateway-core.md) §10 (review of #10)*: replay across a restart is closed by a per-process DPoP nonce (RFC 9449 §8) the proof must carry, instead of refusing proofs dated before the process started; the CLI retries once on `use_dpop_nonce`. |
| D10 | **Listeners**: `:8443`, HTTPS, serving `/mcp` and `/.well-known/oauth-protected-resource`, with TLS terminated in `nyyrikkid` from a mounted certificate; `:8081`, plain HTTP, serving only `/healthz` and `/readyz` with no data, for the kubelet. That is the complete list; a test asserts it. Clients, in-cluster ones included, use the canonical URL, because DPoP proofs are checked against it (D9). Outbound: the authorization server, the Telegram Bot API (long polling), and the configured targets' API servers. | Least surface. Tokens never cross a plaintext hop, even inside the cluster: an Ingress in front uses TLS passthrough or re-encrypts, and never logs the `Authorization` or `DPoP` headers, since its logs are agent-readable too (OD7). *Revised 2026-10-26 by [docs/02](02-gateway-core.md) D10*: `:8443` also serves `/stream`. |
| D11 | **Storage**: SQLite in WAL mode through `modernc.org/sqlite` on a PVC (OD11), holding pending approvals, elevations and the audit log. The audit log is also written to stdout as JSON lines. Binaries are built with `CGO_ENABLED=0 -trimpath`. The Deployment has one replica and the `Recreate` strategy, so two pods never write the same database. | Single instance, no extra service, static binaries (M8). Compare-and-set transitions in SQLite have exactly one winner (`docs/measured.md`, grant mechanics M1), which R2 and R5 rely on. |
| D12 | **Config**: one YAML file rendered by the Helm chart into a ConfigMap, decoded strictly with `go.yaml.in/yaml/v3` (`KnownFields(true)`) and validated in full at startup; invalid config means the process doesn't start. The file holds no secrets, only paths to them (D15). | Fail closed on typos. `gopkg.in/yaml.v3` is unmaintained (`docs/gotchas.md`). ConfigMaps are readable by the agents (OD7). |
| D13 | **Kubernetes support**: the three maintained releases, 1.35 and newer (M7). Earlier releases are refused at startup by checking the target's `/version`. | 1.34 is end of life on 2026-10-27, and before 1.35 a WebSocket exec needs only `get pods/exec` (`docs/gotchas.md`). |
| D14 | **Dependency policy.** Every dependency is justified in its PR. The licence allowlist is MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 and ISC, with CC-BY-4.0 for documentation files only. A module that `go-licenses` can't place on the allowlist (the go-sdk, M3) is reviewed by hand, ignored by name with the reason, and its licence files are pinned by hash. Versions are pinned in `go.mod`, `go.sum` is committed, builds use `-mod=readonly`, and downloads are verified through the Go checksum database. Renovate proposes updates. | Supply chain is in scope (SECURITY.md), and the project may be published (OD2, OD10). |
| D15 | **Credential custody.** Every credential is a file: Kubernetes Secrets in Nyyrikki's namespace mounted read-only, never environment variables. For the cluster Nyyrikki runs in, its own ServiceAccount token, projected and short-lived. For a remote cluster, a token for a ServiceAccount there that can only impersonate. Nyyrikki's ServiceAccounts may impersonate only the users and groups in the human registry (`resourceNames`) and hold no other rights. How each is granted and rotated is R4 and R6. | A Secret's value doesn't appear in the pod spec, which the agents can read (OD7); an environment variable's literal value would. A credential that can only impersonate the owner is capped at the owner's own rights. |
| D16 | **Everything Nyyrikki logs is agent-readable.** In the owner's cluster the agents can read pod logs (OD7, M11), so logs and the stdout audit stream carry nothing an agent mustn't see: no credential, no elevation handle, no raw tool arguments (the audit records the canonical request, R3), no Telegram callback data, nothing that would help to answer an approval. Agent keys appear only as a keyed hash. | Turns OD7 into a rule implementations can check. |
| D17 | **Gates** (§5.6): format, vet, staticcheck, `go mod tidy -diff`, `go test -race` over the full suite, govulncheck, the licence check, a secret scan, and `helm lint` plus `kubeconform` on the chart once it exists. Each gate has a canary that proves it fails on a planted violation. | `CODE-REVIEW.md` §Gates; a gate that checks nothing is worse than none. |
| D18 | **CI**: GitHub Actions. Every third-party action is pinned to a commit SHA. The default token permission is `contents: read`. *Revised 2026-10-30 (owner's request)*: `ci.yml` and `e2e.yml` (and, from 2026-10-30, `ssh-host.yml`) run on self-hosted runners named by the repository variables `RUNNER_LABEL` and `RUNNER_LABEL_DISK` (the owner's are ARC pools on their cluster, limited to the public internet by a NetworkPolicy), falling back to `ubuntu-latest` when unset; so do the release and the Claude review workflows. Pull requests from forks always run GitHub-hosted (narrowed in the next note). *Revised again 2026-10-30 (review of #31)*: the owner's runners are ephemeral, one pod per job, and their NetworkPolicy allows DNS, the registry cache and the public internet. `ci.yml`, `e2e.yml` and `ssh-host.yml` send a pull request whose head isn't this repository to GitHub-hosted runners, a positive check, so an unknown head repository counts as outside; the automatic review skips such PRs. `@claude` from a review or review comment on one runs GitHub-hosted too, since that checkout is the PR's merge commit; from a PR comment it runs self-hosted, at a writer's request: the workflow's steps run from the default branch, then Claude reads the PR head, with `.claude/`, `.mcp.json` and `CLAUDE.md` restored from the base branch by the pinned action (check that on every bump of `claude-code-action`), and its tools are read-only `gh` and `git` commands and inline comments. BuildKit in the release is pinned by digest. | Supply chain. *2026-10-30*: a GitHub billing hold stopped every hosted job, and the owner's other repositories already run on these pools; the owner asked for everything self-hosted. Accepted risk: the release job, which pushes the image that runs Nyyrikki with impersonation rights, runs on nodes that also run other repositories' privileged Docker-in-Docker jobs, not on a fresh hosted VM (SECURITY.md). Fork PRs run hosted so that no code from outside the repository runs on the owner's cluster. |
| D19 | **Repository layout** in §5.5. Application code goes in `internal/`; nothing is importable from outside by accident. | |
| D20 | **Conventions** in §5.7: type-prefixed ULIDs, RFC 3339 UTC times with milliseconds, Go duration syntax in config. | One format everywhere. |
| D21 | **Test layers** (§5.8): unit; integration with an in-process `nyyrikkid`, real SQLite, a fake Bot API, a test authorization server and a fake apiserver; end to end with Keycloak, a kind cluster and the real binaries. Parsers are fuzzed. | Each layer catches what the others can't. |
| D22 | **The threat model and its invariants live in SECURITY.md**, and each invariant is tested by an acceptance criterion in a design doc. | One home per fact (`CLAUDE.md`). |
| D23 | **Releases**: release-please, following Conventional Commits. Images and the chart are versioned together. Details are R6. | Already the repository's convention. |
| D24 | **Elevation handles** (OD15). An approved `elevate` returns a handle: 256 random bits with a fixed prefix that secret scanners can match, returned only to the call that asked for it, stored only as a SHA-256 hash. It is a bearer secret within its agent key: any session under that key that learns it can use it, so where it may be written is a deployment requirement (SECURITY.md). A request is covered by an elevation only if it carries the handle (an MCP tool argument; for the CLI a flag or `NYYRIKKI_ELEVATION`), the handle matches in constant time, and the agent key, human, target and expiry match too. **Outcomes**: no handle → the one-off path; a handle that was never issued to this agent key → denied and audited, never turned into a one-off request; a handle of this agent key whose elevation has expired or been ended, or that doesn't name the request's target → not covered, so the one-off path, audited as such, since a request outside a scope is exactly what one-off approval exists for. **Authority made for one call goes only to that call**: an `elevate` result, or the result of a one-off approval, is returned to the waiting call and nowhere else. If R2 adds any way to pick one up later (after a timeout or reconnect), it takes a secret reference like the handle, never an ID or the agent key alone. The handle never reaches logs, the audit log or Telegram (D16). The same rules apply to MCP and the CLI. R2 designs the operations around them. | OD15. Sessions that share an agent key don't share elevations. A handle alone is useless to anyone with another agent key (D5). |
| D25 | **Two ways to set up an MCP harness**, both giving the agent only its own tokens: (a) the harness's own OAuth sign-in (DCR), configured once per user; (b) a repository `.mcp.json` whose `headersHelper` is `nyyrikki mcp-headers`, which prints `{"Authorization": "Bearer …"}` from a sign-in made once with `nyyrikki login --mcp`, refreshing it when needed. That login registers its own client through DCR (device grant only) and signs in with it (OD16, D7), and keeps its tokens in a login file of its own, separate from the CLI's, private to its agent and not replaced unless told to (§5.4). Its tokens aren't DPoP-bound, so whoever has the file can use them until the session's maximum length. `mcp-headers` fails closed: if it can't produce a fresh token it exits non-zero and prints nothing, and where the harness tells the helper the server URL (Claude Code: `CLAUDE_CODE_MCP_SERVER_URL`, M14), it refuses unless that equals the canonical URL, so a `.mcp.json` pointing elsewhere gets no token. A static token in an environment variable is not offered: the authorization server's access tokens live for minutes, and a long-lived one would bypass OD3 and OD13. Variable names given to the helper avoid the words Claude Code strips (`TOKEN`, `KEY`, `AUTH`…, M14). | OD15: one configuration shared by every session, nothing to do per session. `headersHelper` re-runs after a 401, so short-lived tokens work (M14). |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Nyyrikki as its own OAuth authorization server, federating login to an upstream IdP | OD3. More code in the crown jewel, and token minting next to the credentials it protects. |
| Using Keycloak's experimental CIMD and RFC 8707 now | D7. They may break between Keycloak releases (M6). Reconsidered when Keycloak promotes them. |
| Local JWT validation only, with short-lived tokens | OD13. A revoked agent would keep working until its token expired. |
| Per-agent static bearer tokens, or mTLS client certificates | OD3. The owner chose OAuth sign-in. Both also need an enrolment and revocation surface Nyyrikki would have to build. |
| An MCP server on the agent's machine (stdio), talking to Nyyrikki | OD6. One more binary on the machine the agent controls; the spec's authorization flow is for HTTP (M4). |
| A REST API for the CLI next to `/mcp` | D4. A second API is a second decision path to keep in step. |
| MCP session IDs as the agent's identity or as the key of an elevation | D5. A client-chosen bearer value is not an identity. |
| Keycloak's `sid` alone as the agent key, made fresh per sign-in by removing the Cookie authenticator, with an `auth_time` check as backstop | OD14. Keycloak very likely keeps the existing session (and `sid`) even when it makes the owner authenticate again, and the `auth_time` check misses the case where both sign-ins refresh after the second one (review of the FD0 PR, round 1). |
| Elevations for CLI agents only, to close the merged-MCP-agent gap | OD15. The owner accepted the gap, narrowed by elevation handles, to keep MCP elevations. |
| A long-lived token for MCP harnesses in an environment variable | D25. It would be a standing credential outside the authorization server's session control. `headersHelper` gives the same one-time setup with short-lived tokens. |
| A dedicated VM for Nyyrikki (the replaced plan's host G) | OD2. |
| Rust, TypeScript | OD8. No apiserver request parser; reimplementing it is where parser differences come from. |
| PostgreSQL | OD11. Another service and credential to guard, for HA that v1 doesn't need. |
| Teleport instead of building | Compared before the repository existed and not recorded with sources (replaced docs/01). Measure its current editions before reopening. |

## 5. Design

### 5.1 Architecture

```
 owner's phone                    Kubernetes cluster (the owner's: OD7)
 ┌──────────┐            ┌───────────────────────────────────────────────────────┐
 │ Telegram │◄──┐        │  agents' namespace(s)          nyyrikki namespace      │
 └──────────┘   │        │  ┌────────────────────┐        ┌────────────────────┐  │
                │        │  │ agent pod          │ HTTPS  │ nyyrikkid (1 pod)  │  │
 ┌──────────┐   │        │  │  MCP client ───────┼───────►│ :8443 /mcp         │──┼──► remote cluster API
 │ Telegram │◄──┼────────┼──┼  nyyrikki CLI ─────┼───────►│  decision point    │  │    (impersonating)
 │ Bot API  │ long poll  │  │  holds: its OAuth  │        │  SQLite on PVC     │  │
 └──────────┘   │        │  │  tokens only       │        │  Secrets as files  │──┼──► this cluster's API
                └────────┼──┼────────────────────┼────────┤                    │  │    (impersonating)
                         │  └─────────┬──────────┘        └─────────┬──────────┘  │
                         │            │ sign-in (browser /          │ JWKS,       │
                         │            ▼ device code, by the owner)  ▼ introspect  │
                         │        ┌──────────────────────────────────────┐        │
                         │        │ Keycloak (authorization server)      │        │
                         │        └──────────────────────────────────────┘        │
                         └───────────────────────────────────────────────────────┘
```

Keycloak may run anywhere; the chart doesn't deploy it. Agents may also
run outside the cluster and reach `:8443` through an Ingress.

### 5.2 Components and where they are specified

| Component | Lives in | Specified by |
|---|---|---|
| Listeners, TLS, token checks, the MCP endpoint and tool wiring | `nyyrikkid` | this doc (D4–D10), R2 |
| Operations, target registry, human registry, elevation model, decision point | `nyyrikkid` | R2 |
| Audit log | `nyyrikkid` | R3 |
| Request parsing, forwarding, impersonation, credential custody | `nyyrikkid` | R4 |
| Telegram bot, approvals | `nyyrikkid` | R5 |
| The CLI (`nyyrikki login`, `targets`, `run`, `elevate`) | `nyyrikki` | R2 (commands), this doc (D4, §5.4) |
| Helm chart, images, releases | `deploy/` | R6 |

### 5.3 Request path

1. The agent calls a tool on `/mcp`, through its MCP client or the CLI,
   with `Authorization: Bearer <access token>` (MCP clients) or
   `Authorization: DPoP <access token>` plus a `DPoP` proof (the CLI).
2. `nyyrikkid` validates the token locally (D9). Failure: 401 with the
   `resource_metadata` challenge, audited.
   Any DPoP-bound token, and every CLI token, also needs a valid proof
   (D9).
3. It resolves the human from `sub` and the agent from (issuer, `azp`,
   `cnf.jkt`) for the CLI or (issuer, `azp`, `sid`) for MCP clients
   (D8). An unknown `sub`: deny, audited.
4. For run and elevate it introspects the token (D9). Not active, or
   Keycloak unreachable: deny, audited.
5. The decision point (R2) decides, escalating to Telegram (R5) where
   needed. An elevation covers the request only if the request carries
   that elevation's handle (D24). What an approval or elevation
   produces is returned only to the call that waited for it (D24). A pending approval keeps the tool call open, with MCP
   progress notifications while it waits (R5 decides the details).
6. An allowed request is forwarded as the human, with Nyyrikki's
   credential (R4), and the response returned to the agent, unredacted
   (R9). Every step is audited (R3).

### 5.4 Signing in

- **MCP clients** follow the spec's flow (M4): 401 → Protected Resource
  Metadata → Keycloak's metadata → Dynamic Client Registration →
  authorization code with PKCE in the owner's browser, asking for the
  Nyyrikki audience scope. Where the client runs in a pod with no
  browser, Claude Code takes the pasted redirect URL (M14); M10
  measures it, and Codex. Alternatively, a repository's `.mcp.json`
  uses `nyyrikki mcp-headers` as its `headersHelper`, after one
  `nyyrikki login --mcp` (D25). Either way, every harness session using
  that configuration is the same agent, and each gets its own
  elevation handle (D24).
- **The CLI** uses a pre-registered public client and the device
  authorization grant: `nyyrikki login` prints a URL and a code, the
  owner signs in on another device, and the CLI stores its tokens in a
  file only its user can read. Each `nyyrikki login` first makes a new
  key pair, kept in that file, and the client requires DPoP, so its
  tokens are bound to that key (D7, M13). The key makes each login a
  new agent (OD5, OD12, OD14). A copied token alone is useless, but
  whoever can read the file is that agent, so each agent needs its own
  login file that no other agent can read (SECURITY.md, deployment
  requirements). `nyyrikki login` refuses to replace an existing login
  unless told to explicitly.
- **Session lifetimes** are set in the realm, and the chart's
  documentation gives the recommended values: no `offline_access` for
  these clients, and a maximum session length after which the owner
  signs in again. Ending a session in Keycloak's account console ends
  that agent at once for run and elevate (D9).
- **What the approver sees** about an agent: the client's registered
  name, marked as its claim, the time of the sign-in and a short form of
  the agent key. R5 designs the message.

### 5.5 Repository layout

```
go.mod                 module github.com/Tuhis/Nyyrikki
LICENSE                Apache-2.0
cmd/
  nyyrikkid/           server
  nyyrikki/            CLI: login, targets, run, elevate
internal/
  codes/               decision values and error codes, one definition
  config/              strict decoding and validation
  server/              listeners, TLS, lifecycle, wiring
  authn/               token validation and introspection (D9)
  …                    packages for R2–R5, named by their docs
test/
  canaries/            planted violations the gates must catch (§5.6)
  e2e/                 kind + Keycloak + the real binaries (§5.8)
deploy/
  chart/nyyrikki/      Helm chart (R6)
docs/
```

### 5.6 Gates and CI

FD2 adds these to `CODE-REVIEW.md` §Gates and to `CONTRIBUTING.md`
"Running the gates", with the exact versions and flags measured in M12:

```sh
test -z "$(gofmt -l .)"           # format
go vet ./...
staticcheck ./...
go mod tidy -diff                 # go.mod / go.sum tidy
go test -race -count=1 ./...      # unit + integration
govulncheck ./...
go-licenses check ./... --allowed_licenses=MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC
gitleaks dir . --redact           # secret scan
helm lint deploy/chart/nyyrikki && helm template … | kubeconform -strict   # once the chart exists
```

The go-sdk's licence (M3) is handled as D14 says, with the outcome
recorded in M12.

**Canaries**: `test/canaries/` holds one planted violation per gate: a
misformatted file, a vet error, a staticcheck finding, an untidy
`go.mod`, a failing test, a module with a known vulnerability, a
disallowed licence and a fake secret, plus a chart error once the chart
exists. They are excluded from the normal run. A CI job,
`gates-selftest`, runs each gate against its canary and **fails if the
gate passes**.

Unit and integration tests run on every push and pull request; the end
to end suite runs on merge to `main` and nightly. Where they run is D18's.

### 5.7 Conventions

- **IDs** are a type prefix plus a ULID (`github.com/oklog/ulid/v2`).
  Each design doc claims its prefixes. Config-defined IDs, such as
  target names, are slugs.
- **Times** are RFC 3339 UTC with milliseconds on the wire
  (`2026-10-26T09:15:02.123Z`) and INTEGER Unix milliseconds in SQLite.
  The server's clock is the only clock that decides anything.
- **Durations in config** use Go syntax (`90s`, `15m`).
- **Names**: the human an agent acts for is the **human**; whoever
  answers on Telegram is the **approver** (in v1 the same person, OD1);
  whoever installs and configures Nyyrikki is the **operator**.
- **Spec keywords**: MUST, SHOULD and MAY as in RFC 2119.

### 5.8 Testing strategy

1. **Unit**: pure logic: config validation, token checks, parsers, the
   decision point, the text rendered for approvers.
2. **Integration**: an in-process `nyyrikkid` with a temporary SQLite
   database, a fake Telegram Bot API that records requests and injects
   updates, a test authorization server issuing tokens with chosen
   claims (wrong `aud`, wrong `iss`, expired, inactive on
   introspection), and a fake apiserver. DPoP negative cases: no proof,
   a DPoP-bound or CLI token sent as `Bearer`, two `DPoP` headers, a
   replayed `jti`, a proof from before the process started, wrong
   `htm`, `htu` or `ath`, a different key, `alg: none` and `HS256`, a
   `jwk` with private members, and an introspection answer whose
   `cnf.jkt` or `client_id` differs. Elevation handle cases: missing (one-off
   path), never issued to this agent key or from another agent key
   (denied), after expiry or end, or on a target the elevation doesn't
   name (one-off path). `nyyrikki mcp-headers`: refresh failure (exits
   non-zero, prints nothing) and a server URL other than the canonical
   one (refused).
3. **End to end** (`test/e2e`): Keycloak 26.8.x configured as §5.4
   says, a kind cluster running a supported Kubernetes release with
   Nyyrikki installed from its chart, a second kind cluster as a remote
   target, the fake Bot API driven by the test as the approver, and a
   scripted agent using both the CLI and an MCP client.
4. **Adversarial "evil agent" scenarios**, added by each doc that opens
   a path: presenting another agent's or a foreign issuer's token,
   reusing a revoked session, impersonation fields in the request,
   answering its own approval, and reading Nyyrikki's logs for anything
   useful (D16). Every attempt fails and is audited.
5. **Fuzzing**: every parser of agent input and of Telegram updates.

### 5.9 What CLAUDE.md records once this doc is approved

FD0 replaces `CLAUDE.md`'s "Architecture (nothing locked in yet)"
section with a "locked in" list of D1–D18, D24 and D25, one line each with its
reason, linking here, and adds the rejected alternatives that are easy
to re-propose (Nyyrikki as its own authorization server, local-only
token checks, an agent-side stdio MCP server, a second API for the CLI)
to its "Rejected" list.

## 6. Security considerations

The threat model, its assets, trust base, adversaries, invariants
(`INV-xx`) and accepted risks are in [`SECURITY.md`](../SECURITY.md)
(D22). What this doc adds to it:

- **New trust boundaries and inputs.** Agent → `/mcp` (bearer token and
  tool arguments, attacker-controlled; checked by D9, then R2–R4).
  Keycloak → Nyyrikki (JWKS and introspection answers; Keycloak is in the
  trust base). Telegram → Nyyrikki (R5). The Helm values (operator,
  trusted; validated strictly, D12).
- **Dependency failures.** Keycloak unreachable or answering anything
  but `active: true`: run and elevate denied (D9). Invalid config: no
  start (D12). SQLite unwritable: deny (R2, R3). Unsupported Kubernetes
  version: target refused (D13).
- **What reaches logs, Telegram and the agent.** Logs are agent-readable
  (D16), so they carry no secrets and no approval material. Responses go
  to the agent unredacted (R9); Nyyrikki never adds its own credentials to them (docs/04 OD3 for a request that reads them).
- **New ways to reach a target.** One: `/mcp` (D4, D10). Any later
  endpoint is added by a dated revision of D4 and passes the same
  decision point.
- **Identity on the target.** The human's Kubernetes user and groups
  from the registry (D8), through a credential that can impersonate
  nothing else (D15).
- **The shared cluster (OD7).** The agents can read most of the cluster,
  including Nyyrikki's pod spec, ConfigMap, events and, most likely,
  logs. They must not be able to read Secrets, exec into, attach to or
  port-forward to Nyyrikki's pod, reach it through the apiserver proxy,
  or change anything in its namespace. M11 checks this for the owner's
  agents; SECURITY.md states it as a deployment requirement.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 The owner has approved this doc's decisions | the owner, by merging the FD0 PR |
| G2 `CLAUDE.md` lists what was locked in, and SECURITY.md has the threat model | review of the FD0 PR |
| G3 The skeleton builds both binaries as static executables with `CGO_ENABLED=0 -trimpath` on both supported Go majors | CI job on FD1 |
| G4 Every gate runs in CI and fails on its canary | `gates-selftest` (FD2) |
| G5 Actions are pinned to SHAs and the default token is `contents: read` | a CI check that fails on an unpinned action or broader default permissions (FD2) |
| G6 The licence file is Apache-2.0 and the licence gate passes on the skeleton's dependencies | the licence gate (FD2) |
| G7 M9–M11 are measured and recorded here, and any decision they contradict is revised with a dated note | review of the FD3 PR, by the owner |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **FD0** | This doc; the threat model in SECURITY.md; `CLAUDE.md` "locked in" and "Rejected"; ROADMAP and docs index | G1, G2 |
| **FD1** | `go.mod`, `LICENSE`, the layout of §5.5 with two `main` packages that start and exit, and a CI build matrix | G3 |
| **FD2** | The gates, their canaries and `gates-selftest`; `CODE-REVIEW.md` §Gates and `CONTRIBUTING.md`; action pinning; M12 | G4, G5, G6 |
| **FD3** | Measurement spikes, not product code: Keycloak 26.8.1 against D7 (M9); Claude Code and Codex in a pod against a stub `/mcp` behind `auth.RequireBearerToken` (M10); the agents' cluster rights (M11) | G7 |

Ordering: FD1 before FD2, since the gates need something to run on.
FD3 is independent and can go in parallel; R2's doc doesn't lock its
authentication details before FD3 has measured them. M0 is done when
FD0–FD2 have landed (ROADMAP); FD3 is needed by M1 at the latest.

## 9. Risks and open questions

- **Keycloak can't do part of D7** (M9). Fallbacks, in order: enable the
  experimental feature that covers it, with the version pinned and a
  dated revision of D7; or reopen OD3. The owner decides.
- **MCP sign-ins can merge** (OD14, OD15, OD16). All harness sessions
  that share one MCP sign-in (one harness OAuth sign-in, or one
  `nyyrikki login --mcp`) are one agent, and two sign-ins of the same
  client registration in one browser session may be too. That includes
  a deliberate case: a steered agent that knows another MCP agent's
  client ID (they aren't secret) gets the owner to sign in for it in
  the same browser, and so shares that agent's key. The elevation
  handle (D24) keeps it from using the other agent's elevations, as long
  as it can't read the handle (SECURITY.md, deployment requirements); what
  it gains is being shown to the approver, and audited, under the
  other agent's name. Accepted by the owner. If MCP clients gain DPoP,
  D8 adopts it by a dated revision. Agents that need strict separation
  use the CLI.
- **DPoP doesn't behave as documented on 26.8.1** (M9, M13). Then the
  CLI key isn't fresh per login and OD14 is reopened before R2's doc
  locks.
- **An MCP client can't sign in from a pod** (M10). The CLI's device
  grant still works, so agents use the CLI; or the client gets its
  tokens another way the owner approves. Nothing here weakens D9.
- **The agents can reach Nyyrikki's port through the apiserver proxy**
  (M11), bypassing the NetworkPolicy. That port only accepts valid
  tokens, so this isn't a bypass of approval, but it is a path the
  threat model says doesn't exist. If M11 finds it, the deployment
  requirement in SECURITY.md is tightened and the owner removes those
  rights from the agents.
- **One human approves their own agents' requests** (OD1). An attacker
  who steers an agent still has to get the owner to tap; the message
  design (R5) is the defence. Accepted in SECURITY.md.
- **Single replica** (OD11). If Nyyrikki is down, nothing privileged
  runs. That fails closed.
- **Measured facts that later docs need** (impersonation RBAC, exec and
  WebSocket behaviour, Telegram) are re-checked by R4 and R5, not here.

## 10. How it was implemented (YYYY-MM-DD)

<!-- Added during implementation. -->

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
