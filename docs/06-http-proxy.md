# R9 — HTTP admin-API proxy (docs/06)

**Status**: drafted 2026-10-25, adapted from the Warden design. Status
lives in [`ROADMAP.md`](../ROADMAP.md). There are no open owner
decisions. Decisions D1–D12 await the owner's approval.

Chunks **HP1–HP4** (`HP` = HTTP proxy; unused).

**Relationship to earlier work**: the first protocol proxy behind the
gate in [docs/02](02-grant-core.md) §5.9. It uses the redaction in
[docs/03](03-audit-log.md) §5.9, and writes the `curlrc` format consumed
by [docs/05](05-agent-integration.md) §5.4. Together with docs/02–05,
it is the first end-to-end slice: an agent creates a Keycloak user after
a Telegram tap.

---

## 1. Purpose

Admin HTTP APIs, such as Keycloak's, are guarded by a credential that is
all or nothing. Whoever holds the client secret can do anything its
roles allow, for as long as the secret lives. Putting that secret on A
means every process there holds it. With this proxy, A calls
`https://nyyrikki.internal:8443/u/<upstream>/…` with its grant token,
and G does the rest:

1. normalizes the request;
2. evaluates it against the profile's method and path rules;
3. holds mutating calls in step mode;
4. adds the real credential, which A never sees;
5. forwards to the one configured base URL.

### Non-goals

- **Browser admin consoles** (for example the Keycloak admin UI).
- **Arbitrary-URL proxying.** A can't name a host.
- **WebSocket upgrades and `CONNECT`.** Denied in v1.
- **Rules on query strings, headers or bodies.** Rules match the method
  and path only.
- **Response filtering.** Responses pass through unchanged, minus the
  headers in §5.4.

## 2. Measured and verified before writing

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `httputil.ReverseProxy.Director` is unsafe for this purpose. Hop-by-hop headers are removed *after* `Director` runs, so a client can list any header in `Connection` and strip headers the proxy added. `Rewrite` runs after that removal, and also drops inbound `Forwarded` and `X-Forwarded-*`. | `go doc net/http/httputil.ReverseProxy`, Go 1.26.8, 2026-10-25 | Confirmed, quoted: "this permits a malicious client to remove any headers that may be added by Director … Rewrite addresses these issues." Drives D3, and a gotcha |
| M2 | `http.DefaultTransport` uses `ProxyFromEnvironment`. A `Transport` with `Proxy: nil` uses no proxy. | `go doc net/http.Transport`, `go doc net/http.DefaultTransport` | Confirmed. Drives D7: environment variables on G can't redirect upstream traffic |
| M3 | Keycloak 26.8.1 (2026-10-13): the admin REST API can be called by a confidential client that has *Client authentication* and *Service account roles* enabled, using `grant_type=client_credentials`. The realm-management client roles include `view-users`, `query-users` and `manage-users`. The documented example uses the **master** realm with the full `admin` role. | keycloak.org server_development guide ("Authenticating with a service account"), server_admin guide | Partly. The mechanism is confirmed. The least-privilege shape (§5.7: a client in the target realm with only realm-management user roles) is assembled from separate pages, so HP4 measures it against a real Keycloak |

## 3. Owner decisions

None open.

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Fixed upstreams.** Each one is a name plus a `base_url` in config. The path `/u/<upstream>/<rest>` can only append `<rest>` to that base URL. | INV-18. A can't point the proxy anywhere else. |
| D2 | **Normalize strictly, and reject rather than repair** (§5.2). Encoded slashes and backslashes, dot segments, empty segments, a trailing slash, control characters and absolute-form request targets are all rejected. | INV-14. A path is either unambiguous or refused, so the rules and the upstream see the same thing. |
| D3 | **`httputil.ReverseProxy` with `Rewrite`, never `Director`.** | M1. |
| D4 | **Strip the client's credentials and routing headers, then set G's own** (§5.4). | INV-04, INV-14. |
| D5 | **Read means `GET`, `HEAD` or `OPTIONS`.** Every other method is mutating. `CONNECT`, `TRACE` and any `Upgrade` request are denied before policy runs. | Step mode needs a clear rule. The denied methods tunnel or reflect. |
| D6 | **Credential types**: `oauth2_client_credentials`, `bearer_file`, `basic` and `header`. They are resolved on G, and OAuth2 tokens are cached in memory until 30 s before their expiry. | These cover Keycloak and the usual token-authenticated APIs. |
| D7 | **One `http.Transport` per upstream**, with `Proxy: nil`, TLS verified against a configured CA (TLS 1.2 minimum), the dial pinned to the configured host, and timeouts set. | M2, INV-12. |
| D8 | **Responses**: `Set-Cookie` is stripped. A same-origin `Location` is rewritten to the `/u/<upstream>/…` path. A `Location` pointing at any other origin is removed, and the response becomes `502 upstream_redirect_offsite`. | A has no session with the upstream. Redirects must stay inside the proxy. |
| D9 | **Request bodies are capped at 10 MiB.** Bodies of mutating requests go to the step summary and the audit log only after redaction (docs/03 §5.9). Response bodies are never stored. | Bounded memory. INV-11. |
| D10 | **A failure to get a token returns `502 upstream_auth_failed`.** There is never a retry without a credential. | Fail closed. |
| D11 | **Errors are returned as JSON** `{"error":{"code","message"}}`, with `X-Nyyrikki-Request-Id`, so scripts can tell a Nyyrikki error from an upstream one. | Typed failures (docs/02 D13). |
| D12 | **The upstream's own authorization is the hard boundary.** For Keycloak, that is the service account's realm roles (§5.7). | The same principle as Kubernetes RBAC (SECURITY.md). |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Collapsing `//` and resolving `..` instead of rejecting them | A second, different reading of the path. A rule would match what the upstream doesn't see. |
| Forwarding A's own `Authorization` header to the upstream | It would put upstream credentials on A (INV-04). |
| Matching on the query string | Parameter order and encoding vary. Rules stay on the path, and the upstream's roles do the rest. |
| `Director` | M1. |

## 5. Design

### 5.1 Routing

- **Path**: `/u/<upstream>/<rest>`. `<upstream>` must be in the grant's
  `http.upstreams`, otherwise `out_of_scope`.
- **Authentication**: the mTLS client, plus `Authorization: Bearer
  nyg_…`, checked against the active grant and the client (docs/02
  §5.12).
- **Destination**: `base_url` + `/` + normalized `<rest>`. After
  building the URL, G asserts that it still starts with `base_url`'s
  path.

### 5.2 Path normalization (INV-14)

These steps run on the raw request target before anything else:

1. Only the origin form (`/u/…`) is accepted. An absolute-form target is
   rejected with `invalid_path`.
2. Split `<rest>` on `/`. Reject the request if any of these is true:
   - a segment is empty (this covers `//` and a trailing `/`);
   - a segment is `.` or `..`;
   - a segment contains `%2F`, `%2f`, `%5C`, `%5c`, `%00`, or an invalid
     percent sequence;
   - a segment decodes to a control character (C0, C1 or DEL).
3. Percent-decode each segment once. The decoded segments, joined with
   `/` and given a leading `/`, form `op.Path`.
4. Forward the segments re-encoded with `url.PathEscape`.

The query string is forwarded verbatim and plays no part in matching.

### 5.3 Operation and read vs mutating

The operation is:

```
Kind=http  Method=<method>  Path=<normalized>  Upstream=<name>
Mutating = Method ∉ {GET, HEAD, OPTIONS}
```

`CONNECT`, `TRACE`, and any request carrying `Upgrade` are rejected with
`method_not_allowed` before policy runs. Everything else goes through
`gate.Authorize` (docs/02 §5.9).

In step mode, the step summary is `METHOD /path` plus the redacted body
digest.

### 5.4 Headers and bodies

**Inbound headers stripped** before forwarding:

- `Authorization`, `Proxy-Authorization`, `Cookie`;
- `Forwarded` and every `X-Forwarded-*` (dropped by `Rewrite`, M1);
- every `X-Nyyrikki-*`;
- hop-by-hop headers (`Connection` and the headers it names,
  `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`).

**Outbound**, G sets:

- `Host` = the upstream host;
- the injected credential (§5.5);
- `User-Agent: nyyrikki/<version>`.

`Accept`, `Content-Type`, `Content-Length`, `If-Match` and
`If-None-Match` are passed through. Every other header is dropped. This
is an allowlist.

**Response**:

- `Set-Cookie` is stripped.
- `Location` is handled per D8.
- Hop-by-hop headers are removed by `ReverseProxy`.
- The status code, content type and sizes are audited. The response
  body is streamed to A and never stored.

**Redaction**: on top of docs/03 §5.9, a Keycloak `credentials[].value`
and a `secret` field in client representations are covered by the shared
rules there. New upstream-specific fields get added there, not here.

### 5.5 Credential injection

| Type | Behaviour |
|---|---|
| `oauth2_client_credentials` | POST to `token_url` with `client_id` and the resolved `client_secret_ref` (client-secret-basic), plus `scopes`. The access token is cached until 30 s before `expires_in` and refreshed once per expiry, with concurrent callers waiting on one refresh. It is sent as `Authorization: Bearer`. |
| `bearer_file` | `Authorization: Bearer <file contents>`. The file is re-read when its mtime changes. |
| `basic` | `Authorization: Basic base64(username:<password_ref>)` |
| `header` | `<header_name>: <value_ref>` (for example `X-API-Key`). `header_name` is validated against the stripped-header list, so it can't be `Host`, a hop-by-hop header, or a header A can send. |

Token-endpoint errors return `502 upstream_auth_failed` and the audit
event `upstream.auth_failed` (D10). The token endpoint uses the same
pinned `Transport` rules (D7).

### 5.6 TLS to the upstream (INV-12)

TLS is verified against the upstream's `tls_ca_file`, or failing that
against `pki.upstream_ca_bundle_file`. There is no `InsecureSkipVerify`,
and config validation rejects every attempt to disable verification. The
minimum is TLS 1.2. Timeouts: dial 5 s, TLS handshake 5 s, response
headers 30 s, idle 90 s.

### 5.7 Keycloak (the reference upstream)

- **`base_url`**: `https://keycloak.internal/admin`, so profile paths
  look like `/realms/acme/users`.
- **Least privilege** (to be measured in HP4, M3):
  - A confidential client `nyyrikki-admin` **in the target realm**
    (`acme`), not in `master`.
  - *Client authentication* on, *Service account roles* on, and every
    other flow off.
  - Service-account roles: only the `realm-management` client roles
    the profiles need: `view-users`, `query-users`, `manage-users`.
- **Token URL**:
  `https://keycloak.internal/realms/acme/protocol/openid-connect/token`.
- **Never use the documented master-realm `admin` example.** The
  service account's roles, not Nyyrikki's rules, are the hard boundary
  (D12).
- **Example rules**: see `keycloak-users` in docs/02 §5.15.5.

### 5.8 `curlrc` for A

`nyyrikki-mcp` writes this to `grants/<id>/curlrc` (docs/05 §5.4):

```
--cacert /…/internal-ca.pem
--cert   /…/client.crt
--key    /…/client.key
--header @/…/grants/<id>/auth-header
```

`auth-header` (mode `0600`) holds `Authorization: Bearer nyg_…`, so the
token doesn't appear in the curlrc itself or on a command line.

Usage: `curl -K …/curlrc https://nyyrikki.internal:8443/u/keycloak-admin/realms/acme/users`.
`env` exports `NYYRIKKI_KEYCLOAK_ADMIN=https://nyyrikki.internal:8443/u/keycloak-admin`.

### 5.9 Configuration

```yaml
pki:
  upstream_ca_bundle_file: "/etc/nyyrikki/pki/upstream-ca.pem"
http_upstreams:
  - name: keycloak-admin
    base_url: "https://keycloak.internal/admin"
    tls_ca_file: "/etc/nyyrikki/pki/keycloak-ca.pem"     # optional
    credential:
      type: oauth2_client_credentials
      token_url: "https://keycloak.internal/realms/acme/protocol/openid-connect/token"
      client_id: nyyrikki-admin
      client_secret_ref: "secret://keycloak-nyyrikki-admin"
      scopes: []
```

Validation:

- Names match `^[a-z0-9][a-z0-9-]{1,61}$` and are unique.
- `base_url` is `https`, has no query string or fragment, and has no
  trailing slash.
- Each credential has exactly the fields its type needs.
- `header_name` passes the §5.5 rule.

| Key | Consumed by (production call site) |
|---|---|
| `http_upstreams[].name`, `.base_url` | `proxy/http.New` (route table) |
| `http_upstreams[].tls_ca_file`, `pki.upstream_ca_bundle_file` | `proxy/http.newTransport` |
| `http_upstreams[].credential.*` | `proxy/http.newInjector` |

## 6. Security considerations

- **New input**: the full HTTP request from A, which is untrusted.
  - The path is validated in §5.2.
  - Headers are allowlisted in §5.4.
  - The body is capped and redacted before it is recorded.
  - The method is mapped in §5.3.
- **New outbound boundary**: G ↔ upstream, with TLS verified (§5.6).
  The response from the upstream is passed to A, minus cookies and
  offsite redirects.
- **Dependency failures**:
  - token endpoint down → `502`, no call made (D10);
  - upstream down → `502`;
  - audit down → refused (docs/03 §5.6).

  None of them allows an operation.
- **What reaches the audit log and Telegram**: the method, the
  normalized path and the redacted body digest. Never headers, tokens or
  the injected credential.
- **New ways to reach an upstream**: exactly one, `/u/<upstream>/…`,
  and only through `gate.Authorize` (docs/02 D5). The bypass hunt
  covers:
  - HTTP/2 (served by Go's TLS listener; same handler);
  - `HEAD`/`OPTIONS` (reads, still evaluated);
  - redirects (D8);
  - `Upgrade` (denied);
  - encoded paths (§5.2).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. Only configured upstreams in the grant's scope are reachable. No request field changes the scheme, host or port (INV-18) | tests with off-scope names, absolute-form targets, and `Host` header games |
| G2. Every rejection in §5.2 fires, and the resolved URL never escapes `base_url` (INV-14) | table test of the normalization matrix, plus fuzzing |
| G3. The headers listed in §5.4 never reach the upstream, including when they are named in `Connection` (INV-14, M1) | stub upstream that records the headers it receives |
| G4. No upstream credential, OAuth2 token or Keycloak secret ever reaches A, in any response, header or error (INV-04) | capture every byte returned to A in the e2e suite and scan for canaries |
| G5. An upstream with an untrusted certificate fails with no request sent. Disabling verification is rejected at config load (INV-12) | integration test, config test |
| G6. Reads pass in step mode. Every mutating method is held. `CONNECT`, `TRACE` and `Upgrade` are denied | integration tests |
| G7. In e2e against real Keycloak, the `keycloak-users` profile works: a `POST /realms/acme/users` is held, then approved through the fake Bot API, and the user exists. A `DELETE` is denied. The service account can't touch realm `master` | e2e |
| G8. `Set-Cookie` is stripped. A same-origin `Location` is rewritten. An offsite `Location` turns into `502` | stub upstream tests |
| G9. A failure to get a token returns `502 upstream_auth_failed`, and the upstream receives no unauthenticated request | stub IdP test |
| G10. Every §5.9 key changes behaviour at its call site | one test per key |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **HP1** | Routing, normalization and the operation mapping, with fuzzing | G1, G2 |
| **HP2** | `ReverseProxy` with `Rewrite`, header allowlist, response handling, per-upstream transport and TLS | G3, G5, G6, G8 |
| **HP3** | Credential injectors and the OAuth2 token cache | G4, G9, G10 |
| **HP4** | Keycloak e2e, including the M3 measurement, and the `curlrc` format with docs/05 AG3 | G7 |

Ordering notes: HP1 and HP2 need docs/02 GC7, because forwarding takes a
`Permit`. HP4 needs docs/04 TG3 for the approval in G7.

## 9. Risks and open questions

- **Other admin APIs may need rules on query strings or bodies** (for
  example, "may only set these fields"). Out of scope for v1. If it
  comes up, it gets its own proposal. Until then the upstream's roles
  are the boundary.
- **M3**: Keycloak's least-privilege setup is assembled from several doc
  pages. HP4 confirms it.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
