# R10 — Kubernetes API proxy (docs/07)

**Status**: drafted 2026-10-25, adapted from the Warden design. It
includes the connect-subresource correction, measured in M1. Status
lives in [`ROADMAP.md`](../ROADMAP.md). Open: OD1 (clusters older than
1.35). Decisions D1–D14 await the owner's approval. Revised 2026-10-26
after review in PR #1: D11 (self-check against the bootstrap allowlist,
M9, M10), path checks in §5.2.

Chunks **KP1–KP5** (`KP` = Kubernetes proxy; unused).

**Relationship to earlier work**: a protocol proxy behind the gate in
[docs/02](02-grant-core.md) §5.9. It uses the recorders and redaction in
[docs/03](03-audit-log.md), and writes the kubeconfig consumed by
[docs/05](05-agent-integration.md) §5.4.

---

## 1. Purpose

A node upgrade from inside a thread means:

- `kubectl drain`, which is evictions;
- `cordon` and `uncordon`, which are node patches;
- perhaps an `exec` to look around.

Today that takes a kubeconfig on A with enough rights for all of it,
valid until someone remembers to rotate it. With this proxy, A's
`kubectl` and `helm` talk to `https://nyyrikki.internal:8443/k8s/<cluster>/…`
with the grant token. G then:

1. parses each request exactly as the apiserver will;
2. applies the profile's rules;
3. holds evictions for a tap if the profile says so;
4. records exec streams;
5. forwards the request **impersonating a fixed, per-profile user**,
   whose RBAC is the real limit.

### Non-goals

- **Changing response objects.** There is no field filtering.
- **Admission policy.** Nyyrikki doesn't validate object contents. RBAC
  and the cluster's own admission do.
- **Recording SPDY exec.** SPDY exec is refused (D9).
- **Aggregated APIs and webhook proxying beyond the `proxy`
  subresource.** These are default-denied by policy.
- **Clusters older than the supported range** (OD1).

## 2. Measured and verified before writing

All measured on 2026-10-25.

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

M1 output (k8s.io/apiserver v0.37.1):

| Request | Verb | Resource | Subresource | Namespace | Name |
|---|---|---|---|---|---|
| `GET …/pods/web-0/exec` (WebSocket upgrade) | get | pods | exec | shop | web-0 |
| `POST …/pods/web-0/exec` | create | pods | exec | shop | web-0 |
| `GET …/pods/web-0/portforward` | get | pods | portforward | shop | web-0 |
| `POST …/pods/web-0/attach` | create | pods | attach | shop | web-0 |
| `GET …/pods/web-0/log` | get | pods | log | shop | web-0 |
| `GET /api/v1/nodes/node-1/proxy/metrics` | get | nodes | proxy | | node-1 |
| `POST …/pods/web-0/eviction` | create | pods | eviction | shop | web-0 |
| `GET …/namespaces/shop/pods` | list | pods | | shop | |
| `GET …/pods?watch=true` | watch | pods | | shop | |
| `DELETE …/namespaces/shop/pods` | deletecollection | pods | | shop | |
| `GET /apis/apps/v1/…/deployments/web/scale` | get | deployments (apps) | scale | shop | web |
| `GET /version`, `GET /apis` | get | — (non-resource) | | | |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | Support clusters older than 1.35? On 1.34 and older, the apiserver lacks the `create` check for WebSocket exec (M5). There, RBAC that grants `get pods/exec`, for example through a broad `get *` role, also allows exec. Nyyrikki's own policy still classifies it correctly (D4), but the hard boundary is weaker. | *Open.* Recommendation: **no.** At startup G reads `/version` and refuses to enable a cluster below 1.35, with a clear error. 1.34 is end of life on 2026-10-27 (M7). |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Impersonation, not token relay.** G's identity in each cluster can do nothing but impersonate. It impersonates only the user `nyyrikki:<profile>` (and its groups) taken from the grant's frozen profile. | INV-05. If Nyyrikki's policy had a bug, RBAC would still refuse whatever the impersonated user isn't bound to. |
| D2 | **Strip every client-sent identity header** (`Authorization`, `Impersonate-*`) and every hop-by-hop header before anything else. The upgrade headers survive only on the vetted streaming path (§5.7). | INV-05, INV-14. kubeconfig's own `as:` field (impersonation) can't get through. |
| D3 | **Parse with the apiserver's own `RequestInfoFactory`.** | G must see what the apiserver will see (M1). |
| D4 | **Connect-subresource override.** If the subresource is `exec`, `attach`, `portforward` or `proxy`, `Operation.Verb` becomes that subresource name, whatever the HTTP method. | M1: otherwise a WebSocket exec is a `get` and passes as a read. |
| D5 | **Reads are `get`, `list` and `watch`, after D4.** Everything else is mutating, and `exec`, `attach`, `portforward` and `proxy` are always mutating. | Step mode needs a fixed rule. |
| D6 | **Implicit allows** for discovery, health and version, OpenAPI, and the self-review APIs (§5.6). They are still audited. | Without them `kubectl` breaks, and they reveal only what the impersonated user could learn anyway. |
| D7 | **Request bodies of mutating calls are recorded** after redaction (docs/03 §5.9). Response bodies are not. | Evidence of what changed, without secrets. |
| D8 | **WebSocket exec and attach are proxied and recorded** through a passive channel-frame parser (§5.7). G strips `Sec-WebSocket-Extensions`, so frames stay uncompressed and parseable. | Recording is a system goal (docs/01 §1, goal 7). M4. |
| D9 | **SPDY exec and attach are always refused** (`spdy_exec_denied`). Port-forward is allowed on both transports when policy allows it, recorded as metadata only. | SPDY framing isn't recorded. kubectl ≥ 1.30 uses WebSockets, and falls back to SPDY only after a refusal (M3), so a refusal shows up as two denied attempts, both audited. |
| D10 | **Nyyrikki's errors are Kubernetes `Status` objects** with matching HTTP codes. | `kubectl` prints them cleanly. |
| D11 | **At startup and on every reload, G checks its own identity** in each cluster (§5.11): a `SelfSubjectRulesReview` per namespace it can name, compared against the configured impersonation rules plus the M10 bootstrap allowlist, and `SelfSubjectAccessReview` probes for the permissions that matter most. Any extra rule, an `incomplete` result, or an allowed probe disables that cluster. A RoleBinding in a namespace G can't name stays invisible to it, so the operator runs a binding audit at setup (docs/09 §5.4). | INV-05 is verified as far as G can see, not assumed. "Any rule other than impersonation" alone would disable every cluster, because every identity gets the M10 rules. |
| D12 | **Constrained impersonation, once measured.** Clusters on 1.36 or newer get it, which lets G impersonate each user only for the verbs that profile needs. Older clusters use the legacy `impersonate` verb with `resourceNames`. KP5 measures the exact rules (M6). | Defence in depth: even G's identity is limited per profile. |
| D13 | **TLS to the apiserver is verified** against the configured CA. | INV-12. |
| D14 | **The kubeconfig carries the token only by reference** (`tokenFile`). | M8. docs/05 D3. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Hand A a short-lived token for an RBAC-limited user | A talks to the apiserver directly. Nothing can hold an operation, record exec, or revoke within 2 s. Violates INV-04 in spirit. |
| Re-derive verbs from the HTTP method ourselves | Drifts from the apiserver. M1 shows even the library needs the D4 override, so a hand-written mapper would need far more. |
| Allow SPDY exec unrecorded per profile | A knob that switches off recording for the most powerful operation. kubectl doesn't need it (M3). |
| Give G a cluster-admin token and rely on Nyyrikki's rules alone | A policy bug would become cluster-admin. D1. |

## 5. Design

### 5.1 Impersonation

Each profile with a `k8s` section names a fixed user, and optionally
groups:

```yaml
k8s:
  impersonate: { user: "nyyrikki:k8s-node-maint", groups: ["nyyrikki:node-maint"] }
```

G forwards every request as that user. Cluster RBAC binds the user to
exactly the verbs and resources the profile needs (§5.11). Kubernetes
RBAC has no deny rules, so the role must be an **allowlist** that leaves
out whatever the profile denies. For example, list resources explicitly
rather than `*`, so that `secrets` isn't included.

### 5.2 Routing, authentication and header stripping

- **Path**: `/k8s/<cluster>/<apipath>`. `<cluster>` must be in the
  grant's `k8s.clusters`, otherwise `out_of_scope`.
- **Authentication**: the mTLS client, plus `Authorization: Bearer
  nyg_…`, checked against the active grant (docs/02 §5.12).
- **Stripped first** (D2):
  - `Authorization`;
  - every `Impersonate-User`, `Impersonate-Group`, `Impersonate-Uid` and
    `Impersonate-Extra-*`;
  - `Connection` and the headers it names, `Keep-Alive`, `TE`,
    `Trailer`, `Transfer-Encoding`;
  - `Upgrade` and `Sec-WebSocket-*`, except on the streaming path in
    §5.7.
- **Path checks** (INV-14): `<apipath>` goes through the same
  normalizer as docs/06 §5.2, one function shared by both proxies. Each
  segment is decoded once and then checked, and empty, dot, encoded-slash,
  control-character and double-encoded segments are rejected with a
  `400` `Status`. `RequestInfoFactory` (§5.3) parses the decoded
  segments, and the forwarded path is those same segments re-encoded, so
  the parser and the apiserver see the same path.
- **Rewriting**: the remaining request is rewritten with
  `httputil.ReverseProxy`'s `Rewrite`, never `Director` (docs/06 M1), to
  `<apiserver_url>/<apipath>`.

### 5.3 Parsing into an Operation

```go
factory := &request.RequestInfoFactory{
    APIPrefixes:          sets.NewString("api", "apis"),
    GrouplessAPIPrefixes: sets.NewString("api"),
}
ri, err := factory.NewRequestInfo(reqWithPathStrippedToAPIPath)   // error -> 400, deny
```

| Operation field | Value |
|---|---|
| `Kind` | `k8s` |
| `Cluster` | `<cluster>` |
| `Group` | `ri.APIGroup` |
| `Resource` | `ri.Resource`, plus `"/" + ri.Subresource` if there is one |
| `Namespace` | `ri.Namespace` |
| `Name` | `ri.Name` |
| `Verb` | `ri.Verb`, then the **D4 override**: if `ri.Subresource` ∈ {`exec`, `attach`, `portforward`, `proxy`}, the subresource name |

`Mutating` is per §5.4. A request with `ri.IsResourceRequest == false`
goes through §5.6, or else to policy, which has no grammar for it, and
is denied.

Policy rules are written in the overridden vocabulary, for example
`exec pods/exec -n shop web-*`. `pods/log` is not overridden: it stays
`get pods/log`, a read.

### 5.4 Read vs mutating

- **Read**: `{get, list, watch}`, evaluated after D4. This covers
  `get pods/log` and `get */status`.
- **Mutating**: everything else, including `create`, `update`, `patch`,
  `delete` and `deletecollection`. `exec`, `attach`, `portforward` and
  `proxy` are always mutating, and are sessions (§5.7).
- **`proxy`**: the proxied path is invisible to policy (M2), so no
  example profile allows `proxy`. A profile that does should say why in
  its description.

### 5.5 Recording request bodies

For mutating resource requests, the body goes through `redact.Body`
(docs/03 §5.9) into `op.start`, and into the step summary in step mode.
Kubernetes-specific redaction:

- `Secret` objects: only metadata and key names survive;
- `data` and `stringData` anywhere;
- `TokenRequest` bodies.

All of these are implemented in docs/03's package. Response bodies are
not stored; the status code, the result `kind` and the
`resourceVersion` are.

### 5.6 Implicit allows

These are allowed regardless of rules, and audited:

- `GET /api`, `/apis`, `/api/v1`, `/apis/<group>`, `/apis/<group>/<version>`
  (discovery);
- `GET /openapi/v2`, `/openapi/v3`, `/openapi/v3/*`;
- `GET /version`, `/healthz`, `/livez`, `/readyz`;
- `create` on `selfsubjectaccessreviews`, `selfsubjectrulesreviews`
  (`authorization.k8s.io`) and `selfsubjectreviews`
  (`authentication.k8s.io`). These answer only for the impersonated
  user.

Anything else falls through to policy (docs/02 §5.8.5, step 5).

### 5.7 Streaming: exec, attach, port-forward and watch

**WebSocket exec and attach** (`GET` with `Upgrade: websocket`,
subprotocol `v5.channel.k8s.io`):

1. Policy runs on the overridden operation (`exec pods/exec …`).
2. In step mode, the operation is held **before** the upgrade. The step
   summary is `exec pod/web-0 -c app -- /bin/sh`, built from the
   `command` and `container` query parameters, rendered per docs/04
   §5.7.
3. G creates a session `ss_` (kind `k8s-exec`) and opens the recording.
   If the recording can't be opened, the request is refused (docs/03
   D8).
4. G dials the apiserver's WebSocket with the impersonation headers, the
   same subprotocol, and no `Sec-WebSocket-Extensions`.
5. G copies frames both ways, unchanged, and tees them into the parser.
   The first byte of each binary message is the channel:
   - 0 → recording `i`;
   - 1 and 2 → `o`;
   - 3 is the status, recorded at close;
   - 4 → `r`, parsed from JSON `{Width, Height}`;
   - 255 is a close.

   `tty=true` writes asciicast v2; otherwise JSONL (docs/03 §5.4).
6. When the grant context is cancelled, G closes both sides within 2 s
   (INV-07) and records `close_reason`.

**SPDY exec and attach** (`POST` with `Upgrade: SPDY/3.1`): refused with
`Status` 403 `spdy_exec_denied` (D9).

**Port-forward**: when policy allows `portforward`, either transport is
proxied as an opaque stream: WebSocket with
`SPDY/3.1+portforward.k8s.io`, or SPDY. It is a session (kind
`k8s-portforward`), recorded as `.meta.json` with byte counts and
duration.

**Watch**: a `watch` with an open response is a session (kind
`k8s-watch`), so that teardown can close it. It is not recorded beyond
`op.start` and `op.end`.

### 5.8 Headers G adds

After stripping (§5.2), G adds:

```
Authorization:                  Bearer <G's own credential for this cluster>   (or G's client certificate)
Impersonate-User:               <profile.k8s.impersonate.user>    # only from the frozen snapshot
Impersonate-Group:              <each profile group>
Impersonate-Extra-nyyrikki-grant:  <grant id>
Impersonate-Extra-nyyrikki-client: <client id>
```

The values come only from the grant's snapshot and IDs, never from the
request (INV-05, INV-18). The extras make the apiserver's own audit log
show which grant made each change.

### 5.9 Errors

Every Nyyrikki-side rejection returns a `metav1.Status`:

```json
{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403,
 "message":"nyyrikki: policy_denied: delete pods not permitted by profile k8s-node-maint (request 01JB…)"}
```

| Nyyrikki code | HTTP | `reason` |
|---|---|---|
| `policy_denied`, `out_of_scope`, `step_denied`, `spdy_exec_denied` | 403 | `Forbidden` |
| `step_expired` | 408 | `Timeout` |
| `grant_not_active`, `unauthenticated` | 401 | `Unauthorized` |
| `rate_limited` | 429 | `TooManyRequests` |
| `audit_unavailable`, `busy` | 503 | `ServiceUnavailable` |

### 5.10 kubeconfig for A

`nyyrikki-mcp` writes one file per cluster (docs/05 §5.4):

```yaml
apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster: { server: "https://nyyrikki.internal:8443/k8s/prod",
             certificate-authority: "/…/internal-ca.pem" }
users:
- name: nyyrikki
  user:
    tokenFile: "/…/grants/gr_…/token"          # M8: the token stays out of this file
    client-certificate: "/…/client.crt"
    client-key: "/…/client.key"
contexts:
- { name: prod, context: { cluster: prod, user: nyyrikki } }
current-context: prod
```

Both credentials are needed: the client certificate for the transport,
and the token for the grant (INV-06).

### 5.11 Cluster setup

**G's identity** is a ServiceAccount `nyyrikki` in namespace
`nyyrikki-system`, with a token mounted on G, or a client certificate.
On a cluster older than 1.36, or until D12 is measured, its role is:

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: nyyrikki-impersonator }
rules:
- apiGroups: [""]
  resources: ["users"]
  verbs: ["impersonate"]
  resourceNames: ["nyyrikki:k8s-node-maint"]       # one entry per profile user
- apiGroups: [""]
  resources: ["groups"]
  verbs: ["impersonate"]
  resourceNames: ["nyyrikki:node-maint"]
- apiGroups: ["authentication.k8s.io"]
  resources: ["userextras/nyyrikki-grant", "userextras/nyyrikki-client"]
  verbs: ["impersonate"]
```

It is bound with a ClusterRoleBinding to the ServiceAccount, and nothing
else is bound to it.

**The self-check (D11)** runs per cluster at startup and on every reload:

1. **`SelfSubjectRulesReview`** in `default`, `kube-system`,
   `nyyrikki-system`, and every namespace written literally in a
   profile's rules (`-n shop`). Every rule returned must be one of:
   - an `impersonate` rule whose resource names are users, groups and
     extras that a configured profile uses;
   - a rule in the M10 bootstrap allowlist, which is compiled into G per
     supported minor version.

   Anything else, or `incomplete: true`, disables the cluster.
2. **`SelfSubjectAccessReview` probes**, cluster-wide (namespace empty)
   and in each namespace from step 1. Every one must come back
   `allowed: false`:
   - `impersonate users system:admin`, `impersonate groups
     system:masters`, `impersonate serviceaccounts` (any name);
   - `get secrets`, `create pods`, `create pods/exec`, `patch nodes`,
     `create clusterrolebindings`, and `*` on `*`.

The check can't see a RoleBinding in a namespace it doesn't query, and
G can't list namespaces. The operator closes that gap once at setup
with a binding audit that needs cluster-admin (docs/09 §5.4). A cluster
that fails is disabled. It doesn't stop the other clusters.

**Every impersonated user is also in `system:authenticated`** (M9). The
RBAC boundary for a profile is therefore its own role *plus* everything
the cluster binds to `system:authenticated`. On a default cluster that's
only the M10 rules, but some distributions and operators bind more. The
setup audit in docs/09 §5.4 lists those bindings too.

**The impersonated user** gets one role per profile, as an allowlist
matching the profile. For `k8s-node-maint`:

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: nyyrikki-k8s-node-maint }
rules:
- apiGroups: ["", "apps", "batch", "policy"]
  resources: ["pods", "nodes", "deployments", "daemonsets", "replicasets", "statefulsets", "jobs", "events", "namespaces", "poddisruptionbudgets"]
  verbs: ["get", "list", "watch"]                  # no secrets, no configmaps
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["patch"]                                 # cordon / uncordon
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]                                # drain
```

A profile that allows `exec` needs **both** `get` and `create` on
`pods/exec`, because of the WebSocket `create` check (M5).

Restrict apiserver admin access to G's address where the cluster
allows it. Put the apiserver CA in `ca_file` (INV-12).

### 5.12 Configuration

```yaml
k8s_clusters:
  - name: prod
    apiserver_url: "https://10.0.0.1:6443"
    ca_file: "/etc/nyyrikki/pki/prod-apiserver-ca.pem"
    credential:
      serviceaccount_token_file: "/etc/nyyrikki/secrets/prod-sa-token"
      # or: client_cert_file + client_key_file
```

Validation:

- Names are unique and match `^[a-z0-9][a-z0-9-]{1,61}$`.
- `apiserver_url` is `https`.
- `ca_file` exists.
- Exactly one credential form is given.
- Every profile with a non-empty `k8s` section sets `impersonate.user`.
- An `impersonate.user` must start with `nyyrikki:`, so it can never be
  an existing human or admin user.

At runtime, per cluster, G reads `/version` (OD1) and runs the D11
check. A cluster that fails either is marked unavailable: its requests
get `503` and it raises an alert. Other clusters are unaffected.

| Key | Consumed by (production call site) |
|---|---|
| `k8s_clusters[].apiserver_url`, `.ca_file`, `.credential.*` | `proxy/k8s.newClusterTransport` |
| `k8s_clusters[].name` | `proxy/k8s.New` (route table) |
| `profiles[].k8s.impersonate.*` | `proxy/k8s.impersonationHeaders` (from the grant snapshot) and the `nyyrikki k8s rbac` generator (KP5) |

## 6. Security considerations

- **New input**: Kubernetes API requests from A, which are untrusted.
  - Path and verb are parsed by the apiserver's library (D3), plus the
    D4 override.
  - Identity headers are stripped (D2).
  - Bodies are redacted before recording.
  - The streaming upgrade is accepted only on the §5.7 path.
- **New outbound boundary**: G ↔ apiserver, with TLS verified (D13).
  G's identity can only impersonate, beyond the M10 bootstrap rules
  (D1, D11).
- **Dependency failures**:
  - apiserver down → `503 Status`;
  - D11 or the version check fails → the cluster is disabled;
  - audit or recording down → refused (docs/03 §5.6).

  None of them allows an operation.
- **What reaches the audit log and Telegram**: the parsed operation, the
  redacted body digest, and the exec command and container. Never
  `Authorization`, tokens, or Secret values.
- **New ways to reach the apiserver**: only `/k8s/<cluster>/…`, through
  `gate.Authorize`. The bypass hunt covers:
  - WebSocket and SPDY upgrades (§5.7);
  - `proxy` subresources (deny by default, M2);
  - impersonation headers (stripped);
  - kubeconfig `as:` (stripped);
  - HTTP/2 (same handler);
  - discovery (implicit allows only).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. The operation mapping matches the M1 table, including the D4 override (WebSocket `GET pods/exec` → `exec`, mutating; `GET pods/log` → `get`, a read) | table test using the real `RequestInfoFactory`; fuzzing |
| G2. A client-sent `Authorization`, `Impersonate-User: system:admin`, `Impersonate-Group` or `Impersonate-Extra-*` never reaches the apiserver. Impersonation comes only from the snapshot. A traversal such as `/api/v1/namespaces/shop/pods/x/%2e%2e/%2e%2e/%2e%2e/kube-system/secrets` is rejected before parsing (INV-05, INV-14) | fake apiserver that records headers and paths; the docs/06 G2 normalization matrix run against `/k8s/<cluster>/…`; e2e against k3s |
| G3. In e2e, an operation that the impersonated user's RBAC lacks is refused by the apiserver, even when Nyyrikki's rules would allow it (INV-05) | e2e: a permissive profile with a narrow RBAC role |
| G4. G refuses to enable a cluster whose identity has any permission beyond the configured impersonation rules and the M10 allowlist, where `SelfSubjectRulesReview` is `incomplete`, or where any §5.11 probe is allowed. A cluster with only the default bootstrap bindings is enabled (D11) | e2e against k3s on each supported minor version: the default cluster passes; an extra ClusterRoleBinding for `get pods` fails; a RoleBinding for `get secrets` in a namespace a profile names fails; `impersonate users` without `resourceNames` fails |
| G5. WebSocket exec with `tty` produces a playable `.cast`, and without `tty` a `.jsonl`, with input and output matching the session | e2e with `kubectl exec` (≥ 1.30) |
| G6. SPDY exec is refused. A refused WebSocket exec followed by kubectl's SPDY retry produces two audited denials and no exec (M3, D9) | e2e with `kubectl exec`, plus a forced SPDY client |
| G7. Every Nyyrikki rejection is a valid `Status` with the code from §5.9 | integration tests |
| G8. With the implicit allows only, `kubectl get --raw /version`, `kubectl api-resources` and `kubectl auth can-i` work, while everything else is denied | e2e |
| G9. No upstream credential (G's token or client key) reaches A in any response or error (INV-04) | canary scan over the bytes returned to A |
| G10. An apiserver with an untrusted certificate is refused (INV-12) | integration test |
| G11. Revoke during an exec session, a port-forward and a watch closes all three within 2 s (INV-07) | e2e with timing |
| G12. A cluster older than 1.35 is refused at startup (OD1, if accepted) | integration test with the fake apiserver's `/version` |
| G13. Every §5.12 key changes behaviour at its call site | one test per key |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **KP1** | Routing, header stripping, `RequestInfo` mapping and the D4 override, implicit allows | G1, G2, G8 |
| **KP2** | Forwarding with impersonation, `Status` errors, the cluster transport with TLS, the version check | G7, G9, G10, G12, G13 |
| **KP3** | The D11 self-check, and the RBAC examples verified in k3s | G3, G4 |
| **KP4** | Streaming: the WebSocket exec parser and recording, SPDY refusal, port-forward, watch sessions, teardown | G5, G6, G11 |
| **KP5** | D12: measure constrained impersonation on ≥ 1.36, then a `nyyrikki k8s rbac <cluster>` command that prints the RBAC for the configured profiles | the M6 row updated with the measured rules |

Ordering notes: KP1 and KP2 need docs/02 GC7. KP4 needs docs/03 AU3.
KP5 is last.

## 9. Risks and open questions

- **The KEP-4006 gates are beta until 1.38** (M3). If a future kubectl
  changes its fallback behaviour, G6 catches it in the nightly e2e run
  against the latest k3s.
- **RBAC allowlists drift from profiles.** KP5's generator closes most
  of that gap. Until then the RBAC is maintained by hand next to the
  profile.
- **The shared normalizer rejects a trailing slash and empty segments.**
  kubectl's discovery requests (`/api`, `/apis`) carry neither, but a
  client that sends one gets a `400`. G8's e2e run with real kubectl
  catches it, and any exception is decided and recorded here.
- **`proxy` subresources hide their target path** (M2). They are denied
  unless a profile explicitly allows them.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
