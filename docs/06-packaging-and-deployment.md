# R6 — Packaging and deployment, the minimal part for M4 (docs/06)

**Status**: drafted 2026-10-26. No owner decisions needed beyond
docs/01's. Awaiting the owner's approval of the doc as a whole; merging
the PR that adds it is that approval. Status lives in
[`ROADMAP.md`](../ROADMAP.md).

Chunks **PK1–PK4** (`PK` = packaging; unused).

**Relationship to earlier work**: implements docs/01 OD2, D3, D10, D11,
D15, D23 for `ROADMAP.md` M4. Upgrades and the rest of R6 come later.

---

## 1. Purpose

The owner has to be able to install Nyyrikki next to a real cluster,
give it exactly the rights it needs on each target, sign agents in and
pair the approver, and upgrade it by version, without anything in the
chart assuming the owner's environment.

### Non-goals

- Deploying Keycloak (docs/01 §5.1: it may run anywhere).
- High availability (docs/01 OD11).
- An operator surface (R7).

## 2. Measured and verified before writing

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `gcr.io/distroless/static-debian12:nonroot` runs a static Go binary as UID 65532 without a shell | distroless README, 2026-10-26 | Confirmed |
| M2 | A projected ServiceAccount token is mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` and refreshed by the kubelet; a Secret mounted as a volume is updated in place when the Secret changes (not with `subPath`) | kubernetes.io "Configure Service Accounts for Pods", "Secrets" | Confirmed. D4 |
| M3 | GitHub artifact attestations are available for this private repository | **Not yet measured.** PK4 | — |

## 3. Owner decisions

None new. docs/01 OD2, OD7, OD10, OD11 apply.

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **One image**, `ghcr.io/tuhis/nyyrikki`, holding only `nyyrikkid` (with kubectl's code inside, docs/04 D6), on distroless static, non-root, built `CGO_ENABLED=0 -trimpath`. The base image is pinned by digest. | docs/01 D11; least surface. |
| D2 | **A Helm chart** in `deploy/chart/nyyrikki`: one Deployment (one replica, `Recreate`, `readOnlyRootFilesystem`, all capabilities dropped, `RuntimeDefault` seccomp, `automountServiceAccountToken` only when a target is in-cluster), a Service for `:8443`, a PVC for the state directory, an in-memory `emptyDir` for the runtime directory, a ConfigMap rendered from `values.config`, a ServiceAccount, and a NetworkPolicy. The chart creates no Secret; values name existing ones (TLS, Telegram token, introspection secret, remote target tokens). | docs/01 D10–D12, D15. Secrets created by Helm end up in the release record. *Revised 2026-10-27 (building the e2e test)*: an optional `trustedCA` ConfigMap adds CA certificates to the system roots, through a mounted file and `SSL_CERT_DIR` (the only env var, and not a secret), for an authorization server or Bot API endpoint behind a private CA. *Extended 2026-10-30 by [docs/07](07-ssh-target.md) §5.5*: with an SSH target, the chart renders the `ssh` block, mounts `secrets.sshUserCA` at `/etc/nyyrikki/ssh/user-ca`, and NOTES.txt prints each host's setup command. |
| D3 | **RBAC on the cluster Nyyrikki runs in**: a ClusterRole with only `impersonate` on `users` and `groups`, `resourceNames` set to the human's Kubernetes user and groups from the values, bound to Nyyrikki's ServiceAccount. For a remote cluster, `deploy/remote-target/` holds the same role plus a ServiceAccount and a long-lived token Secret to apply there; the token is copied into a Secret in Nyyrikki's namespace. | docs/01 D15, INV-05. |
| D4 | **Rotation**: every credential is a mounted file read on use (docs/02 D2, docs/04 D9, docs/05 D10), so replacing a Secret's value is the rotation; no restart is needed. The in-cluster token is rotated by the kubelet (M2). | One mechanism for every credential. |
| D5 | **The NetworkPolicy** admits `:8443` from the namespaces listed in values (default: all) and `:8081` from anywhere (it serves no data), and denies all other ingress. Egress is open by default, with a values option to restrict it to DNS, the authorization server, Telegram and the API servers. | docs/01 D10; SECURITY.md deployment requirements. |
| D6 | **Releases**: release-please on `main` opens the release PR; on release, a workflow builds the image (pushed by digest and by version tag) and the CLI for linux and darwin, amd64 and arm64, with SHA256SUMS, and packages the chart with the same version. *Revised 2026-10-28 (owner decision, deploying on the owner's cluster)*: the chart is also pushed to `oci://ghcr.io/tuhis/charts/nyyrikki`, so a GitOps controller such as Flux can install it by version from an OCI `HelmRepository`; the release asset stays. | docs/01 D23. |
| D7 | **Setup documentation** in `docs/setup/`: Keycloak (realm, CLI client with the device grant and "Require DPoP bound tokens", the audience scope, DCR policies, introspection client, session lengths, no `offline_access`; *revised 2026-10-30, docs/01 OD17*: offline sessions for MCP harnesses, capped, and how to revoke them), Telegram (BotFather, `/start` to learn the user ID, 2-Step Verification and passcode), install, enrolling agents (`nyyrikki login`, `nyyrikki login --mcp` with `.mcp.json`, the harness's own OAuth sign-in), and the deployment requirements of SECURITY.md. | docs/01 §5.4; SECURITY.md deployment requirements. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Secrets created by the chart from values | They'd be stored in the Helm release Secret and in whatever holds the values file. |
| A separate CLI image | Agents install a binary; an image adds nothing. |

## 5. Design

The chart's values mirror the config file of docs/02 §5.6 under
`config:`, plus `secrets:` naming the existing Secrets and where each is
mounted, `rbac.impersonate` (users, groups), `networkPolicy`, `image`,
`persistence` and `tls`.

## 6. Security considerations

- **Credentials.** Mounted read-only from Secrets, never env vars
  (docs/01 D15); the chart's template test asserts no `env` holds a
  Secret reference.
- **RBAC.** Impersonate only the human's names (D3); a template test
  asserts the ClusterRole has no other rule.
- **What the agents can read.** The pod spec and ConfigMap hold no
  secret (docs/01 OD7).
- **Listeners.** Only `:8443` and `:8081` are exposed (docs/01 D10).
- **The human's own rights on the cluster Nyyrikki runs in** (docs/04
  OD3, accepted risk). A human who can reach Nyyrikki's credentials can,
  through one approved request or any request under an elevation, hand
  them to the agent. The setup docs give the rights that narrow it, best
  effort (SECURITY.md, Accepted risks, which is the full list: no write
  and no Secret read in Nyyrikki's namespace, and in the namespace
  `deploy/remote-target/` creates on remote targets; no `nodes/proxy`,
  no node debugging, no privileged or `hostPath` pods, no RBAC
  `bind`/`escalate`/`impersonate`, no admission webhooks or mutating
  admission policies, no `persistentvolumes` write, no CSR approval),
  and the option that closes it: Nyyrikki on a cluster the human doesn't
  administer.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 The chart lints and renders against the Kubernetes 1.35 schemas | `helm lint` and `kubeconform -strict` gates |
| G2 The rendered ClusterRole has only `impersonate` on the configured names, and no container env references a Secret | `TestChartRBAC`, `TestChartNoSecretEnv` (template tests) |
| G3 The image builds, runs as non-root and starts with a valid config | CI image build and a smoke test in kind (e2e) |
| G4 Nyyrikki runs in front of a real target, and an agent completes real tasks through a one-off approval and an elevation, and the owner runs M2's and M3's manual checks | manual, by the owner (`ROADMAP.md` M4) |
| G5 A tagged release publishes the image, CLI binaries with checksums and the chart | the release workflow on the first release |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **PK1** | Dockerfile and image build in CI | G3 (build) |
| **PK2** | Helm chart, remote-target manifests, chart gates and template tests | G1, G2 |
| **PK3** | setup docs | G4 (owner follows them) |
| **PK4** | release-please and the release workflow | G5 |

## 9. Risks and open questions

- **Attestations** (M3) may not be available on the plan; then releases
  ship SHA256SUMS only.

## 10. How it was implemented (2026-10-27)

- The chart builds `config.yaml` itself from values and fixes every file
  path to its mounts, so a path in values can't point at the wrong file.
  `TestChartConfigIsValid` parses the rendered file with nyyrikkid's own
  config loader, so every value reaches the binary.
- The ClusterRole's groups rule is left out when the human has no groups:
  an empty `resourceNames` would mean "any group". `TestChartRBAC` covers
  both cases.
- The image is about 95 MB, mostly kubectl's code (docs/04 M9).
- M3 (attestations) is not measured yet; the release workflow publishes
  SHA256SUMS.

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
