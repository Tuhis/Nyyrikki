# R1 — Foundations: architecture, threat model, toolchain (docs/01)

**Status**: drafted 2026-10-25, adapted from the Warden design. Status
lives in [`ROADMAP.md`](../ROADMAP.md). OD1 and OD2 were decided by the
owner on 2026-10-25. OD3 (the project licence) is open. Decisions D1–D16
await the owner's approval. The threat model is in
[`SECURITY.md`](../SECURITY.md). Revised 2026-10-26 after review in PR #1:
D9 and §5.8 (licences `go-licenses` can't classify).

Chunks **FN1–FN3** (`FN` = foundations; unused).

**Relationship to earlier work**: this is the first design doc. It
adapts a design written before the repository existed (the "Warden"
docs), restructured into this repo's roadmap items. Every later doc
builds on the decisions here.

---

## 1. Purpose

An AI coding agent runs on an agent VM (**A**) with full local autonomy.
Inside A it can do anything. Sometimes a task needs more than A is
allowed:

- SSH to a server as an admin;
- an imperative `kubectl` action;
- the Keycloak admin API;
- an entire Kubernetes node upgrade, which is all three.

Today there are two ways to provide that, and both are bad:

- Put admin credentials on A. Every process on A can then read them,
  forever.
- Have the human do it by hand. That is slow, and the agent loses the
  thread's context.

The situation where it hurts: the agent is halfway through an upgrade,
hits `forbidden`, and the human has to drop what they're doing and take
over.

Nyyrikki is a gateway on a separate host (**G**) that holds the real
credentials. The agent asks for a named, time-limited **grant**, and a
human approves it with one tap in Telegram. From then on, G mediates
every operation the agent makes: it checks policy, holds operations that
need another look, records everything, and cuts access the moment the
grant ends. The agent keeps working in the same thread.

### Goals (for the whole system; each doc refines its own)

1. **In-thread elevation.** The agent asks from the thread it is working
   in. The approver taps once in Telegram. The agent continues with full
   context.
2. **No privileged secret on A.** A holds only request capability and
   short-lived, revocable grant credentials.
3. **An approval A can't produce**, from a channel A can't reach (OD2,
   SECURITY.md "central assumption").
4. **Least privilege per profile** across Kubernetes, SSH and HTTP admin
   APIs.
5. **Per-operation oversight when wanted** (step mode).
6. **Instant revoke and hard expiry**: within 2 s.
7. **Complete, tamper-evident audit**, plus recordings of terminal and
   exec streams.
8. **Existing tools work unchanged** (`kubectl`, `helm`, `ssh`, `scp`,
   `sftp`, `curl`, `ansible`), through generated config files.

### Non-goals (v1)

- **Securing A itself.** Anything on A can use an active grant
  (SECURITY.md RR-1).
- **Human sign-in through OIDC**, and human users as requesters (OD1;
  roadmap R12).
- **High availability.** One `nyyrikkid`. If G is down, nobody elevates,
  and humans keep their own break-glass path.
- **Browser access to admin consoles**, such as the Keycloak admin UI.
  APIs only.
- **Other protocols**: databases, RDP and so on.
- **Understanding shell semantics.** SSH command rules are guardrails.
- **Approval inside the coding tool's UI.** It renders on A (rejected
  alternatives).
- **Moderated mode and a live session view.** Deferred to R7 (docs/02
  D12).

## 2. Measured and verified before writing

Measured on 2026-10-25. Library versions are the latest releases on that
date.

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

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | Who does v1 authenticate as the requester: agents on A, human users through OIDC, or both? | **Decided 2026-10-25: agents first.** Agent clients authenticate with mTLS plus per-grant credentials. Human sign-in through OIDC is a later roadmap item (R12). The original R2 scope ("OIDC sign-in, sessions") moves there. |
| OD2 | What may a Telegram tap approve on its own? Options: a tap for everything; a tap plus a passkey for high-risk profiles; a passkey always, with Telegram only notifying. | **Decided 2026-10-25: a Telegram tap approves everything on its own.** No passkey anywhere. The owner chose the UX of one tap. The residual risks are recorded in SECURITY.md (RR-3, RR-6). Passkey approval is listed as rejected in CLAUDE.md. |
| OD3 | Nyyrikki's own licence. The repository has none yet. | *Open.* Recommendation: **Apache-2.0**, the same as `gawk`. It includes a patent grant, and it is compatible with every dependency allowed by D9. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Topology.** All real credentials live on a dedicated gateway host G. A is untrusted and reaches targets only through G. Targets accept admin access only from G. | SECURITY.md: the central assumption, INV-01 and INV-04. |
| D2 | **Requester**: agent clients (OD1). The identity is an mTLS client certificate from G's internal CA (docs/02 §5.11). | OD1. |
| D3 | **Approval channel**: a Telegram bot, by outbound long-poll from G. A verified tap decides on its own (OD2, docs/04). | OD2. With no inbound endpoint, nothing on the network can inject an update (INV-19). |
| D4 | **Language: Go.** `go.mod` declares `go 1.26.0`, the oldest supported major (M1, M2). CI tests the latest patch of both supported majors. The floor rises when a major drops out of support. | One language for all three binaries. The Kubernetes request parser and the SSH library are native Go (M5, docs/07), so G parses requests exactly as the apiserver does. |
| D5 | **One module**, `github.com/Tuhis/Nyyrikki`, with three binaries: `nyyrikkid` (the server, on G), `nyyrikki` (the admin CLI, on G), and `nyyrikki-mcp` (on A). | Shared types for the control API, one set of gates. |
| D6 | **Storage**: SQLite in WAL mode through `modernc.org/sqlite` for state. Append-only JSONL files for the audit log. Files for recordings. Binaries are built with `CGO_ENABLED=0 -trimpath`. | Single instance, no extra service, static binaries (M3). |
| D7 | **Config**: one YAML file, decoded strictly with `go.yaml.in/yaml/v3` (`KnownFields(true)`) and validated in full. Secrets are referenced, never inline (docs/02 §5.15). | Fail closed on typos. M4: the old `gopkg.in/yaml.v3` is unmaintained. |
| D8 | **Listeners**: `:8443` for agents (mTLS required), `:2222` for SSH (per-grant key), the admin Unix socket, and optional metrics on loopback only. That is the complete list. There is no web UI in v1. | Least surface. A test asserts this inventory (docs/09 G1). |
| D9 | **Dependency policy.** Every dependency is justified in its PR (CONTRIBUTING). The licence allowlist is MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 and ISC; CC-BY-4.0 is allowed for documentation files only. `go-licenses` can't express "documentation only", so a module whose licence it can't place on the allowlist is handled as in §5.8: reviewed by hand, ignored by name with the reason, and its licence file pinned by hash. Versions are pinned in `go.mod`, `go.sum` is committed, builds use `-mod=readonly`, and module downloads are verified through the Go checksum database. Renovate proposes updates, as in `gawk`. | Supply chain (SECURITY.md scope). |
| D10 | **Gates**: format, vet, staticcheck, `go mod tidy -diff`, `go test -race` across the full suite, govulncheck, a licence check and a secret scan. Each gate has a canary that proves it fails on a planted violation (§5.8). | CODE-REVIEW §Gates. The gawk lesson: a gate that checks nothing is worse than none. |
| D11 | **CI**: GitHub Actions. Every third-party action is pinned to a commit SHA. The default token permission is `contents: read`. | Supply chain. |
| D12 | **Repository layout** in §5.6. Application code goes in `internal/`, and only `nyyrikki-mcp`'s control-API client is shared across binaries. | Nothing is importable from outside by accident. |
| D13 | **Conventions** in §5.7: ULID IDs with type prefixes, RFC 3339 UTC times with milliseconds on the wire, Unix milliseconds in the DB. | One format everywhere. |
| D14 | **Test layers**: unit; integration (an in-process `nyyrikkid` with real SQLite, a fake Bot API and fake targets); end to end (docker compose with real k3s, OpenSSH and Keycloak). Parsers and matchers are fuzzed. | Each layer catches what the others can't (§5.9). |
| D15 | **Every security invariant lives in SECURITY.md** and is tested by at least one acceptance criterion in a design doc. | One home per fact (CLAUDE.md). |
| D16 | **Releases**: release-please, following Conventional Commits (CONTRIBUTING). Packaging details are in docs/09. | Already the repo's convention. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Adopt Teleport instead of building | Compared in the design conversation that preceded this repository. The owner chose to build. That comparison wasn't recorded with sources, so measure Teleport's current editions before reopening this. |
| Approve inside the coding tool's UI (a native button in the T3 Code thread) | It renders on A, and the agent controls A. It could answer its own prompt. SECURITY.md "central assumption". |
| Give A scoped admin credentials, or wrapper CLIs on A that "check first" | Any process on A can read the credentials or skip the wrapper. INV-01, INV-04. |
| Rust | Good safety properties, but the Kubernetes request classifier the design depends on (docs/07 M1) and a mature SSH server and client library are Go. Reimplementing either is a source of exactly the drift that causes bypasses. |
| TypeScript / Node | The same problem, and weaker SSH server support. |
| Human OIDC sign-in in v1 | OD1. |
| A web approval UI with passkeys on G | OD2. Recorded in CLAUDE.md "Rejected". |

## 5. Design

### 5.1 Architecture

```
┌────────────────────── Agent VM (A) — untrusted ───────────────────────┐
│ coding agent (Claude Code / Codex, e.g. in a T3 Code thread)           │
│   ├─ MCP stdio → nyyrikki-mcp ───────── control API (mTLS) ───────────┼──┐
│   ├─ kubectl (generated kubeconfig) ─── /k8s/<cluster>/… ─────────────┼──┤ :8443
│   ├─ curl    (generated curlrc)     ─── /u/<upstream>/… ──────────────┼──┤
│   └─ ssh/scp/sftp (generated config) ─────────────────────────────────┼──┼─▶ :2222
└────────────────────────────────────────────────────────────────────────┘  │
                                                                            ▼
┌──────────────────────────── Gateway host (G) — TCB ────────────────────────────────┐
│ nyyrikkid                                                                           │
│  ├ control API (grants, extensions, steps view)                         docs/02     │
│  ├ gate: policy · step broker · allowances   (the one decision point)   docs/02     │
│  ├ HTTP proxy ── injected upstream credential ───▶ Keycloak admin API…  docs/06     │
│  ├ k8s proxy  ── impersonation only ─────────────▶ kube-apiserver(s)    docs/07     │
│  ├ SSH proxy  ── ephemeral cert (≤ 3 min) ───────▶ servers / nodes      docs/08     │
│  ├ grant manager · timers · teardown · SQLite                           docs/02     │
│  ├ audit log (hash chain, anchors) · recordings                         docs/03     │
│  ├ Telegram bot ── outbound long-poll only ──────▶ api.telegram.org     docs/04     │
│  └ admin socket /run/nyyrikki/admin.sock ◀── nyyrikki CLI (root on G)   docs/02     │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                         ▲
                     approver's phone ── Telegram ── taps Approve / Deny / Revoke
```

### 5.2 Components and where they are specified

| Component | Binary | Doc |
|---|---|---|
| Config, store, client identity, grants, policy, gate, control API, admin socket | `nyyrikkid`, `nyyrikki` | [docs/02](02-grant-core.md) |
| Audit log and recordings | `nyyrikkid` | [docs/03](03-audit-log.md) |
| Telegram escalation | `nyyrikkid` | [docs/04](04-telegram-escalation.md) |
| Agent side: MCP server, enrolment, credential files | `nyyrikki-mcp` | [docs/05](05-agent-integration.md) |
| HTTP admin-API proxy | `nyyrikkid` | [docs/06](06-http-proxy.md) |
| Kubernetes API proxy | `nyyrikkid` | [docs/07](07-kubernetes-proxy.md) |
| SSH proxy | `nyyrikkid` | [docs/08](08-ssh-proxy.md) |
| Packaging, deployment, operations | all | [docs/09](09-packaging-and-deployment.md) |

### 5.3 Listeners

| Listener | Default | Who connects | Transport security | Authentication |
|---|---|---|---|---|
| Agent | `:8443` | A only (firewall) | TLS with an internal-CA server certificate | client certificate **required**, plus the grant token on `/k8s` and `/u` |
| SSH | `:2222` | A only (firewall) | SSH (G's proxy host key, pinned on A) | per-grant public key |
| Admin socket | `/run/nyyrikki/admin.sock` | the `nyyrikki` CLI on G | n/a | file permissions (group `nyyrikki-admin`) |
| Metrics (optional) | `127.0.0.1:9442` | a local scraper | none | none: loopback only |

There is no inbound listener for Telegram (D3) and no web UI (D8).

### 5.4 Request path

Every protocol follows the same path:

```
receive → authenticate the transport (client cert, or SSH key → grant)
        → load the active grant; require client == transport identity     (INV-06)
        → parse into a policy.Operation (protocol doc)
        → gate.Authorize: Evaluate → deny | allow | hold for a Telegram tap
        → audit op.start (fail closed)                                       (INV-10)
        → forward with G's credential, tee the recording
        → audit op.end
```

Everything in flight runs under the grant's context. Cancelling the
context on revoke, expiry or release aborts the operation and closes its
connections (INV-07).

### 5.5 Deployment shape

- **G** is a small dedicated Linux VM. It is not A, and not a node of any
  cluster it manages.
- **Targets** accept admin access only from G's address.
- **A** loses all its standing admin credentials. The point is that A
  can't do these things without G.

The details are in docs/09.

### 5.6 Repository layout

```
go.mod                      module github.com/Tuhis/Nyyrikki
cmd/
  nyyrikkid/                server
  nyyrikki/                 admin CLI (admin socket client)
  nyyrikki-mcp/             agent-side MCP server + enroll (docs/05)
internal/
  codes/                    error codes, one definition (docs/02 D13)
  config/  store/  pki/  identity/  grants/  policy/  gate/  steps/
  controlapi/  adminapi/  audit/  record/  telegram/  render/
  proxy/http/  proxy/k8s/  proxy/ssh/
  server/                   wiring, listeners, lifecycle
pkg/
  controlclient/            control-API client used by nyyrikki-mcp
migrations/                 0001_core.sql (docs/02), 0002_telegram.sql (docs/04)
test/
  fakebotapi/               fake Telegram Bot API (docs/04 TG1)
  e2e/                      docker compose environment (§5.9)
  canaries/                 planted violations the gates must catch (§5.8)
docs/
```

### 5.7 Conventions

- **IDs** are a type prefix plus a ULID: `cl_ ap_ gr_ ex_ st_ al_ ss_ pm_
  dr_`. Config-defined IDs may use a slug (`cl_agent_vm_a`).
- **Tokens**: `nyg_<grantId>_<secret>` (grant), `nye_<secret>`
  (enrolment). G stores only their SHA-256.
- **Times** are RFC 3339 UTC with milliseconds on the wire
  (`2026-10-25T09:15:02.123Z`) and INTEGER Unix milliseconds in SQLite.
- **Durations in config** use Go syntax plus `d` for days (`90s`, `15m`,
  `12h`, `90d`). Sizes use `KiB`, `MiB` and `GiB`.
- **Hosts**: the agent VM is **A**, the gateway host is **G**. The
  humans who decide are **approvers**. The person running G is the
  **operator**, root on G. A's machine identity is a **client**.
- **Spec keywords**: MUST, SHOULD and MAY as in RFC 2119.

### 5.8 Gates and CI

FN2 adds these to `CODE-REVIEW.md` §Gates and to `CONTRIBUTING.md`
"Running the gates":

```sh
test -z "$(gofmt -l .)"                                   # format
go vet ./...
staticcheck ./...
go mod tidy -diff                                         # go.mod/go.sum tidy
go test -race -count=1 ./...                              # unit + integration
govulncheck ./...
go-licenses check ./... --allowed_licenses=MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC
gitleaks dir . --redact                                   # secret scan
```

**Licences that `go-licenses` can't classify.** The MCP go-sdk's
licence files mix MIT and Apache-2.0 for code with CC-BY-4.0 for docs
(M7), and `go-licenses` judges a module by its licence file, not by file
type. FN2 runs `go-licenses report` on it and records the result in M9.
If the module doesn't pass as reported, FN2:

- reviews the licence by hand, and records the outcome and the date in
  M9;
- adds `--ignore github.com/modelcontextprotocol/go-sdk` to the gate
  with a comment pointing at M9;
- pins the SHA-256 of the module's licence files in the gate, so a
  licence change in an update fails CI and is reviewed again.

**Canaries**: `test/canaries/` holds one planted violation per gate:

- a misformatted file;
- a vet error;
- a staticcheck finding;
- an untidy `go.mod`;
- a failing test;
- a module with a known vulnerability;
- a disallowed licence;
- a fake secret.

The canary files are excluded from the normal gate run. A CI job,
`gates-selftest`, runs each gate against its canary and **fails if the
gate passes**.

The e2e suite (§5.9) runs on merge to `main` and nightly. Unit and
integration tests run on every push and pull request.

### 5.9 Testing strategy

1. **Unit**: pure logic. Policy matcher and evaluation, config
   validation, audit chain, PKI minting, path normalization, the
   untrusted-text renderer, token formats.
2. **Integration**: one in-process `nyyrikkid` with a real temp SQLite,
   the fake Bot API (`test/fakebotapi`, which records every request and
   can inject updates), and fake upstreams (an HTTP stub, a fake
   apiserver, an in-process SSH server).
3. **End to end**: `docker compose` in `test/e2e`:

   ```
   nyyrikkid    built from source
   agent        nyyrikki-mcp + kubectl + openssh-client + curl, scripted scenarios
   k3s          single-node cluster, RBAC and the nyyrikki ServiceAccount preloaded
   sshd-target  OpenSSH trusting G's SSH user CA
   keycloak     dev mode, realm acme, service-account client
   fakebotapi   the same fake Bot API, driven by the test runner as "the approver"
   ```

4. **Adversarial "evil agent" scenario**. The agent tries each of these:
   - approve its own request;
   - replay a tap;
   - reach the Bot API with a forged update;
   - inject impersonation headers;
   - traverse paths;
   - point the HTTP proxy elsewhere;
   - reuse a released token;
   - open a denied SSH channel.

   Every attempt must fail, and must be audited.
5. **Fuzzing**: the policy matcher, HTTP path normalizer, k8s operation
   mapper, audit canonical encoder, SSH username parser, exec-frame
   parser, Telegram callback-data parser and the untrusted-text renderer.

### 5.10 What CLAUDE.md records once this doc is approved

FN3 replaces CLAUDE.md's "Architecture (nothing locked in yet)" section
with a locked-in list, each entry linking back here:

- agents first;
- Telegram tap approves on its own;
- Go `1.26.0` floor;
- one module with three binaries;
- SQLite, JSONL audit, file recordings;
- the listener inventory (D8);
- the dependency policy (D9).

Until then, that section stays as it is.

## 6. Security considerations

- **The threat model is SECURITY.md.** It covers assets, actors, the
  central assumption, trust boundaries, residual risks RR-1–RR-7 and
  invariants INV-01–INV-19. This doc's architecture decisions are what
  that model assumes. Changing D1, D3 or D8 means revisiting it.
- **New trust boundaries**: A ↔ G (docs/02), Telegram ↔ G (docs/04),
  G ↔ targets (docs/06–08). Each doc's §6 names who controls each input
  and where it is validated.
- **Supply chain**: pinned modules verified against the checksum DB,
  govulncheck, a licence allowlist, a secret scan, actions pinned by SHA,
  and a read-only CI token (D9–D11). Reproducible builds (D6), and the
  release path in docs/09.
- **Fail closed** is a project-wide rule (CLAUDE.md). Every doc lists
  how each of its dependency failures ends in deny.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. The owner approves this doc's decisions, and OD3 is answered | the owner, recorded in §3 and §4 with the date |
| G2. CI runs every gate in §5.8 on the empty skeleton, and all pass | the CI run on the FN2 pull request |
| G3. Every gate fails on its canary | the `gates-selftest` CI job, which fails if any gate passes its canary |
| G4. CODE-REVIEW §Gates and CONTRIBUTING "Running the gates" list exactly the §5.8 commands | review of the FN2 pull request |
| G5. CLAUDE.md records the locked-in decisions (§5.10) and nothing else from this doc | review of the FN3 pull request |
| G6. SECURITY.md's threat model is approved together with this doc | the owner, at G1 |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **FN1** | `go.mod`, the three `cmd/*/main.go` stubs (print the version and exit), `internal/codes` (empty), the `LICENSE` per OD3, `renovate.json5`, a `Makefile` with a `gates` target | G1 |
| **FN2** | `.github/workflows/ci.yml` running the gates; `test/canaries` and `gates-selftest`; pinned tool versions (M9); the CODE-REVIEW and CONTRIBUTING gate sections | G2, G3, G4 |
| **FN3** | CLAUDE.md "Architecture (locked in)" | G5 |

Ordering notes: FN1 waits for G1, since no code lands before the owner
approves this doc. FN3 lands after FN2, so the locked-in list includes
the real gate commands.

## 9. Risks and open questions

- **The rest of the plan rests on OD2.** If the owner later wants a
  passkey for some profiles, docs/04 grows a second decision channel and
  INV-02 changes. Reopening it requires new evidence (CLAUDE.md
  "Rejected").
- **Floors move.** Go majors leave support every six months, and the
  Kubernetes libraries track Go closely (M2). Renovate plus D4's
  floor-bump rule keep this routine.
- **Effort.** The original estimate for this design was a usable first
  slice (approvals plus the HTTP proxy) in about 3–5 weeks, and the full
  build in about 2–3 months, plus an external security review before
  production use. It predates the switch to Telegram, which removes the
  web UI and passkey work.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
