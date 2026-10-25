# R6 — Packaging, deployment and operations (docs/09)

**Status**: drafted 2026-10-25, adapted from the Warden design. Status
lives in [`ROADMAP.md`](../ROADMAP.md). Open: OD1 (where G runs) and OD2
(where audit anchors go). Decisions D1–D11 await the owner's approval.

Chunks **DP1–DP4** (`DP` = deployment; unused).

**Relationship to earlier work**: packages the binaries from
[docs/01](01-foundations.md), and gives the operations side of every
other doc: PKI bootstrap for [docs/02](02-grant-core.md), bot and pairing
setup for [docs/04](04-telegram-escalation.md), anchor shipping for
[docs/03](03-audit-log.md), and target setup for docs/06–08. Everything
in SECURITY.md reduces to G being a small, hardened, dedicated host
(RR-2). This doc is where that is made true.

---

## 1. Purpose

A security gateway that is hard to install, back up or recover gets
installed sloppily. This doc makes the deployment one well-defined
shape:

- one dedicated VM;
- three binaries and one systemd unit;
- a bootstrap run-book that ends with a working approval in Telegram;
- the rotations, backups, upgrades and break-glass procedures that keep
  it trustworthy afterwards.

### Non-goals

- **A container image, Helm chart or Kubernetes deployment** of G (D2).
- **High availability** (docs/01 non-goals).
- **Packaging for distributions** (deb, rpm). Tarballs only in v1.
- **Managing the targets' own configuration.** This doc lists what to
  set on targets. Doing it is the owner's tooling.

## 2. Measured and verified before writing

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Static binaries build with `CGO_ENABLED=0` given the chosen dependencies | docs/01 M3 (`modernc.org/sqlite` ran with `CGO_ENABLED=0`) | Confirmed for SQLite. FN2's CI builds all three binaries this way |
| M2 | The hardening directives in §5.2 are accepted by the systemd on the target distribution, with an acceptable `systemd-analyze security` exposure score | **Not yet measured.** DP1 runs it on the chosen OS (OD1) and records the score here | — |
| M3 | GitHub artifact attestations (`actions/attest-build-provenance`) are available for this private repository's plan | **Not yet measured.** DP2 checks it. If they are unavailable, releases ship SHA256SUMS only | — |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | Where does G run: which hypervisor and OS? | *Open.* Recommendation: a dedicated small VM (2 vCPU, 2 GiB RAM, 20 GiB disk, encrypted at rest) on a different physical host from A if one is available, and in no cluster it manages. A current Debian stable or Ubuntu LTS. Nothing else runs on it. |
| OD2 | Where do audit anchors and the audit log go off G (docs/03 §5.5)? | *Open.* Recommendation: object storage with object lock or retention, if the owner has it. Otherwise syslog over TLS to a separate host that G can append to but not delete from. Without either, docs/03 D3 protects only against non-root tampering. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **G is a dedicated Linux VM running only `nyyrikkid`** under systemd, as an unprivileged `nyyrikki` user, with the hardening in §5.2. | RR-2. The smallest possible TCB. |
| D2 | **No container image and no chart in v1.** | A container runtime adds to the TCB. Running G inside a cluster it manages breaks D1. |
| D3 | **A firewall on G**, inbound: `:8443` and `:2222` from A's addresses only, plus SSH from the operator's admin network for break-glass. Outbound: only to the configured targets, `api.telegram.org:443`, NTP and the anchor sink. | Least reachability. Matches docs/01 D8 and INV-19. |
| D4 | **Bootstrap goes through `nyyrikki init-pki`**, which generates every key and prints the fingerprints that must be stored off G (§5.3). | One audited way to create keys. |
| D5 | **Releases**: release-please tags; CI builds static `linux/amd64` and `linux/arm64` tarballs with `-trimpath`, plus `SHA256SUMS`, and build provenance if M3 allows. | docs/01 D16. Verifiable artifacts. |
| D6 | **Upgrades are stop, swap, start.** Migrations run forward-only (docs/02 §5.16). Active grants survive. Open sessions drop, and the agent reconnects within the grant. | Single instance. Good enough for a short window. |
| D7 | **Break-glass doesn't depend on G**: a sealed, separately protected admin path to each target, used only when G is down, and logged out of band. | RR-5. Nyyrikki removes standing access from A, not the humans' ability to recover their own infrastructure. |
| D8 | **Backups are encrypted and cover `/etc/nyyrikki` and `/var/lib/nyyrikki`.** SQLite is backed up with `VACUUM INTO`. A restore drill runs quarterly. | Keys in a backup are as sensitive as on G. |
| D9 | **The real-Telegram smoke test runs monthly**: a test profile with no scope, requested from A and approved on the real bot, checking the message format and that every decision path still works. | docs/04 §9: Bot API drift can't be caught by the fake. |
| D10 | **The listener inventory is tested**: on a deployed G, only `:8443`, `:2222`, the admin socket and loopback metrics listen. | docs/01 D8, INV-19. |
| D11 | **Approver setup includes 2-Step Verification and a passcode** in Telegram before pairing, and a review of the account's active sessions. | docs/04 D13, RR-3. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Running G as a pod in one of the managed clusters | Compromising the cluster would compromise G, and the other way round. D1, D2. |
| Running G on A, or on A's VM host without isolation | A must not be able to reach G's secrets (SECURITY.md). |
| deb/rpm packages in v1 | More release machinery than one VM needs. Tarballs plus this run-book are enough. |
| An inbound HTTPS endpoint for Telegram webhooks | docs/04 D2. |

## 5. Design

### 5.1 The G host

- **Hardware and OS**: per OD1. NTP synced, since timers and certificate
  validity depend on it (docs/02 §5.7). Disk encrypted at rest.
- **Access**: no interactive logins except the operator's break-glass
  administration over SSH from the admin network.
- **Firewall** per D3. A is firewalled to `:8443` and `:2222`.
- **Users and groups**:
  - `nyyrikki`: the service user;
  - `nyyrikki-admin`: the group for humans allowed the admin socket.

### 5.2 systemd unit

```ini
[Unit]
Description=Nyyrikki gateway
After=network-online.target
Wants=network-online.target

[Service]
User=nyyrikki
Group=nyyrikki
SupplementaryGroups=nyyrikki-admin
ExecStart=/usr/local/bin/nyyrikkid --config /etc/nyyrikki/nyyrikki.yaml
RuntimeDirectory=nyyrikki
RuntimeDirectoryMode=0755
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
CapabilityBoundingSet=
ReadWritePaths=/var/lib/nyyrikki
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Notes:

- The admin socket lives in `/run/nyyrikki`. `nyyrikkid` sets its
  group to `nyyrikki-admin` and its mode to `0660`, which is why the
  unit has `SupplementaryGroups=nyyrikki-admin`. The directory is
  `0755` so that members of that group can reach the socket; the
  socket's own mode is what protects it.
- Default ports are above 1024, so no capabilities are needed.
- DP1 measures the exposure score (M2).

### 5.3 Install and bootstrap

1. **Install** `nyyrikkid` and `nyyrikki` into `/usr/local/bin`, after
   verifying `SHA256SUMS`. Create the users and directories (docs/02
   §5.16).
2. **`nyyrikki init-pki`** creates, under `/etc/nyyrikki/pki/` (`0600`):
   - the internal CA, and a server certificate for `nyyrikki.internal`;
   - the SSH user CA;
   - the SSH proxy host key;
   - the audit anchor key.

   It prints the internal CA's SHA-256 (for enrolment), the SSH user
   CA's public key (for targets), and the anchor public key. **Store
   all three off G.**
3. **Create the Telegram bot** with @BotFather. Put the token in
   `/etc/nyyrikki/secrets/telegram-bot-token` (`0600`). Don't set a
   webhook (docs/04 D2).
4. **Write `nyyrikki.yaml`** (§5.12), then run `nyyrikki config.validate`.
5. **`systemctl enable --now nyyrikki`**, then `nyyrikki status`.
6. **Approvers**: in Telegram, enable 2-Step Verification and a
   passcode (D11). Then run `nyyrikki approver pair ap_<name>` and open
   the link on the phone (docs/04 §5.2).
7. **Enrol A**:
   1. `nyyrikki client enroll cl_<name>`.
   2. On A: `nyyrikki-mcp enroll …` (docs/05 §5.6).
   3. Register the MCP server (docs/05 §5.7).
8. **Configure the targets** (§5.4).
9. **Verify end to end**: request the no-scope smoke profile from a
   thread, approve it in Telegram, and check `nyyrikki audit.verify`.

### 5.4 Target setup

| Target | Where |
|---|---|
| Keycloak and other HTTP APIs | docs/06 §5.7 (service account and roles); upstream CA in `pki.upstream_ca_bundle_file` |
| Kubernetes | docs/07 §5.11 (impersonator role, per-profile roles); apiserver CA in `ca_file` |
| SSH servers | docs/08 §5.11 (`TrustedUserCAKeys`, principals, host keys into `ssh_known_hosts`) |

For every target:

- Admin access is restricted to G's address.
- The standing admin credentials A had are removed.

### 5.5 Backups and anchors

- **What**: `/etc/nyyrikki` and `/var/lib/nyyrikki`, encrypted and
  access-controlled. SQLite: `sqlite3 nyyrikki.db "VACUUM INTO '…'"`
  from a timer, never a raw copy of a live WAL database.
- **Anchors and audit off G**: per OD2. A systemd timer copies
  `anchors.jsonl`, and the rotated audit files, every 15 min.
- **Restore drill**: quarterly, into a staging VM. `audit.verify`
  passes, and a test grant works.

### 5.6 Monitoring and alerts

| Alert | Source |
|---|---|
| `nyyrikkid` down, or restarting | systemd / node exporter |
| `nyyrikki_audit_degraded == 1`, recording errors | metrics (docs/03 §5.8) |
| `nyyrikki_telegram_up == 0` for 2 min, or approvals unavailable | metrics (docs/04 §5.8) |
| `ssh.hostkey_mismatch`, `upstream.auth_failed` spikes, a disabled cluster | audit, metrics |
| Certificate expiry < 14 d (internal CA server cert, client certs) | `nyyrikki_cert_expiry_seconds` |
| NTP unsynchronized | node exporter |
| Unusual rates of `telegram.update_ignored` or `callback_rejected` | audit, metrics. A burst can mean someone is probing the bot |

### 5.7 Key rotation

| Key | Procedure |
|---|---|
| A's client certificate | Automatic (docs/05 D9). |
| Internal CA | Long-lived. To rotate: add the new CA as trusted alongside the old one, re-enrol the clients, then remove the old CA. |
| G's server certificate | `nyyrikki init-pki --renew-server-cert`. Clients trust the CA, not the certificate. |
| SSH user CA | Add the new public key to the targets' `TrustedUserCAKeys` (both trusted), switch G to the new key, then remove the old one after a day. |
| SSH proxy host key | New key, then reissue grants. A's per-grant `known_hosts` comes from the credentials. |
| Audit anchor key | Yearly. Add the new public key to `audit.anchor_pubkeys` under a new key ID, and keep the old one for verification. |
| Telegram bot token | BotFather `/revoke`, update the secret file, `config.reload`. |
| Upstream secrets | Rotate in the IdP, update `secrets/`, `config.reload`. |

### 5.8 Break-glass

When G is unavailable, humans use the independent path (D7). Examples: a
sealed admin credential in a safe, or a separate bastion with its own
MFA. Use is logged out of band, and drilled twice a year. It never goes
through A, and it is not a way to approve anything on G (docs/02
"rejected: break-glass approval").

### 5.9 Upgrades

1. Read the release notes and verify `SHA256SUMS`.
2. Run `nyyrikki config.validate` with the new binary.
3. `systemctl stop nyyrikki`, swap the binaries, `systemctl start
   nyyrikki`.
4. Migrations run, active grants reload, and open sessions are recorded
   as closed with `restart` (docs/02 §5.17).
5. Keep `nyyrikki-mcp` within one minor version of `nyyrikkid`. The
   control API is `/v1` and only grows additively.

### 5.10 Releases

- **release-please** opens the release PR from Conventional Commits. On
  merge, it tags.
- **The release workflow** builds:
  - `nyyrikki_<version>_linux_{amd64,arm64}.tar.gz`, each containing all
    three binaries, `LICENSE`, and the systemd unit;
  - `SHA256SUMS`;
  - build provenance, if M3 allows.

  Actions are pinned by SHA (docs/01 D11).
- **`nyyrikki-mcp` for A** is in the same tarballs. A's architecture
  may differ from G's.

### 5.11 Decommissioning

- **A client**: `nyyrikki client.disable cl_…` (this ends its new
  requests and connections), revoke its active grants, and
  `client.revoke-cert`. Then remove it from config and reload.
- **A profile**: remove it from config and reload. Live grants keep
  their snapshot until they end, or revoke them.
- **An approver**: `approver.unpair`, then remove them from config.

### 5.12 Complete example `nyyrikki.yaml`

```yaml
server:
  agent_listener: { addr: ":8443", server_name: "nyyrikki.internal" }
  ssh_listener:   { addr: ":2222", host_key_file: "/etc/nyyrikki/pki/ssh-proxy-host.ed25519" }
  admin_socket:   "/run/nyyrikki/admin.sock"
  metrics:        { enabled: true, addr: "127.0.0.1:9442" }
storage:  { sqlite_path: "/var/lib/nyyrikki/nyyrikki.db" }
audit:
  dir: "/var/lib/nyyrikki/audit"
  rotate_size: 128MiB
  retention: "0"
  anchor_key_file: "/etc/nyyrikki/pki/audit-anchor.ed25519"
  anchor_key_id: "an1"
  anchor_pubkeys: { an1: "/etc/nyyrikki/pki/audit-anchor.ed25519.pub" }
recordings: { dir: "/var/lib/nyyrikki/recordings", retention: 90d }
pki:
  internal_ca:
    cert_file: "/etc/nyyrikki/pki/internal-ca.crt"
    key_file:  "/etc/nyyrikki/pki/internal-ca.key"
    client_cert_ttl: 90d
    server_cert_ttl: 90d
  ssh_user_ca: { key_file: "/etc/nyyrikki/pki/ssh-user-ca.ed25519", cert_ttl: 3m }
  ssh_known_hosts_file: "/etc/nyyrikki/pki/ssh_known_hosts"
  upstream_ca_bundle_file: "/etc/nyyrikki/pki/upstream-ca.pem"
timers: { request: 15m, extension: 10m, step: 5m }
telegram:
  bot_token_ref: "secret://telegram-bot-token"
  bot_username: "nyyrikki_example_bot"
approvers:
  - { id: ap_juho, display_name: "Juho", telegram_user_id: 123456789, enabled: true }
clients:
  - { id: cl_agent_vm_a, display_name: "agent-vm-a", enabled: true, source_cidrs: ["10.20.0.5/32"] }
http_upstreams:
  - name: keycloak-admin
    base_url: "https://keycloak.internal/admin"
    credential:
      type: oauth2_client_credentials
      token_url: "https://keycloak.internal/realms/acme/protocol/openid-connect/token"
      client_id: nyyrikki-admin
      client_secret_ref: "secret://keycloak-nyyrikki-admin"
k8s_clusters:
  - name: prod
    apiserver_url: "https://10.0.0.1:6443"
    ca_file: "/etc/nyyrikki/pki/prod-apiserver-ca.pem"
    credential: { serviceaccount_token_file: "/etc/nyyrikki/secrets/prod-sa-token" }
ssh_targets:
  - { name: node-1, host: 10.0.1.11, port: 22, logins: [root] }
  - { name: node-2, host: 10.0.1.12, port: 22, logins: [root] }
profiles:
  - name: smoke
    description: "No access. Used to test the approval path (D9)."
    clients: [cl_agent_vm_a]
    ttl: { default: 5m, max: 5m, max_total: 5m }
    step: off
  # k8s-node-maint and keycloak-users: see docs/02 §5.15.5
```

## 6. Security considerations

- **New trust boundary**: none in code. Operationally, this doc sets the
  boundaries everything else assumes: G's isolation (D1, D3), the
  approver's account hygiene (D11), and the key custody (D4, D8).
- **Dependency failures**: an outage of G, Telegram or a target leaves
  no access (RR-5). Break-glass is independent (D7). Disk-full stops
  escalations through audit fail-closed (docs/03 §5.6), which an alert
  catches.
- **Supply chain**: verified tarballs, checksums, provenance if
  available, pinned actions (D5).
- **What reaches the model, the audit log or Telegram**: nothing new.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. On a deployed G, the only listeners are `:8443`, `:2222`, the admin socket, and loopback metrics. No socket accepts Telegram updates (docs/01 D8, INV-19) | an integration test of the running server's listeners, plus `ss -lntpx` checked in the DP1 run-book |
| G2. The systemd unit starts with the §5.2 hardening, and its exposure score is recorded (M2) | DP1, on the OD1 OS |
| G3. The bootstrap run-book in §5.3 takes a fresh VM to a working smoke-profile approval | DP3: executed by the owner and timed, with any gaps fixed in this doc |
| G4. Backup and restore into staging passes `audit.verify` and a test grant | DP3 drill, recorded with the date |
| G5. A tagged release produces tarballs for both architectures, `SHA256SUMS`, and provenance (or a recorded reason it doesn't) | DP2: first release |
| G6. Upgrading with an active grant keeps the grant, and the agent continues after reconnecting | DP4: e2e test across two builds |
| G7. Break-glass is documented per target and drilled | the owner, recorded with the date |
| G8. The monthly real-Telegram smoke test (D9) is scheduled and its procedure written down | DP3 |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **DP1** | systemd unit, install layout, `init-pki`, listener inventory test | G1, G2 |
| **DP2** | Release workflow: release-please and build/checksum/provenance | G5 |
| **DP3** | Run-books: bootstrap, rotation, backup and restore, break-glass, smoke test. Executed once | G3, G4, G7, G8 |
| **DP4** | Upgrade e2e test | G6 |

Ordering notes: DP1 can start once docs/02 GC8 (the admin CLI) exists.
DP2 any time after docs/01 FN2. DP3 needs a deployable build with docs/04
and at least one proxy. DP4 needs two releases.

## 9. Risks and open questions

- **OD1 and OD2 decide how strong RR-2 really is.** Without anchors off
  G, root on G can rewrite history unnoticed.
- **Run-books rot.** G3 has to be re-run whenever §5.3 changes. The
  monthly smoke test (D9) catches some of that drift.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
