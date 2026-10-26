# R11 — SSH proxy (docs/08)

**Status**: drafted 2026-10-25, adapted from the Warden design. Status
lives in [`ROADMAP.md`](../ROADMAP.md). There are no open owner
decisions. Decisions D1–D14 await the owner's approval. Revised 2026-10-26 after
review in PR #1: D2 (`source_cidrs` required) and §5.3 (requests before
the dial are queued).

Chunks **SH1–SH5** (`SH` = SSH; unused).

**Relationship to earlier work**: a protocol proxy behind the gate in
[docs/02](02-grant-core.md) §5.9, using the per-grant SSH key from
docs/02 §5.12. It records through [docs/03](03-audit-log.md) §5.4, and
writes the SSH config consumed by
[docs/05](05-agent-integration.md) §5.4.

---

## 1. Purpose

SSH is where "admin" is most absolute and least observable. A root key
on A works on every server it is authorized for, forever, and nothing
records what it typed. With this proxy:

- A connects to G with a key that exists only for one grant.
- G checks the profile's rules for every channel, and holds commands for
  a tap in step mode.
- G logs in to the target with a certificate that is valid for three
  minutes and minted for that session alone.
- G records the terminal.
- When the grant ends, the session ends within two seconds.

Plain `ssh`, `scp`, `sftp` and `ansible` work through a generated config
file.

### Non-goals

- **Understanding shell commands.** Command rules are guardrails, not a
  boundary (SECURITY.md RR-4).
- **Agent forwarding, X11, and remote port forwarding** (`-R`): always
  denied.
- **Password or keyboard-interactive login**, on either side.
- **Recording file contents** for SFTP and direct-tcpip. Metadata only.
- **Jump-host chains beyond G**, and targets reached through another
  bastion.

## 2. Measured and verified before writing

All measured on 2026-10-25.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `golang.org/x/crypto/ssh` v0.58.0 (BSD-3-Clause, needs Go 1.26) covers the server side (`ServerConfig`, `NewServerConn`), the client side, certificate signing (`Certificate.SignCert`, `NewCertSigner`) and certificate checking (`CertChecker`, `FixedHostKey`) | pkg.go.dev; ran a handshake test with a CA-signed host certificate | Confirmed |
| M2 | `golang.org/x/crypto/ssh/knownhosts` supports `@cert-authority` and `@revoked` lines | knownhosts.go source at v0.58.0 (`markerCert`, `markerRevoked`) | Confirmed. Pins and a host CA come from one standard file (D6) |
| M3 | `ssh.Certificate` has `KeyId`, `ValidPrincipals`, `ValidAfter`, `ValidBefore` and `Permissions` (critical options and extensions) | `go doc golang.org/x/crypto/ssh.Certificate`, v0.58.0 | Confirmed |
| M4 | OpenSSH sshd (`TrustedUserCAKeys`, `AuthorizedPrincipalsFile`) logs the certificate key ID at INFO: `Accepted publickey for alice … ED25519-CERT SHA256:… ID <keyid> (serial N) CA ED25519 SHA256:…` | ran OpenSSH 10.3p1 in an Alpine container | Confirmed. `KeyId = nyyrikki:<grant>:<session>` links target logs to Nyyrikki's audit log |
| M5 | sshd only allows `direct-tcpip` for a certificate login if the certificate carries the `permit-port-forwarding` extension, and only allocates a PTY with `permit-pty` | sshd(8) "AUTHORIZED_KEYS FILE FORMAT" / ssh-keygen(1) "CERTIFICATES" | **Not yet measured** against a live sshd. SH3 measures it. D8 depends on it |

## 3. Owner decisions

None open.

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **A terminating proxy.** A's SSH session ends at G, and G opens a separate SSH connection to the target. | G sees the decrypted channels, so it can apply policy per channel, record, and tear down. |
| D2 | **A authenticates with the grant's own ed25519 key**, and nothing else. The key must belong to an active grant of a client whose `source_cidrs` allow the address. `source_cidrs` is required for every client that may request an SSH profile, and each entry must be a single address (docs/02 §5.15.6). | INV-06, INV-09. The key stops working when the grant ends. There is no mTLS on this listener, so unlike the HTTP token, the key works on its own: the address is what binds it to A. |
| D3 | **The username encodes the target**: `<login>+<target>`, for example `root+node-1`. | One config entry serves every target and login in scope. |
| D4 | **The upstream dial is lazy.** G dials the target only when the first channel that needs it has passed policy, and its hold if any. | A denied or unapproved operation never touches the target. |
| D5 | **Upstream login uses an ephemeral certificate per session** from G's SSH user CA: principal = the login, valid from now−60 s to now+3 min, `KeyId nyyrikki:<grant>:<session>`, over a key pair generated in memory for that session. | INV-13. A target never holds a reusable Nyyrikki credential. M4. |
| D6 | **Target host keys are verified** through one OpenSSH `known_hosts` file. It holds pins and/or `@cert-authority` lines, and `@revoked` is honoured. There is never TOFU. A mismatch aborts and audits `ssh.hostkey_mismatch`. | INV-12. M2. |
| D7 | **Channels are allowlisted** (§5.5). `session` (shell, exec, sftp), `direct-tcpip` when policy allows it, and `pty-req`, `window-change`, `signal` and allowlisted `env` within an allowed session. Everything else is rejected. | Agent forwarding, X11 and `tcpip-forward` would open holes around the proxy. |
| D8 | **Certificate extensions** are `permit-pty` always, and `permit-port-forwarding` only if the profile has a `direct-tcpip:` rule that is not `deny`. Nothing else: no agent forwarding, no X11, no `permit-user-rc`. | The certificate is no stronger than the profile. M5 is to be measured. |
| D9 | **`env` allowlist**: only `LANG` and `LC_*` are forwarded. | Blocks `LD_PRELOAD`-style injection through `env` requests. |
| D10 | **Shell, exec and subsystem are always mutating.** In step mode, each is held with the exact command or subsystem shown. | A shell can't be split into reads and writes, so the whole channel is the unit of approval. |
| D11 | **Recording** (docs/03 §5.4): asciicast v2 for channels with a PTY, JSONL for exec without one, and metadata for SFTP (a passive SFTP v3 packet parser, written by us) and for direct-tcpip. | Evidence of what was done. A passive parser can't alter the stream. |
| D12 | **Teardown writes one notice** to the channel's stderr (`[nyyrikki] session ended: <reason>`), then closes both connections within 2 s. | INV-07. The agent sees why its session ended. |
| D13 | **G's proxy host key is a stable ed25519 key**, generated by `init-pki`, and pinned on A under the alias `nyyrikki`. | A can verify G without colliding with real host names. |
| D14 | **One upstream connection per A connection and target.** Later channels reuse it, as long as each passes policy. A new A connection means a new certificate. | Fewer dials and certificates, without stretching any certificate's life. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| A non-terminating jump host (`ProxyJump`), with A authenticating end to end | G can't see channels, record or hold anything, and A would need a credential the target accepts. |
| Long-lived keys on targets, held by G | A reusable credential on every target. Ephemeral certificates cost nothing at login time (D5). |
| Trust on first use for target host keys | INV-12. |
| Allowing agent forwarding "for git" | It lets the target use A's keys, and it bypasses the proxy. |
| `github.com/pkg/sftp` to parse SFTP | We only need to observe request types and paths passively. A small parser of our own avoids a dependency, and is fuzzed (docs/01 §5.9). |

## 5. Design

### 5.1 Connection model

```
A ──ssh (per-grant key)──▶ G:2222 ──ssh (ephemeral cert from the SSH user CA)──▶ target:22
        server side (G)                        client side (G)
```

`ssh.ServerConfig`:

- `PublicKeyCallback` looks up the key in the active-grant index (docs/02
  §5.17). If it isn't found, the grant isn't active, or the client's
  `source_cidrs` don't allow the address, the login fails (INV-06).
- No password or keyboard-interactive callbacks.
- Banner: none.
- Max auth tries: 3.

### 5.2 Username → target and login

The username is `<login>+<target>`, split at the last `+`:

- `<target>` must be in the grant's `ssh.targets`;
- `<login>` must be in both the profile's `ssh.logins` and the target's
  `logins`.

Otherwise the login fails, and the SSH failure message names the reason
(`out_of_scope: node-9`). An unparseable username fails the same way.

### 5.3 Lazy dial and host verification

On the first channel that needs the target (`session` or
`direct-tcpip`):

1. `gate.Authorize` runs on the channel's operation (§5.5). A deny
   rejects the channel. A hold waits for the tap (docs/04 §5.5) before
   anything else happens.
2. Mint the certificate (§5.9).
3. Dial `<host>:<port>` with `HostKeyCallback` set to
   `knownhosts.New(pki.ssh_known_hosts_file)` (D6). A mismatch or an
   unknown key aborts the channel with `ssh.hostkey_mismatch` (audited)
   and alerts.
4. Authenticate with the certificate.
5. Open the matching channel upstream, replay the queued requests
   (below), and splice the two channels through the recorder.

**Requests before the dial are queued.** An OpenSSH client sends
`pty-req` and `env` on the session channel *before* `shell`, `exec` or
`subsystem`, so they arrive while there is no upstream yet. G:

- checks each one against §5.5, drops what §5.5 drops, and answers
  `want_reply` locally;
- queues the rest in arrival order, keeping only the latest
  `window-change`, at most 16 requests and 16 KiB, after which the
  channel is closed;
- replays the queue upstream in order after step 4, then sends the
  `shell`, `exec` or `subsystem` request itself.

If the target refuses a replayed request it had been told succeeded
(`pty-req` on a target with `PermitTTY no`), G writes the reason to the
channel's stderr and closes it. A queued request is never replayed for a
channel that policy denied.

### 5.4 G's host key toward A

G presents its proxy host key (D13). On A, `known_hosts` contains
`nyyrikki ssh-ed25519 AAAA…`, and the config sets `HostKeyAlias
nyyrikki` with `StrictHostKeyChecking yes`.

### 5.5 Channels and policy

| Channel / request | Operation | Handling |
|---|---|---|
| `session` → `shell` | `SSHType=shell` | policy; mutating, so held in step mode |
| `session` → `exec` | `SSHType=exec`, `Command=<bytes as string>` | policy; mutating, so held |
| `session` → `subsystem` | `SSHType=subsystem`, `Subsystem=<name>` | policy; `sftp` is metadata-recorded |
| `pty-req`, `window-change` | — | allowed inside an allowed session; recorded as size and resize |
| `env` | — | `LANG` and `LC_*` are forwarded; others are dropped silently (D9) |
| `signal` | — | forwarded |
| `direct-tcpip` | `SSHType=direct-tcpip`, `Host`, `Port` | policy (`direct-tcpip:` rules), default deny; a session of its own |
| `auth-agent-req@openssh.com`, `x11-req`, `tcpip-forward`, `streamlocal-forward@openssh.com`, `direct-streamlocal@openssh.com`, anything else | — | **rejected** |

**Step mode** shows the exact command, with non-printing bytes
hex-escaped (docs/04 §5.7). Commands are never offered as allowances
(docs/04 §5.5).

### 5.6 Recording

Recordings go to `recordings/<grant>/<session>.*` (docs/03 §5.4):

- **A PTY channel** (shell or exec): asciicast v2.
  - Upstream stdout and stderr become `o` events.
  - A's stdin becomes `i` events.
  - `pty-req` and `window-change` become `r` events.
  - The header's `nyyrikki` object carries the target, login and key ID.
- **Exec without a PTY**: JSONL with `in`, `out` and `err` chunks, plus
  `exit` with the exit status.
- **SFTP**: the passive SFTP v3 parser reads the client→server packet
  stream. It decodes the length, the type, the request ID, and the path
  or handle fields of `OPEN`, `CLOSE`, `READ`, `WRITE` (offset and
  length only), `REMOVE`, `RENAME`, `MKDIR`, `RMDIR`, `SETSTAT` and
  `SYMLINK`. It logs `{t_ms, op, path, bytes}` to `.meta.json`. A parse
  error stops metadata parsing for that channel, and is recorded. It
  does not interrupt the transfer, because the parser is passive.
- **direct-tcpip**: `.meta.json` with the endpoints, bytes and duration.

A recording failure follows docs/03 D8: the session is refused, or
closed.

### 5.7 Teardown

On revoke, expiry or release (docs/02 §5.17):

1. Write `\r\n[nyyrikki] session ended: <reason>\r\n` to every open
   session channel's stderr. This is the only byte G ever injects
   (D12).
2. Close all channels, and both connections. The bound is 2 s
   (INV-07).
3. The target sees the connection drop. The certificate is near expiry
   anyway, and its private key was never written down.

### 5.8 direct-tcpip

A profile rule such as `direct-tcpip: 10.0.1.*:5432 → confirm` lets
`ssh -L 5432:10.0.1.5:5432 … root+node-1@nyyrikki` tunnel through the
target. Each tunnel is a session: metadata-recorded and torn down like
any other. The certificate gets `permit-port-forwarding` only when such a
rule exists (D8). Remote forwarding (`-R`) is always rejected.

### 5.9 SSH user CA and ephemeral certificates

The CA is an ed25519 key at `pki.ssh_user_ca.key_file`, generated by
`init-pki` (docs/09). Its public key is installed on targets (§5.11).

Per upstream connection, G generates an ed25519 key pair in memory and
signs:

```
Certificate{
  CertType:        UserCert,
  KeyId:           "nyyrikki:<grant_id>:<session_id>",
  ValidPrincipals: [<login>],
  ValidAfter:      now − 60 s,
  ValidBefore:     now + pki.ssh_user_ca.cert_ttl   (≤ 3m, INV-13),
  Serial:          a random uint64,
  Permissions.Extensions: {"permit-pty": ""} (+ "permit-port-forwarding": "" per D8),
}
```

The private key lives only for the connection. `ss_` rows record the
serial, so `Accepted publickey … ID nyyrikki:gr_…:ss_… (serial N)` in a
target's log (M4) maps back to the audit log.

### 5.10 SSH artifacts for A

`nyyrikki-mcp` writes these into `grants/<id>/ssh/` (docs/05 §5.4):

- `id_ed25519` and `id_ed25519.pub`: the per-grant key, generated at
  request time.
- `known_hosts`: `nyyrikki ssh-ed25519 AAAA…`, G's proxy host key from
  the credentials.
- `config`:

  ```
  Host nyyrikki
      HostName nyyrikki.internal
      Port 2222
      IdentityFile /…/grants/<id>/ssh/id_ed25519
      IdentitiesOnly yes
      UserKnownHostsFile /…/grants/<id>/ssh/known_hosts
      HostKeyAlias nyyrikki
      StrictHostKeyChecking yes
      ForwardAgent no
      ForwardX11 no
  ```

Usage:

```
ssh  -F <cfg> root+node-1@nyyrikki                     # shell
ssh  -F <cfg> root+node-1@nyyrikki 'apt-get -y upgrade' # exec
scp  -F <cfg> file root+node-1@nyyrikki:/tmp/           # sftp subsystem (scp ≥ 9 uses SFTP)
sftp -F <cfg> root+node-1@nyyrikki
```

### 5.11 Target setup (sshd)

- `TrustedUserCAKeys /etc/ssh/nyyrikki_user_ca.pub`.
- Map principals to logins:
  `AuthorizedPrincipalsFile /etc/ssh/principals/%u` (for example,
  `/etc/ssh/principals/root` containing `root`), or rely on principal =
  username.
- Accept admin logins only from G: firewall `:22` to G's address, or
  `Match Address`.
- Remove any standing admin keys A used to have.
- Put each target's host key into G's `known_hosts` with
  `ssh-keyscan`, **verified out of band**, or sign host keys with a host
  CA and add an `@cert-authority` line (D6).

### 5.12 Configuration

```yaml
server:
  ssh_listener: { addr: ":2222", host_key_file: "/etc/nyyrikki/pki/ssh-proxy-host.ed25519" }
pki:
  ssh_user_ca: { key_file: "/etc/nyyrikki/pki/ssh-user-ca.ed25519", cert_ttl: 3m }
  ssh_known_hosts_file: "/etc/nyyrikki/pki/ssh_known_hosts"
ssh_targets:
  - name: node-1
    host: 10.0.1.11
    port: 22
    logins: [root, maint]
```

Profile section (docs/02 §5.15.5): `ssh: { targets: [...], logins:
[...], rules: [...] }`.

Validation:

- `cert_ttl` ≤ 3m.
- `ssh_known_hosts_file` exists and has an entry for every target's
  host, or an `@cert-authority` line covering it.
- Target names match `^[a-z0-9][a-z0-9-]{1,61}$`.
- A profile's `ssh.logins` ⊆ each referenced target's `logins`.
- Key files are `0600`.

| Key | Consumed by (production call site) |
|---|---|
| `server.ssh_listener.addr`, `.host_key_file` | `proxy/ssh.Listen` |
| `pki.ssh_user_ca.key_file`, `.cert_ttl` | `proxy/ssh.newMinter` |
| `pki.ssh_known_hosts_file` | `proxy/ssh.dialTarget` (`knownhosts.New`) |
| `ssh_targets[]` | `proxy/ssh.resolveTarget` |

## 6. Security considerations

- **New inputs**: the SSH connection from A, which is untrusted.
  - The username is parsed in §5.2.
  - Channel and request types are allowlisted in §5.5.
  - `env` is allowlisted.
  - Command bytes are shown escaped, and matched as guardrails only.
  - SFTP packets are parsed passively, with fuzzing.
- **New outbound boundary**: G ↔ sshd, with the host key verified (D6)
  and an ephemeral, minimal certificate (D5, D8).
- **Dependency failures**:
  - target unreachable or host key mismatch → the channel is rejected;
  - CA key unreadable → G refuses to start;
  - audit or recording down → refused (docs/03 §5.6).

  None of them allows an operation.
- **What reaches the audit log and Telegram**: the target, login,
  channel type and command. Never key material.
- **New ways to reach a target**: only through `:2222` and
  `gate.Authorize`, per channel. The bypass hunt covers:
  - each channel and request type in §5.5;
  - reusing an upstream connection for a new channel (each one passes
    policy, D14);
  - `direct-tcpip` (policy-gated);
  - `-R` and streamlocal (rejected).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. Only the active grant's own key, from an allowed address, logs in. A released, expired or revoked grant's key fails. Another grant's key can't reach this grant's targets (INV-06) | integration tests with an in-process SSH server |
| G2. A login or target outside scope, or a malformed username, fails with the reason | table test |
| G3. A denied or still-held channel never causes a dial to the target (D4) | test with a target that counts accepted connections |
| G4. The certificate presented to sshd is valid for at most 3 min, has principal = login and key ID `nyyrikki:<grant>:<session>`, and carries only the D8 extensions. It can't log in after it expires (INV-13) | e2e: capture the certificate at a test sshd, and try it again after expiry |
| G5. A changed or unknown target host key aborts with `ssh.hostkey_mismatch`. A `@revoked` key is refused (INV-12) | e2e |
| G6. Agent forwarding, X11, `-R`, streamlocal and unknown channel types are rejected. `direct-tcpip` follows policy | integration tests, one per type |
| G7. Only `LANG` and `LC_*` env requests reach the target. `pty-req` and `env` sent before `shell` or `exec` reach the target in order, before it | test sshd that records the environment and the request order |
| G8. A PTY shell produces a playable `.cast`, exec without a PTY produces `.jsonl`, and `sftp` and `scp` produce `.meta.json` with the operations and paths | e2e with OpenSSH clients |
| G9. Revoke during an interactive shell, an exec and a direct-tcpip tunnel prints the notice and closes everything within 2 s (INV-07) | e2e with timing |
| G10. No CA key, certificate private key or target credential ever reaches A (INV-04) | canary scan over the bytes sent to A |
| G11. M5 is measured, and D8 is confirmed or revised | SH3, recorded in §2 |
| G12. Every §5.12 key changes behaviour at its call site | one test per key |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **SH1** | Server side: listener, key authentication through the grant index, username parsing, channel allowlist | G1, G2, G6 |
| **SH2** | Lazy dial: gate integration, knownhosts verification, splicing | G3, G5 |
| **SH3** | SSH user CA and minting; target setup verified in e2e; the M5 measurement | G4, G11 |
| **SH4** | Recording: asciicast, JSONL, the SFTP parser (with fuzzing), direct-tcpip metadata; the env allowlist | G7, G8 |
| **SH5** | Teardown, artifacts for docs/05 AG3, knob tests, canary scan | G9, G10, G12 |

Ordering notes: SH1 needs docs/02 GC4 (the key index). SH2 needs GC7.
SH4 needs docs/03 AU3.

## 9. Risks and open questions

- **RR-4 (SECURITY.md)**: a shell is a shell. Narrow target accounts
  and `exec:` rules are the real limits.
- **M5 is unmeasured.** If OpenSSH turns out not to need
  `permit-port-forwarding` for `direct-tcpip`, D8 still doesn't widen
  anything. If it needs other extensions for SFTP, SH3 records it.
- **Large SFTP transfers through a passive parser**: the parser reads
  only headers and skips data by length, so its cost doesn't grow with
  file size. A load test in SH4 confirms it.

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
