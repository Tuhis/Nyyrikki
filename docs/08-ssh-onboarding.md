# R12 — SSH onboarding and upkeep, made simple (docs/08)

**Status**: drafted 2026-10-31. Owner decisions OD1–OD9 taken the same
day, in the conversation that asked for this doc. Waiting for approval,
which is the merge of the PR that adds it. Status lives in
[`ROADMAP.md`](../ROADMAP.md).

Chunks **SE1–SE6** (`SE` = SSH ease; unused).

*Revised 2026-10-31 (OD9, the same day)*: the chart makes the CA keys in the
cluster with a one-off hook Job (D16); `nyyrikkid ssh-ca` on the
administrator's machine stays as the alternative.

**Relationship to earlier work**: builds on [docs/07](07-ssh-target.md)
(R10) without changing its model. Requests, approvals, the per-run user
certificate, the `ny-<human>` accounts, sudo and session kill stay as
docs/07 decided. What changes is how a host is brought on board and kept
up to date, and how the CA keys are made and rotated. It takes over part
of `ROADMAP.md` R11 (hosts pull their trust material), signed in the pod
rather than by a key kept off it (OD3), so R11's external signer stays
open. When this doc is approved, the rows it revises get dated notes:
docs/07 D4, D6, D8, D12, D14, D16, §5.5, §5.6, §5.7, and the rejected
alternative "a register this host endpoint". docs/02 D13 gets a note for
group names in `elevate` (D11 here). docs/01 D4 and D10 get notes for the
new paths on `:8443` (D4, D7): `GET /hosts/<target>/trust`, and
`POST /hosts/<target>/enroll` and `/enroll/check`, the first `POST`
paths and the first that start an approval without a token from the
authorization server.

---

## 1. Purpose

Setting up a host for docs/07 today takes these steps, and each of them
is a chance to stop or get something wrong:

1. **Make the user CA**: `ssh-keygen` in a temporary directory,
   `kubectl create secret`, then paste the public key into the values.
   The same fact lives in two places, and they have to agree.
2. **Find `ssh.source_addresses`.** If it is wrong, every login is
   refused with no message that says why.
3. **Two rollouts per host.** Add the target with empty `host_keys`,
   roll out, run the script on the host, copy the `host_keys` and
   `session_kill` it prints back into the values, roll out again.
4. **Facts copied by hand.** `session_kill` is something the host does,
   but it is set in the values. When it drifts, the approver is told
   less than is true.
5. **Visit every host again** whenever a human is removed or a CA key is
   added or revoked. A CA rotation is three rollouts and two visits to
   every host. After a leak, that slowness is what hurts.
6. **No groups.** An elevation over ten web hosts names ten targets.

When this ships, a host is brought on board with one command that the
administrator pastes on the host, and one tap on Telegram. A target in
the values needs only its name and address. CA keys are made by the
chart on install, rotated without a rollout, and reach every host that has cron
on their own within 15 minutes. Anyone who keeps everything in Git can
still do it all declaratively, and the manual steps stay documented.

### Non-goals

- **Keeping targets or host facts anywhere but the Helm values** (OD1).
  Nyyrikki stores no registry. Enrollment issues a certificate and
  remembers nothing about the host.
- **systemd timers, or any daemon on the host** (OD2). Not every host
  runs systemd. A host without cron is updated by re-running the setup
  command, as today.
- **Nyyrikki pushing configuration to hosts.** Hosts pull, and they
  apply only what this doc lists (D5). Nyyrikki still runs nothing on a
  host without an approval (docs/07 D14).
- **The pull creating accounts or granting sudo.** Anything that adds
  access on the host still needs an administrator to re-run the setup
  (D5).
- **Running one command across a group of hosts.** Groups name the
  targets of an elevation, nothing more (D11).
- **A maintained Ansible role** (OD8). The docs show cloud-init and
  Ansible snippets that run the same tested setup command.
- **Enrolling hosts without an ed25519 host key** (D8).
- **Telegram bot commands** for administration (§4, rejected
  alternatives).

## 2. Measured and verified before writing

Measured on 2026-10-31 with a Go probe using `golang.org/x/crypto/ssh`
v0.58.0 on Go 1.26.8, against containers of the stated images. SE3, SE4
and SE6 turn these into tests.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | A signature in OpenSSH's `SSHSIG` format, produced in Go (magic `SSHSIG`, namespace, empty reserved field, `sha512`, signed with `ssh.Signer` from an ed25519 key, armored at 70 columns), is accepted by `ssh-keygen -Y verify -f <allowed_signers> -I <identity> -n <namespace> -s <sig>`. The same signature is refused for another namespace ("namespace does not match") and for a changed message ("incorrect signature") | the probe signed a data-line file with namespace `nyyrikki-trust@v1`; verified on Debian 13 (OpenSSH 10.0p2), Ubuntu 24.04 (9.6p1), Rocky 9 (9.9p1), Alpine 3.22 (10.0p2), and locally with 10.5p1 | Confirmed. D4, D5 |
| M2 | sshd accepts a host certificate that `x/crypto/ssh` signed for the host's own ed25519 key, carrying the custom extension `session-kill@nyyrikki`, configured as `HostCertificate` in a drop-in under `/etc/ssh/sshd_config.d/`: `sshd -t` passes and `sshd -T` shows it. A Go client offering only `ssh-ed25519-cert-v01@openssh.com` receives the certificate with the extension intact; `ssh.CertChecker` accepts it for the principal it names and refuses another ("principal … not in the set of valid principals") | Debian 13 (10.0p2), Rocky 9 (9.9p1), Alpine 3.22 (10.0p2) | Confirmed. D7, D8, D10 |
| M3 | **Cron, by implementation.** Debian's `cron` runs `/etc/cron.d/nyyrikki` but ignores `/etc/cron.d/nyyrikki.conf` (a dot in the name). Rocky 9's cronie runs both. BusyBox `crond` (Alpine 3.22) ignores `/etc/cron.d` entirely; Alpine's stock root crontab runs `run-parts /etc/periodic/15min` every 15 minutes, and BusyBox `run-parts` runs an executable `/etc/periodic/15min/nyyrikki-pull` | each daemon started with an every-minute entry, files checked after 75 s; Alpine's crontab read and `run-parts` run by hand | Confirmed. D5 |
| M4 | sshd reads `TrustedUserCAKeys`, `RevokedKeys` and the `AuthorizedPrincipalsFile` at each authentication. Replacing the CA file, extending the KRL with `ssh-keygen -k -u`, or changing a principals file takes effect on the next login **without reloading sshd** | Debian 13 (10.0p2): logins with certificates of two CAs before and after each change, sshd never reloaded | Confirmed. D5: the pull never reloads sshd |
| M5 | OpenSSH 10's `PerSourcePenalties`, on by default, drops new connections from an address for a while after it fails authentication ("drop connection … penalty: failed authentication"). A failed login from Nyyrikki's address makes its next connections to that host fail too, until the penalty runs out | observed while measuring M4, Debian 13 (10.0p2) | Confirmed. D7: the probe tries once per account and stops at the first refusal |
| M6 | BusyBox `wget` has no option to name a CA file (only `--no-check-certificate`) | `wget --help`, BusyBox 1.36.1 | Confirmed. D5: the pull requires `curl` |
| M7 | A `pre-install` hook Job that creates a Secret the chart also templates breaks the first install: `INSTALLATION FAILED: secrets "ca" already exists`. Helm checks for existing objects before the hooks run, then creates its own. Once the Secret exists with `meta.helm.sh/release-name` and `-namespace` annotations and `app.kubernetes.io/managed-by: Helm`, later upgrades and reinstalls adopt it | a probe chart on kind (Kubernetes 1.35.0), Helm 3.20.2, 2026-10-31 | Confirmed. D16: the chart doesn't template the Secret |
| M8 | The other way round, with the chart templating the Secret without `data` and a `post-install,post-upgrade` Job patching keys in (RBAC `get` and `patch` on that one name): the key survives two upgrades, and an uninstall plus reinstall with `helm.sh/resource-policy: keep`. **`helm upgrade --force` replaces the Secret, and the Job then made a new key**: a silent CA change | same probe | Confirmed. D16: rejected, see §4 |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | May enrolled hosts, their keys or facts live in Nyyrikki's own storage instead of the Helm values? | **No. All configuration stays in the Helm values; Nyyrikki stores no registry** (owner, 2026-10-31). The owner may revisit this later. Enrollment therefore issues a host certificate, so the values never need the host's keys (OD4). |
| OD2 | How do hosts pick up CA rotations, revocations and removed humans? | **cron, where present** (owner, 2026-10-31). No systemd timer: "not every SSH target has systemd". The setup installs a cron entry where it finds a cron that reads it (M3), and reports that it didn't otherwise. Weighed against re-applying the setup through an approved `run` on a group, and against dropping the pull. |
| OD3 | Who signs the trust bundle the hosts pull? | **The pod, with the current user CA key** (owner, 2026-10-31). Weighed against a separate trust-root key kept off the pod, which would stop a leaked CA key, or a compromised pod, from adding a CA of its own to every host before the leak is revoked. Accepted: that same holder can already log in as every `ny-*` account from Nyyrikki's source addresses (§6). *Precised 2026-10-31 (round 1 of #40)*: what is accepted is that such a holder can add a CA and signer of their own to every host that pulls (D5's stage/promote rule limits each bundle, not the holder), and that recovering from a leak of `user-ca`, or of a staged `user-ca-next` (also a signer), needs the setup re-run on every host (§5.4). |
| OD4 | Without storage, how does enrollment avoid the second rollout? | **Nyyrikki signs a long-lived host certificate** with a host CA kept in a Secret, after the approver compares the host key's fingerprint on Telegram (owner, 2026-10-31). A target then needs only its address. A host is no longer trusted once its key is listed in `ssh.revoked_host_keys` in the values. Short-lived certificates with automatic renewal were rejected, because renewal would need a timer on the host (OD2). |
| OD5 | Which of the proposals made on 2026-10-31 are in scope? | **All of them, except storage outside the values** (owner, 2026-10-31): CA public keys derived from the private keys, a CA helper command, a staged next CA key, enrollment, the pull, defaults, groups, global host CAs, config-management snippets, `nyyrikki ssh`, and more in `list_targets`. |
| OD6 | Should Nyyrikki contact the host before asking the approver, to read the facts its certificate carries and to fail early on a wrong or unreachable host? | **Yes: a handshake-only host check before every SSH approval and elevation message** (owner, 2026-10-31). It verifies the host key or certificate and disconnects without authenticating. Weighed against keeping `session_kill` as a value copied by hand. |
| OD7 | How does this land? | **Design doc first, as its own PR. Code follows in chunk PRs once the doc is merged** (owner, 2026-10-31). |
| OD8 | Config-management support on the host side? | **Documented cloud-init and Ansible snippets**, not a maintained role (owner, 2026-10-31). |
| OD9 | Must the CA keys still be made outside the cluster? | **No: a one-off `pre-install,pre-upgrade` hook Job makes them in the cluster. The Secret it creates is not part of the Helm release; labels identify it** (owner, 2026-10-31, after M7 and M8). Weighed against the chart templating the Secret and a post-install Job filling it in, which Helm would track, but which `--force` turns into a silent CA change (M8). Helm can't track a Secret a pre-install hook creates (M7). |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **CA keys come from one Secret, mounted whole** at `/etc/nyyrikki/ssh/`, with up to three keys: `user-ca` (required as soon as one SSH target exists), `user-ca-next` (optional, a staged rotation), `host-ca` (optional; it turns on enrollment). Each is an ed25519 OpenSSH private key, read on each use as docs/07 D6 reads `user-ca` today. Their **public keys are derived from them on each use**. Hosts trust `pub(user-ca)`, then `pub(user-ca-next)`, then any keys still listed in `ssh.user_ca_public_keys`, minus any key in `ssh.revoked_user_ca_keys` (D3). `user_ca_public_keys` becomes optional: it holds only extra keys. An optional file that doesn't exist means that feature is absent. A file that exists but can't be read or parsed, or isn't ed25519, makes every SSH run and every `/hosts/` endpoint `unavailable` until it is fixed. | One fact in one place: the public half can't disagree with the private one. A missing optional key only means less is trusted. A broken one could be a half-written rotation, so nothing is served. Because the files are read on each use and the kubelet updates a mounted Secret on its own, a rotation needs no Helm rollout. |
| D2 | **`nyyrikkid ssh-ca`**, also a helper for the administrator's machine, for anyone who doesn't let the chart make the keys (D16). It reads and writes a Secret manifest on stdin and stdout, and holds no Kubernetes client: `init` prints a new Secret with fresh `user-ca` and `host-ca`; `import` reads an R10 Secret and prints a new one with its key as `user-ca` and a fresh `host-ca` (D14); `add-host-ca` adds a fresh `host-ca` to a Secret that lacks one and refuses otherwise; `unstage` removes `user-ca-next`. `init` and `import` label their Secret as D16 does. `stage`, `promote`, `unstage` and `add-host-ca` refuse a Secret without `nyyrikki.dev/component: ssh-ca`, or with data keys outside `{user-ca, user-ca-next, host-ca}`, so an R10 Secret in compatibility mode (D14) is never rotated in place, where the pod wouldn't see `user-ca-next` or would switch to a key no host trusts. `import` takes `--key` for R10's configurable key name and prints the imported key's fingerprint; *Revised 2026-10-31 (round 3 of #40)*: `import` was first said to refuse an existing target, which a tool without a Kubernetes client can't do, and the documented `\| kubectl apply` would have overwritten a live CA; `stage` reads the current Secret and adds a fresh `user-ca-next` (and refuses if one exists); `promote` moves `user-ca-next` to `user-ca`, drops the old key, and prints the old public key to stderr, for `revoked_user_ca_keys` after a leak. Its output keeps only `apiVersion`, `kind`, `metadata.name`, `metadata.namespace`, `type` and `data`. `init` and `import` are used with **`kubectl create -f -`**, never `apply`, so an existing Secret makes kubectl fail with `AlreadyExists` instead of being overwritten: `docker run --rm -i <image> ssh-ca init \| kubectl create -f -`; the commands that read the current Secret first (`stage`, `promote`, `unstage`, `add-host-ca`) end in `kubectl apply -f -`. It also runs or with `go run ./cmd/nyyrikkid` from a checkout. | Replaces five shell lines, with a temporary directory to clean up, by one pipe. Private keys pass only through a pipe on the administrator's machine, never through a pod's log (docs/01 OD7) or a file. It sits in the server binary because it is an administrator's tool, not the agent's (`CLAUDE.md`, rejected: admin tools on the agent's machine). The in-cluster Job and CronJobs of D16 run the same code. |
| D3 | **`ssh.revoked_user_ca_keys`** in the values: public keys hosts must refuse. The setup writes them into the KRL, the trust bundle carries them (D4), and the pull adds them to the KRL (D5). If `user-ca` is itself listed, every SSH run is `unavailable` with detail `user_ca_revoked`, and so are `/hosts/<t>/trust` and `/hosts/<t>/setup.sh` (`503`, same detail), so hosts don't pull bundles every KRL refuses and fail with the wrong cause. | The leak procedure becomes a values change that reaches every host on its own, instead of a visit to each. |
| D4 | **The trust bundle**: `GET /hosts/<target>/trust` on `:8443`, without authentication, with docs/07 D16's rules (only `GET`; a query string is `400`; anything but an SSH target in the registry is the same `404`). The body is data lines in docs/07 D16's grammar: `TARGET`; one `CA_KEY` per trusted user CA key (D1); one `SIGNER_KEY` each for `pub(user-ca)` and, when present, `pub(user-ca-next)`, minus any key in `revoked_user_ca_keys`, so `SIGNER_KEY` is always a subset of `CA_KEY`; one `REVOKED_CA_KEY` per revoked key (D3); one `HUMAN` per human; `SUDO`; `ISSUED=<Unix milliseconds>`; `END=<count>`. Then the line `NYYRIKKI_SIGNATURE`, then an `SSHSIG` signature (M1) over every byte before that line, made with `user-ca` and namespace `nyyrikki-trust@v1`. Only `SIGNER_KEY`s may sign a bundle; extra keys in `user_ca_public_keys` are trusted for logins, never for bundles. *Revised 2026-10-31 (review of #40)*: the signers were first "the CA keys the host trusts", which let the holder of any extra key sign bundles. Each fetch is audited (`host_trust_served`: target, client address, `ISSUED`, CA key fingerprints). | Hosts can check what they fetch with nothing but `ssh-keygen`, which they already have. A namespaced `SSHSIG` can't be mistaken for a certificate signature, so `user-ca` can sign both safely (OD3). The bundle holds nothing the setup script's data lines don't already hold. |
| D5 | **The pull**, installed by the setup where it can be (OD2): the script writes `/etc/ssh/nyyrikki/pull.sh` (a fixed part of the setup body, so it is covered by the published checksum) and `/etc/ssh/nyyrikki/pull.conf` (`URL`, `TARGET`, and `CACERT` if `--cacert` was given; the CA file is copied to `/etc/ssh/nyyrikki/server-ca.pem`). It then installs a schedule: if `/etc/cron.d` exists and a `cron` or `crond` that is not BusyBox is installed, `/etc/cron.d/nyyrikki` (no dot in the name, M3; mode 0644) runs it every 15 minutes, at a minute offset taken from the target name; else, if `/etc/periodic/15min` exists and root's crontab runs it, an executable `/etc/periodic/15min/nyyrikki-pull` that calls it; else nothing, and the script reports `pull: none`. The pull needs `curl` (M6); without it, `pull: none`. **What a pull does**: fetch with `curl -fsS --max-time 30` (and `--cacert` if configured); split at `NYYRIKKI_SIGNATURE`; build an allowed-signers file from the host's own `/etc/ssh/nyyrikki/signers.pub` (written by the setup from its `SIGNER_KEY` data lines, never from the bundle being checked), minus the keys in its KRL; `ssh-keygen -Y verify` (M1); check every data line as the setup does; require `TARGET` to be this host's, and `ISSUED` to be later than the last bundle applied and no more than 10 minutes ahead of the host's clock. *Revised 2026-10-31 (review of #40)*: without the upper bound, one bundle dated far ahead (a `user-ca` holder's, or from a pod whose clock jumped) would make every later bundle look older, and freeze the pull for good. Then it applies, taking access away first: each `REVOKED_CA_KEY` is added to the KRL (`ssh-keygen -k -u`) and dropped from the trusted keys; the principals file and sudoers file of each listed account that is no longer a `HUMAN` are removed; with `SUDO=false`, every Nyyrikki sudoers file is removed. Last, `user_ca.pub` is replaced by the bundle's `CA_KEY` set, and `signers.pub` by its `SIGNER_KEY` set, which must be a subset of the `CA_KEY`s and must relate to the host's current set `old` in one of three ways, where `new` is the bundle's set and `s` the key that signed it: **no change** (`new = old`); **stage** (`new ⊋ old`, with `s ∈ old`); or **promote** (`new ⊊ old`, with `s ∈ new`; dropping a staged key that was revoked or unstaged is also a promote). Any other relation refuses the whole bundle, so no single bundle replaces the signer set. Every change to `signers.pub` is logged through `logger` with the old and new fingerprints, and `--status` prints the current signers. *Revised 2026-10-31 (round 1 of #40)*: first any subset of `CA_KEY` was accepted, so one bundle signed by a leaked `user-ca` could make the holder's key the only signer and lock the host's pull to them. Each file is written to a temporary path and renamed into place. sshd is never reloaded (M4). It **never** creates an account, writes a principals file for a new human, grants sudo, or changes `from=`. When the bundle asks for any of these, it logs "re-run the setup to add …". On any failure it changes nothing, logs through `logger -t nyyrikki` where that exists, and exits non-zero (cron mails root). It records the time and `ISSUED` of the last bundle applied in `/etc/ssh/nyyrikki/pull.state`, which `--status` prints. | Rotation, revocation and removal reach every host with cron within 15 minutes, with no visit (§5.4). Running fixed code that only reads data keeps root on the host out of the pod's reach: fetching and running the served script from cron would hand whoever controls the pod root on every host every 15 minutes, hosts without sudo included. sshd reads all three files at each login (M4), so a reload, and the chance of it failing, is never needed. |
| D6 | **Enrollment tokens**: `kubectl exec -n <ns> deploy/nyyrikki -- nyyrikkid enroll-token <target>` prints a token, and the full command to run on the host. The token is `nye1.<base64url(target ‖ expiry ‖ 16 random bytes ‖ HMAC-SHA256)>`. The HMAC key is derived from `host-ca` with HKDF-SHA256 (info `nyyrikki-enroll-token-v1`), so the server and the exec'd process agree without sharing state or a new Secret. A token lives 15 minutes and names one SSH target, which must be in the registry. The server keeps the random part of each token it has accepted, in memory until expiry, so a token starts at most one enrollment. A restart forgets this, so a token could be used again within its 15 minutes; each use still needs an approval (D7). The command refuses without `host-ca`. The token is never logged; the audit records its random part's hash. | `pods/exec` is an administrator's right, which the agents' cluster-wide read (docs/01 OD7) doesn't include, and exec output isn't kept as a container log. Without a token, anyone who can reach `:8443` could put enrollment prompts in front of the approver, which is how approval fatigue starts. |
| D7 | **Enrollment**, run by the setup script with `--enroll <token>` once the host setup has succeeded: (1) `POST /hosts/<target>/enroll` with `Authorization: Nyyrikki-Enroll <token>` and data lines `HOST_KEY=<the host's ed25519 public key>` and `SESSION_KILL=true\|false` (as step 7 of docs/07 §5.7 found), `END`. A bad or expired token, a target mismatch or a malformed body is `401`/`400` at once, with no prompt. Otherwise (2) the target's humans get an approval message on Telegram (§5.2) showing the host key's SHA256 fingerprint, `session_kill`, `sudo` from config, the address and the client address. The script prints the same fingerprint and "approve only if Telegram shows this" before it waits. The call waits up to `approval.timeout` and is settled like any approval (docs/02 D7; SQLite compare-and-set, the approval store as today; the registry is untouched). (3) On approval, the response is the host certificate (D8). The script installs it as `/etc/ssh/nyyrikki/ssh_host_ed25519_key-cert.pub`, rewrites its sshd drop-in, which then carries `HostCertificate` among the global keywords (D13), runs `sshd -t` and reloads; if that fails, it removes both and reloads. (4) `POST /hosts/<target>/enroll/check` with the same token: Nyyrikki dials the host, checks that it now presents that certificate, and authenticates once as each of the target's accounts with a run certificate (docs/07 D5) that opens no channel. It stops at the first refusal (M5) and answers per account `ok` or `refused`, with a hint that names `ssh.source_addresses` and the principals file. The token is used up after the check or at expiry. Each step is audited (`host_enroll_requested`, `_approved`, `_denied`, `host_cert_issued` with serial and fingerprint, `host_enroll_checked`). | One command on the host, one tap, no second rollout (OD4). The approver compares a fingerprint the host printed on the administrator's terminal, so nothing is trusted on first use (docs/07 D8). The check confirms on the spot what would otherwise first fail on a real run: the host key, the CA trust and the source address. |
| D8 | **The host certificate**: type host; the key is the host's ed25519 key from the enrollment; one principal, the host part of the target's `address` (what docs/07 D8 already requires a host certificate to name); key ID `nyyrikki-host:<target>`; a random 64-bit serial; valid from now − 5 min to now + `ssh.host_cert_validity` (default `43800h`, five years; at most `87600h`); extension `session-kill@nyyrikki` (empty value) only when the enrollment reported `SESSION_KILL=true` and was approved so. No other extension or critical option. Only ed25519 host keys are enrolled. A host without one can still be pinned (`host_keys`). | Long-lived, as OD4 chose, because nothing renews it. The principal ties the certificate to the address Nyyrikki dials, and the key ID to the target (D9), so a certificate for one target is never accepted for another, even at the same address. Changing a target's address means enrolling again. The extension carries the host fact that docs/07 had copied into the values by hand (M2). |
| D9 | **Host verification**, revising docs/07 D8: a host is accepted if its key equals a pin in `host_keys`, or if it presents a host certificate signed by a key in the target's `host_cas`, in the new global `ssh.host_cas`, or `pub(host-ca)`, naming the host and valid now; a certificate signed by `host-ca` must also have key ID `nyyrikki-host:<target>` for the target being dialled. A certificate whose key, or whose signing key, is listed in `ssh.revoked_host_keys` is refused (`host_key_revoked`), and so is a pin that is listed (a config error). **`session_kill` comes from the certificate** when Nyyrikki's own host CA signed it (present extension: `true`, absent: `false`). For a pinned host, or one certified by another CA, it comes from the target's config value, as before. | Enrolled hosts need no entry beyond their address. An organisation that already runs a host CA configures it once. Only a certificate Nyyrikki issued after an approval can state a Nyyrikki-specific fact. The key ID check keeps two targets that share a host name (different ports, a NAT) from accepting each other's certificates. |
| D10 | **The host check before approval** (OD6): before rendering the prompt of an SSH run, and of an elevation naming SSH targets, Nyyrikki dials each SSH host, completes key exchange, verifies the host (D9), reads its facts, and disconnects **without authenticating**, within `ssh.connect_timeout`. For a run, a failed check is `unavailable` with its detail (`host_unreachable`, `host_key_mismatch`, `host_key_revoked`, `host_not_pinned`), audited, and the approver is never asked. For an elevation, a failed check doesn't block it: the message says, per target, "not reachable now: treated as not finishing cuts" (docs/07 D12's warning). The facts shown are kept with the approval or elevation. When the run dials after approval, it verifies the host again; if it would now show less than the approver was shown (`session_kill` was true and isn't), the run is `unavailable` with detail `host_changed`. Elevation targets that failed their check are shown with the warning, so they never trigger `host_changed`. | The approver is told what the host does, from a fact it signed, without anyone copying it by hand. A wrong or unreachable host fails before anyone is asked, not after. No credential is presented and no command runs: what the host sees is a key exchange, the same as `ssh-keyscan`. |
| D11 | **Defaults and groups in config.** A target's `address` may omit the port (`22`). `ssh.defaults.sudo` (default `false`) applies to SSH targets that don't set `sudo`. A new top-level `groups` list, `[{name, targets: [...]}]`, names sets of targets of any type. Group names and target names share one namespace, and config validation refuses a name used twice or a group naming an unknown target. **`elevate` accepts group names** in `targets` and expands them on the server, before validation, into the targets they name. The elevation covers that fixed list, never the group: a later change to the group doesn't widen it (INV-03). `decision.MaxTargets` applies after expansion. Every target must be visible to the human, or the request is `invalid_request`. The elevation message lists every target, with the group's name next to its members. `run` takes target names only. **`list_targets`** returns, per target, `groups` and, for SSH targets, `sudo`. | Ten web hosts, one name. Expanding on the server, and showing what was expanded, keeps "an elevation covers exactly what the approver saw". `sudo` lets an agent pick the right host without trial and error. `session_kill` is the approver's concern and would cost a host check per listing (D10). |
| D12 | **`nyyrikki ssh TARGET [-- ARGS...]`** in the CLI: exactly `nyyrikki run -t TARGET` when given no arguments and stdin is a terminal, and `nyyrikki run TARGET -- ARGS...` otherwise. It refuses a target whose type isn't `ssh` before calling `run`. The MCP tools don't change. | Reads like the `ssh` an agent already knows. It is sugar over the same `run` call, so the CLI offers nothing MCP doesn't (`CLAUDE.md`: thin clients of one API). |
| D13 | **Setup script changes** (docs/07 §5.7): new data lines `SIGNER_KEY` (D4), `ISSUED` (as in D4), `URL` (the canonical URL; `https://` and the characters of a URL only) and `REVOKED_CA_KEY`. New options: `--reset-pull-state` (above), `--cacert FILE` (stored for the pull), `--enroll TOKEN` (D7), `--status` (prints what is installed, the pull schedule and the last pull; changes nothing). Step 2 also adds each `REVOKED_CA_KEY` to an existing KRL. Step 3 writes `signers.pub` from the `SIGNER_KEY` lines and sets `pull.state` to the setup's own `ISSUED` data line (the server's time when `setup.sh` was rendered), after the same check as D5 that it is at most 10 minutes ahead of the host's clock; otherwise step 1 refuses, naming the clock. If the stored mark is itself no more than 10 minutes ahead of the host's clock and is later than the setup's `ISSUED`, step 1 refuses too ("this setup script is older than the last bundle applied; fetch it again"), so a saved or baked-in copy can neither lower the mark nor restore an older signer set. The refusal prints the stored mark and names **`--reset-pull-state`**, which root on the host passes deliberately to set the mark to the setup's `ISSUED` regardless; the leak procedure uses it (§5.4), since a key holder can keep the mark just inside the refusal's window. *Revised 2026-10-31 (round 3 of #40)*: without the flag, the refusal could block the re-run leak recovery requires. *Revised 2026-10-31 (round 2 of #40)*: a stale body first reset the mark unconditionally. So every bundle issued before the setup the administrator just ran is refused, and a far-ahead `ISSUED` an earlier pull stored is forgotten. *Revised 2026-10-31 (round 1 of #40)*: the reset first went to the host's time minus 10 minutes, which could lower the mark and let a bundle from those minutes be replayed. Whenever `/etc/ssh/nyyrikki/ssh_host_ed25519_key-cert.pub` exists, steps 3 and 5 write `HostCertificate` for it among the drop-in's global keywords, before any `Match` block (sshd doesn't allow it inside one), so a re-run without `--enroll` keeps an enrolled host's certificate in use. *Revised 2026-10-31 (review of #40)*: a re-run first rewrote the drop-in without it. Step 3 writes the KRL with them included. A new step 8, after session kill, installs the pull (D5). Step 9 prints what it did, adding `pull: cron.d \| periodic \| none`. If `--enroll` was given, step 10 enrolls (D7). A failed enrollment doesn't roll back steps 2–9: the host is set up and fails closed without a certificate, as a host with empty pins does today. The script exits non-zero and says to run it again with a new token. `--uninstall` also removes the schedule, `pull.sh`, `pull.conf`, `pull.state`, `server-ca.pem`, the host certificate and its `HostCertificate` line. | Every rule of docs/07 §5.7 holds: refuse rather than guess, fail closed at every step, roll back what the run changed. Enrollment comes last because it waits on a person, and the host needs nothing from it to be safe. |
| D14 | **Chart**: `secrets.sshCA.name` (default `nyyrikki-ssh-ca`) is mounted whole at `/etc/nyyrikki/ssh/`, and the config points at `user-ca`, `user-ca-next` and `host-ca` there. For one minor release, the old `secrets.sshUserCA.{name,key}`, when set, is mounted as `user-ca` **instead** (one Secret on the directory, never two), `ssh.generateCA` defaults to `false` while it is set, and `NOTES.txt` says to migrate. **Migration from R10**, in this order, which `NOTES.txt` repeats: (1) `kubectl get secret nyyrikki-ssh-user-ca -o yaml | <ssh-ca> import | kubectl create -f -` writes `secrets.sshCA.name` with the old key as `user-ca` and a fresh `host-ca`; (2) remove that key from `ssh.userCAPublicKeys` and unset `secrets.sshUserCA`, in one rollout; (3) after it, delete `nyyrikki-ssh-user-ca`. If step 1's `create` fails with `AlreadyExists`, compare fingerprints (`import` prints the old key's; the docs show how to read the existing `user-ca`'s): equal means the migration is already done; different means `sshUserCA` was unset first and the hook made a fresh CA no host trusts, so delete that Secret and run step 1 again. `NOTES.txt` gives the same steps. The CA loader logs and audits a warning when an extra key in `user_ca_public_keys` equals a derived one, since it would stay trusted after a promote. *Revised 2026-10-31 (round 2 of #40)*: the migration was first one step, leaving the old key trusted as an extra and its private half in the old Secret. Without migrating, enrollment stays off (no `host-ca`), rotation is refused (D2), and nothing else changes. *Revised 2026-10-31 (round 1 of #40)*: first `generateCA` defaulted to on for an upgrading R10 release, which would have made a CA no host trusts and switched to it when the compatibility ended. New values map one to one onto D1, D3, D8, D9 and D11's config: `ssh.revokedUserCAKeys`, `ssh.hostCAs`, `ssh.revokedHostKeys`, `ssh.hostCertValidity`, `ssh.defaults.sudo`, `groups`, and `ssh.generateCA` and `ssh.caJobs` for D16. `NOTES.txt` prints, per SSH target, the `enroll-token` command and the setup command, unconditionally, since the chart can't see whether `host-ca` exists (D16). | Rotation edits the Secret, not the values (D1). The chart test checks that every value reaches the binary (docs/06). |
| D15 | **Setup docs** (`docs/setup/ssh-hosts.md`) are rewritten around three paths, quickest first: *enroll* (`ssh-ca init`, a target with an address, `enroll-token`, one command on the host, one tap); *declarative* (pins or an organisation's host CA in the values, the setup command from cloud-init or Ansible, with snippets, OD8); *manual* (the file listing, kept checked by docs/07 G9). | The simplest path comes first. The others stay complete. |
| D16 | **The chart makes the CA keys** (OD9), when `ssh.generateCA` is true, which is the default as soon as one SSH target exists. A hook Job (`helm.sh/hook: pre-install,pre-upgrade`, weight `-5`, delete policy `before-hook-creation,hook-succeeded`), running the Nyyrikki image as `nyyrikkid ssh-ca init --create`, creates the Secret `secrets.sshCA.name` with fresh `user-ca` and `host-ca` through the Kubernetes API, with labels `nyyrikki.dev/release: <release>`, `nyyrikki.dev/component: ssh-ca` and `app.kubernetes.io/managed-by: nyyrikki-ssh-ca` (deliberately not `Helm`), annotations `helm.sh/resource-policy: keep` and `argocd.argoproj.io/compare-options: IgnoreExtraneous`, and **no `app.kubernetes.io/instance`**: Argo CD's label tracking counts a live object with that label as part of the app, and auto-sync with prune would delete the Secret, then make a new CA on the next sync, whose PreSync runs the hook again. *Revised 2026-10-31 (round 1 of #40)*: the labels first included `app.kubernetes.io/instance`. If the Secret already exists, the create's `AlreadyExists` is success and nothing is changed or read: the Job never overwrites or patches a Secret, and so needs no `get`. Its ServiceAccount, Role and RoleBinding are hooks too (weight `-10`, delete policy `before-hook-creation,hook-succeeded,hook-failed`, so the grant goes away after a failed Job as well; the Job itself keeps `before-hook-creation,hook-succeeded`, so a failed Job's log stays), and the Role grants only `create` on Secrets in the namespace, which Kubernetes can't restrict to one name. The Job prints the public keys' fingerprints and never a private key. A failed Job fails the install or upgrade. `pre-upgrade` lets an existing release add its first SSH target. **Rotation and repair**: four suspended CronJobs, `<release>-ssh-ca-stage`, `-promote`, `-unstage` and `-add-host-ca`, run those commands (D2). They render when `ssh.caJobs` is true, which defaults to `ssh.generateCA`; set it true with `generateCA: false` for a Secret made by `ssh-ca` on a workstation, and leave it false for one an operator such as External Secrets owns, which they would fight. They act on the Secret in place when started with `kubectl create job --from=cronjob/…`. Their ServiceAccount's Role grants `get` and `update` on that one Secret by name. `promote` writes the old public key to its log, which is public data. The Secret is left alone by `helm uninstall`, `--force` and a broken release. The docs show how to delete it: `kubectl delete secret -l nyyrikki.dev/release=<release>,nyyrikki.dev/component=ssh-ca`. A Secret without `host-ca` (from `ssh-ca` before it existed, External Secrets, an R10 migration not done) keeps enrollment off: `enroll-token` refuses and prints the remedy (the `-add-host-ca` CronJob, or `ssh-ca add-host-ca`), and `NOTES.txt` says the same unconditionally, since the chart can't see the Secret without `lookup`. **Rendering without Helm** (`helm template | kubectl apply`, Kustomize's `helmCharts`) turns hooks into plain objects: the namespace-wide `create` grant would stay and the Job would be reapplied. That mode needs `ssh.generateCA: false`; the docs say so, and the chart can't detect it. With `ssh.generateCA: false`, the Secret comes from `ssh-ca` on a workstation, External Secrets, sealed secrets, or anything else that writes those keys. | No key is made outside the cluster, and none passes through a log, the Helm release Secret, or a terminal. A Secret Helm doesn't own can't be replaced by Helm: a CA every host trusts must never change by accident (M8). The broad `create` lasts only while the hook runs, whether it succeeds or fails, and its ServiceAccount is deleted with it. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Storing enrolled hosts, their keys or facts in SQLite | OD1. Set aside, may be revisited (`CLAUDE.md`, "Explicitly set aside"). |
| A systemd timer or a host-side daemon for the pull | OD2: not every host runs systemd. A daemon is one more thing running as root. |
| Cron fetching and running the served setup script | Whoever controls the pod would get root on every host every 15 minutes, hosts set up without sudo included. The pull is fixed code that reads only data (D5). |
| The pull creating accounts or granting sudo | A root job turning fetched data into new access would widen what a compromised pod gets beyond what it already has. Adding access stays an administrator running the setup. |
| A trust-root signing key kept off the pod | OD3. Safer against a leaked CA key, at the cost of one more key for the administrator to keep and use for every bundle. |
| Short-lived host certificates renewed by the host | OD4: renewal needs a timer. |
| The chart templating the CA Secret, with a Job filling in its keys (Helm-tracked) | M8: `helm upgrade --force`, and probably Argo CD's `Replace=true`, replace the Secret, and the Job then makes a new CA without anyone noticing. A `pre-install` Job with a templated Secret fails the first install (M7). |
| Generating the CA keys in the chart (`genPrivateKey`) | The key would sit in the Helm release Secret, and keeping it stable needs `lookup`, which GitOps tools such as Flux's `helm-controller` dry runs and Argo CD don't support. |
| Nyyrikki generating its own CA keys on first start | Its long-running pod would need the right to write Secrets. The hook Job (D16) holds that right only while it runs. |
| Minting enrollment tokens through `/mcp` or the CLI | Within the agent's reach. A steered agent could start enrollments. |
| Telegram bot commands (`/enroll db-1`) | A command parser on the approval channel is new attack surface on the one thing that must stay outside the agent's reach. `kubectl exec` reuses Kubernetes RBAC. |
| Trusting the host key the enrollment sends, without approval | Trust on first use (docs/07 D8). |
| Keeping docs/07's "no register-this-host endpoint" in full | Its two reasons were a write path into the registry and trusting the host key on first use. Enrollment writes nothing to the registry (OD1) and trusts a key only after an approver compares its fingerprint (D7). |
| `run` across a group | Not chosen. A fan-out is several requests behind one message, which needs its own design. |
| BusyBox `wget` for the pull | It can't be given a CA file (M6). Accepting any certificate would let anyone on the path serve bundles, even though the signature would still stop them. |

## 5. Design

### 5.1 Onboarding, start to finish

The CA keys are made by the chart on the first install that has an
SSH target (D16).

```yaml
# values.yaml
ssh:
  sourceAddresses: [203.0.113.10/32]
targets:
  - name: db-1
    ssh: {address: db-1.example.com}
```

```sh
# Per host, after the rollout (D6):
kubectl -n nyyrikki exec deploy/nyyrikki -- nyyrikkid enroll-token db-1
# prints:
#   curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh -s -- --enroll nye1.…
# On db-1, paste it. It sets the host up, prints the host key's fingerprint,
# and waits for the tap on Telegram, then checks Nyyrikki can log in.
```

### 5.2 The enrollment message

```
Enroll SSH host: db-1
Address: db-1.example.com:22
Host key (as the host sent it): ED25519 SHA256:pr6TBeTH6wi8tgNTw+FSiVQrgmbG3FK9XV/QnVrxPTM
Compare it with what the setup printed on the host.
root via sudo · finishes cuts (as the host reports)
Asked from 198.51.100.7, token issued 12:01
Expires 12:06:04          [Approve] [Deny]
```

It goes to every human of the target. The first valid tap settles it,
and the other copies are edited to say who settled it. Callbacks are
checked as docs/05 D4 checks any callback.

### 5.3 Configuration

```yaml
ssh:
  user_ca_key_file: /etc/nyyrikki/ssh/user-ca              # D1, required
  next_user_ca_key_file: /etc/nyyrikki/ssh/user-ca-next    # D1, optional file
  host_ca_key_file: /etc/nyyrikki/ssh/host-ca              # D1, optional file: enrollment
  user_ca_public_keys: []          # optional extra trusted keys (D1)
  revoked_user_ca_keys: []         # D3
  host_cas: []                     # global host CAs (D9)
  revoked_host_keys: []            # D9
  host_cert_validity: 43800h       # D8
  source_addresses: [203.0.113.10/32]
  connect_timeout: 10s
  defaults: {sudo: false}          # D11
groups:                            # D11
  - name: web
    targets: [web-1, web-2]
targets:
  - name: web-1
    humans: [owner]
    ssh: {address: web-1.internal}  # port 22; host verified by its certificate
```

Each knob's consumer: the three key files → the CA loader (D1), used by
the certificate minter (docs/07 D5), the bundle signer (D4), the token
command and endpoint (D6) and the host-certificate signer (D8);
`user_ca_public_keys`, `revoked_user_ca_keys` → the trusted set (D1, D3),
served by the setup endpoint and the bundle; `host_cas`,
`revoked_host_keys` → host verification (D9); `host_cert_validity` →
the host-certificate signer (D8); `defaults.sudo` → config resolution,
then everything that reads `sudo`; `groups` → `elevate` and
`list_targets` (D11).

### 5.4 Rotating the CA

**Planned**, no rollout and no visit to hosts with a pull:

1. `kubectl create job --from=cronjob/nyyrikki-ssh-ca-stage ssh-ca-stage-1`
   (D16), or, for keys kept outside the chart,
   `kubectl get secret nyyrikki-ssh-ca -o yaml | <ssh-ca> stage | kubectl apply -f -`.
   Within a minute or two the pod sees `user-ca-next`, and the bundles
   trust both keys. Hosts with a pull trust both within 15 minutes.
   `host_trust_served` in the audit shows which targets have fetched.
   Re-run the setup by hand on hosts without a pull.
2. `kubectl create job --from=cronjob/nyyrikki-ssh-ca-promote ssh-ca-promote-1`,
   or `… | <ssh-ca> promote | kubectl apply -f -`. Nyyrikki signs runs and
   bundles with the new key. The old key drops out of the bundles, and
   the pulls stop trusting it. **Promote only after every target has
   fetched a bundle issued after the stage** (`host_trust_served`), and
   re-run the setup on the rest first. A fetch is not an apply: a host
   whose pull refused the bundle still shows as fetched, so check
   `--status` on any host in doubt.

**Undoing a stage**: `kubectl create job --from=cronjob/nyyrikki-ssh-ca-unstage …`,
or `… | <ssh-ca> unstage | kubectl apply -f -`, removes `user-ca-next`.
The next bundle, signed by `user-ca`, drops it (a promote, D5). Stage
again only after every target has fetched a bundle issued after the
unstage, as before a promote.

**A host that misses steps**: one that missed step 1 can't check bundles
signed by the new key. One that missed step 2 and then the next stage
has `{A,B}` and is offered `{B,C}`, which is neither a stage nor a
promote, so it refuses. One that missed an unstage and then a new
stage has `{A,B}` and is offered `{A,C}`: refused for the same reason.
All fail loudly; re-run their setup.

**After a leak of `user-ca`, or of a staged `user-ca-next`** (a signer
on every host since the stage, so its holder can do what a `user-ca`
holder can): for `user-ca-next`, unstage it and list it in
`ssh.revoked_user_ca_keys`; for `user-ca`: stage and promote (steps 1 and 2
above, with the promote gate), then add the old public key (printed by `promote`, in its log) to
`ssh.revoked_user_ca_keys` and roll out. Hosts with a pull add it to
their KRL within 15 minutes, and that stops the leaked key. **It does
not undo what the leaked key may already have signed**: a bundle signed
with it could have added the holder's own CA and signer (stage, D5)
before the revocation, and that key is not in `revoked_user_ca_keys`.
So after either leak, **re-run the setup on every host with
`--reset-pull-state`**, which rewrites `user_ca.pub` and `signers.pub`
from the values (D13) even when a bundle the leaked key signed set the
mark just ahead of the setup's `ISSUED`. The pull
recovers from the revocation of extra keys, not from a leak of a key
that was ever a signer. `--status` and the `logger`
lines of D5 show a host whose signers changed unexpectedly. For an
immediate stop on a host, docs/07 §5.6's manual `ssh-keygen -k -u` still
works.

### 5.5 Package layout

- `internal/sshca`: loads the three key files, derives the trusted set,
  signs `SSHSIG` (D4), signs host certificates (D8), derives the token
  key (D6). The run certificate minter of docs/07 D5 moves onto it.
- `internal/hostsetup`: gains the `trust`, `enroll` and `enroll/check`
  handlers next to `setup.sh`.
- `internal/sshtarget`: host verification (D9), the host check (D10),
  the probe (D7).
- `cmd/nyyrikkid`: subcommands `ssh-ca` and `enroll-token`. With no
  subcommand, it runs the server as today.

## 6. Security considerations

- **New inputs.** `GET /hosts/<t>/trust`: only the target name, checked
  against the registry. `POST /hosts/<t>/enroll` and `/enroll/check`:
  the token (HMAC checked in constant time, expiry, target, single use)
  before anything else is read; then a body of at most 4 KiB of data
  lines, each checked (one ed25519 key, a boolean). Bad input is refused
  without contacting Telegram. Values the pull reads come from a signed
  bundle, and are checked line by line as the setup's data lines are.
- **Dependency failures.** A broken key file stops SSH runs and the
  `/hosts/` endpoints (D1). Telegram unreachable or no answer means the
  enrollment is denied (INV-07). A failed host check denies a run before
  anyone is asked (D10). A failed pull changes nothing (D5). A host that
  can't pull keeps its current trust, so revocations reach it only by
  hand. `pull.state` and `--status` show how long it has been.
- **What reaches Telegram and the audit log.** The host key's
  fingerprint, the address, the client address, `sudo` and
  `session_kill`. Never a token (the audit keeps the hash of its random
  part), a private key, or a certificate's signature. The bundle holds
  no secret.
- **New ways to reach a target.** The host check (D10) and the probe
  (D7). The check never authenticates and runs nothing. It is triggered
  by an agent's `run` or `elevate`, but only towards addresses in the
  registry, and is audited as part of that request. The probe
  authenticates as the target's accounts and opens no channel, so no
  command runs. It happens only after an approved enrollment, once per
  account, stopping at the first refusal so that it doesn't trip
  `PerSourcePenalties` (M5) more than once.
- **Credentials issued.** Host certificates: one host key, one
  principal, five years by default, no extension but the session-kill
  flag. They are stopped by listing the host key in
  `revoked_host_keys`. The CA keys stay in the pod, as docs/07 D6
  decided; `host-ca` adds one more.
- **Who can make or change the CA keys** (D16). The install hook's
  ServiceAccount can create any Secret in the namespace, but only while
  the hook runs, success or failure (`hook-failed`); it can't read one.
  Rendered without Helm, the grant would persist, which is why that
  mode needs `generateCA: false` (D16). The rotation CronJobs' ServiceAccount
  can read and update the CA Secret, so whoever can start a Job, or a
  pod with that ServiceAccount, in Nyyrikki's namespace can read the CA
  keys. That is an administrator's right, and the same person can read
  the Secret directly. Agents' cluster-wide read (docs/01 OD7) covers
  neither. Neither Job's log holds a private key.
- **Blast radius.**
  - *`host-ca`* lets its holder make Nyyrikki trust any host for any
    target address. To use that, they also have to redirect Nyyrikki's
    connections to that address, and the reward is the commands and
    stdin of approved runs. It sits in the same Secret as `user-ca`,
    which already reaches every host directly.
  - *Signing bundles in the pod* (OD3): whoever holds `user-ca`, by a
    leak or a compromise of the pod, can sign a bundle adding their own
    CA, and every host with a pull takes it within 15 minutes, before
    a revocation lands. Their CA still gets past only `from=` and the
    certificate's `source-address` (docs/07 D4, D5): it reaches `ny-*`
    accounts only from Nyyrikki's source addresses, which a `user-ca`
    holder already can. To serve a bundle at all, they also need the
    pod or the TLS path to the hosts. After a leak, re-run the setup on
    each host, which rewrites `user_ca.pub` and `signers.pub` from the
    values and resets `pull.state` (`--reset-pull-state`, D13). That re-run is required, not
    optional: the pull doesn't recover a host from a leak of `user-ca`
    or of a staged `user-ca-next` (§5.4). The stage/promote rule (D5) keeps one bundle from replacing
    the signer set, but two bundles from the holder can. Extra keys in
    `user_ca_public_keys` can't sign bundles (D4).
    SECURITY.md gets this accepted risk when the doc is approved.
  - *The token*: within 15 minutes, its holder can put one enrollment
    prompt in front of the approver. An approver who taps it without
    comparing the fingerprint would trust the holder's host for that
    target's address. The prompt says what to compare. The approver
    should be the administrator at the host, or in touch with them.
- **What the pull can and can't do as root** (D5): add revocations,
  remove principals and sudoers files, replace the trusted CA keys, and
  change the bundle signers by D5's three relations only. Nothing else,
  and never an account or a grant.
- **The setup script** stays one fixed body, checksummed per release,
  with `pull.sh` inside it. A changed body is still visible to a careful
  administrator, as docs/07 §6 says.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 The trusted set is `pub(user-ca)`, `pub(user-ca-next)` when present, and the extra keys, minus the revoked ones. A missing optional file removes that feature only. An unreadable, unparseable or non-ed25519 key file makes SSH runs and every `/hosts/` endpoint `unavailable`. A revoked `user-ca` is `user_ca_revoked`. A Secret change is picked up without a restart | `TestCAKeys*` (`internal/sshca`) |
| G2 `ssh-ca init` prints a Secret with two fresh ed25519 keys and nothing else. `stage` adds `user-ca-next` and refuses if one exists. `promote` moves it and prints the old public key on stderr. None of them prints a private key on stderr or keeps a field outside the allowed list | `TestSSHCACommand*` |
| G3 The bundle has D4's lines and signature, and `ssh-keygen -Y verify` accepts it with the `SIGNER_KEY`s as allowed signers, and refuses one signed by an extra trusted key. It refuses another namespace or a changed byte. The endpoint follows docs/07 D16's method, query and `404` rules and audits each fetch | `TestTrustBundle*`; `test/ssh-host` verifies a served bundle with the host's `ssh-keygen` |
| G4 The pull applies revocations, removes stale humans' principals and sudoers files, removes sudoers with `SUDO=false`, and replaces the CA set, without reloading sshd: a certificate of a newly revoked CA is refused, and one of a newly added CA logs in, on the next login. It refuses, changing nothing, a bundle with a bad signature, one signed by a revoked or untrusted key, another target's, an `ISSUED` not later than the last, one more than 10 minutes ahead of the host's clock, one signed by a key in `user_ca.pub` but not in `signers.pub`, a malformed or cut-off one, and a failed fetch. It never creates an account, writes a new principals file or grants sudo, and logs what it would need a re-run for | `test/ssh-host`: the pull run in Debian, Ubuntu and Rocky containers against served bundles |
| G5 The setup installs `/etc/cron.d/nyyrikki` where a non-BusyBox cron exists, `/etc/periodic/15min/nyyrikki-pull` on Alpine, and nothing (reporting `pull: none`) without cron or without `curl`. The installed schedule runs the pull. `--uninstall` removes every pull file. `--status` changes nothing | `test/ssh-host` (Debian cron, Rocky cronie, Alpine BusyBox, and a host with no cron) |
| G6 Tokens: a valid token is accepted once. An expired one, one for another target, a forged or truncated one, and one replayed after use are each refused with no prompt. The command refuses without `host-ca`. No token appears in a log or audit record | `TestEnrollToken*` |
| G7 Enrollment end to end: the prompt shows the fingerprint, address, `sudo` and `session_kill`. Approve returns a certificate with exactly D8's fields. Deny, a timeout, or the call going away return none and audit why. The check reports `ok` per account, and `refused` with the hint when `source_addresses` is wrong, stopping at the first refusal. A replayed token can't start a second enrollment | `TestEnroll*` against the fake Bot API and an in-process SSH server; e2e on kind against an OpenSSH container enrolled by the served script |
| G8 Host verification accepts a pin, a certificate from a target's or the global `host_cas`, and one from `host-ca`, each naming the host. It refuses one listed in `revoked_host_keys`, an expired one, one for another host, and a `host-ca` certificate whose key ID names another target. `session_kill` is read from Nyyrikki's own certificates only | `TestHostKey*` extended |
| G9 The host check runs before every SSH run prompt and elevation prompt, without authenticating (the in-process server records no auth attempt). A failed check denies a run with its detail, unprompted. An elevation shows the warning for that target. A run whose host now shows less than the prompt did is `host_changed` | `TestHostCheck*`, `TestSSHRunHostChanged` |
| G10 Config: the port defaults to 22. `defaults.sudo` applies only where `sudo` is unset. A name shared by a group and a target, or a group naming an unknown target, is refused. `elevate` with a group covers exactly its expanded members, shows them in the message, and isn't widened by a later group change. `MaxTargets` counts the expanded list. `list_targets` returns `groups` and, for SSH targets, `sudo` | `TestConfigSSHDefaults`, `TestGroups*`, `TestElevateGroup*` |
| G11 `nyyrikki ssh` maps to `run -t` and `run --` as D12 says, and refuses a non-SSH target before calling `run` | `cmd/nyyrikki` tests |
| G12 The chart mounts the whole Secret, maps every new value to the config, honours the old `sshUserCA` for one minor release with a note, and `NOTES.txt` prints the `enroll-token` command | `deploy/chart` tests |
| G13 The setup script: new data lines and options are checked like the others. A failed enrollment leaves the host set up and fail-closed. A re-run without `--enroll` on an enrolled host keeps `HostCertificate` before any `Match` block, and the host still passes verification. A re-run sets `pull.state` to the setup's `ISSUED`, and a bundle issued before the re-run is refused. A setup whose `ISSUED` is more than 10 minutes ahead of the host's clock is refused. A bundle that changes `signers.pub` other than by stage or promote is refused, and each signer change is logged. A bundle whose signers relate to the host's otherwise than D5's three relations is refused, the planned stage, promote and unstage are accepted, and a host offered `{B,C}` while holding `{A,B}` refuses. A pod whose `user-ca-next` is revoked serves a bundle without it as a signer, which hosts accept and apply. A setup older than the last bundle applied is refused and leaves the host unchanged, and with `--reset-pull-state` it succeeds and sets the mark to its `ISSUED`. A failed `sshd -t` after installing the certificate removes it again. The setup and the manual page still produce the same files (docs/07 G9), the pull files included | `test/ssh-host` |
| G14 A real host enrolled with one command and one tap on a real phone, then a CA rotation reaching it by its pull, without a visit | manual, by the owner |
| G15 The install hook creates the Secret with two fresh keys and D16's labels on the first install with an SSH target, and on the upgrade that adds the first one. It leaves an existing Secret byte for byte unchanged. Its Role grants only `create`. Its log holds no private key. `helm upgrade --force` and `helm uninstall` leave the Secret unchanged. The stage and promote CronJobs rotate as §5.4 says, and `-add-host-ca` adds a missing `host-ca` only, each with RBAC on that one Secret name. The hook RBAC is gone after a failed Job. The Secret carries no `app.kubernetes.io/instance`. An upgrade from an R10 release with `secrets.sshUserCA` keeps the old `user-ca`, renders no hook, and `import` migrates it. `enroll-token` without `host-ca` prints the remedy. After migration and a `promote`, the old key is in no `CA_KEY`. `import | kubectl create` against an existing Secret fails and changes nothing; migrating in the wrong order is recovered as D14 says. `stage` and `promote` refuse an R10 Secret. `generateCA: false` renders no hook, and the CronJobs only with `caJobs: true` | `deploy/chart` tests (rendering, RBAC, labels); `TestSSHCACommand*` (`import`, `add-host-ca`); e2e on kind (install, upgrade from an R10 release, a failed hook, `--force`, uninstall, rotation) |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **SE1** | `internal/sshca` (D1, D3), the run minter moved onto it, `nyyrikkid ssh-ca` (D2) with `--create`, chart Secret mount (D14, first part), the install hook and rotation CronJobs (D16) | G1, G2, G12 (Secret part), G15 |
| **SE2** | config defaults, global `host_cas`, `revoked_host_keys`, groups, `elevate` expansion, `list_targets` fields, `nyyrikki ssh` (D11, D12) | G10, G11 |
| **SE3** | trust bundle endpoint and signer (D4) | G3 |
| **SE4** | host verification (D9), host check before approval (D10), session_kill from certificates in messages | G8, G9 |
| **SE5** | tokens, `enroll-token`, enrollment endpoints, Telegram message, host certificate signer, the probe (D6, D7, D8) | G6, G7 (unit) |
| **SE6** | setup script (D5, D13), `test/ssh-host` with Alpine, docs (D15), chart values and `NOTES.txt` (D14, rest), e2e; dated notes in docs/01 (D4, D10), docs/07, docs/02 and SECURITY.md | G4, G5, G7 (e2e), G12, G13, G14 |

SE1 lands first: every other chunk reads keys through `internal/sshca`.
SE2 doesn't depend on the others. SE3 and SE5 need SE1. SE4 needs SE1
for `host-ca`. SE6 needs SE3 and SE5 for the endpoints its script talks to.

## 9. Risks and open questions

- **A host clock more than 10 minutes behind Nyyrikki's** fails every
  pull, and the setup refuses, both naming the clock (D5, D13).
  `--status` says so. Hosts need NTP.
- **A host that can't pull** quietly misses revocations. `--status`
  shows the last pull, and `host_trust_served` in the audit shows which
  targets haven't fetched lately. Nothing alerts on its own.
- **Five-year host certificates** outlive most hosts. A decommissioned
  host's certificate stays valid for its address until its key is
  listed in `revoked_host_keys`. If someone else's machine later gets
  that address, Nyyrikki refuses it anyway, since it doesn't hold that
  key.
- **The host check adds a connection to every SSH request**, about one
  key exchange's latency. It also contacts hosts for requests that are
  then denied. Both are deliberate (OD6).
- **`PerSourcePenalties`** (M5) applies to runs too: on a host where
  Nyyrikki's logins keep failing (a wrong `source_addresses`, a missing
  principals file), its address gets penalised, and the next runs fail
  as unreachable rather than refused. The enrollment check's hint is the
  first place this shows.
- **One machine, one enrolled target.** sshd presents one certificate
  per host key, and D9 ties it to one target by its key ID. A machine
  listed as two targets is enrolled for one and pinned (`host_keys`)
  for the other.

## 10. How it was implemented (YYYY-MM-DD)

<!-- Added during implementation. -->

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
