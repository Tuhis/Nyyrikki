# R10 — SSH target: commands on Linux hosts, as the human (docs/07)

**Status**: drafted 2026-10-29. Owner decisions OD1–OD6 taken the same
day. Awaiting the owner's approval of the doc as a whole; merging the PR
that adds it is that approval. Status lives in
[`ROADMAP.md`](../ROADMAP.md).

Chunks **SH1–SH6** (`SH` = SSH; unused).

**Relationship to earlier work**: a second target type next to
Kubernetes. It reuses the operations, the decision point, elevations and
`/stream` of [docs/02](02-gateway-core.md), the audit log of
[docs/03](03-audit-log.md), the run limits and cutting of
[docs/04](04-kubectl-passthrough.md) D7 and D8, and the messages of
[docs/05](05-telegram-escalation.md). It is the first target that needs
**credentials issued on the target** (`ROADMAP.md` R4: issued
credentials), because SSH can't impersonate. It extends docs/01 OD9
(first target: Kubernetes) and does not revise it. When this doc is
approved, the rows it extends get dated notes: docs/01 D10 (a new path
on `:8443`, D16 here), docs/02 D5 and D13 and §5.2, docs/03 D1 and §5.1,
docs/04 D12 (D17 here), docs/05 D4, D5 and D7, docs/06 D2.

The replaced Warden plan had an SSH proxy design
([docs/08 at 0ea8b56](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/08-ssh-proxy.md)).
This doc takes over its certificate and host-key ideas, not its model:
there, the agent ran plain `ssh` against a protocol proxy (set aside in
`CLAUDE.md`). Here the agent asks Nyyrikki to run a command, as for
kubectl.

---

## 1. Purpose

Not everything an agent needs to fix is in Kubernetes. Restarting a
service on a VM, reading a journal, or editing a file under `/etc`
needs a shell on a host. Today that means giving the agent an SSH key,
which works forever, on every host that trusts it, with nothing
approved and nothing recorded.

With this, an agent asks for one command on one host, the approver sees
that exact command on Telegram, and Nyyrikki runs it as an account that
belongs to the human, with a certificate that lives for two minutes and
never leaves Nyyrikki. An elevation covers a burst of commands on named
hosts, as for kubectl. Where the host allows it, the human's account can
use passwordless sudo, so commands that need root work too, logged under
the human's name.

Setting a host up is one command, with the manual steps documented next
to it.

### Non-goals

- **Running unmodified `ssh`, `scp`, `rsync`, ansible or git over SSH
  from the agent's machine.** That needs a protocol proxy the agent
  connects to, which is the set-aside Warden model (`CLAUDE.md`).
- **Port forwarding of any kind, agent forwarding, X11** (OD5).
- **SFTP and scp.** A command with stdin uploads (`sudo tee /etc/x`); a
  command's stdout downloads.
- **Choosing the remote account.** It is fixed per human (D3); acting as
  another account is `sudo -u` inside an approved command.
- **Password or keyboard-interactive login**, on either side.
- **Recording what is typed in an interactive session.** The approver
  approves the session (OD4).
- **Hosts other than Linux with OpenSSH ≥ 9.0.** No network devices, no
  Windows, no Dropbear.
- **Undoing what a command started.** A command can start work that
  outlives any cut by putting it outside its session: a service
  (`systemctl start`, `systemd-run`), a timer or a cron job, or, on a
  host without systemd session kill, any detached process (D11).
- **Pushing setup to hosts.** Nyyrikki never configures its own trust
  (D14).

## 2. Measured and verified before writing

Measured on 2026-10-29 against OpenSSH 10.0p2 and sudo 1.9.17p2 on
Alpine 3.22 in a container, with the OpenSSH 10 client and a Go probe
using `golang.org/x/crypto/ssh` v0.58.0 on Go 1.26.8, in a throwaway
container. SH5 turns the same checks into `test/ssh-host`.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `golang.org/x/crypto/ssh` v0.58.0 signs user certificates (`Certificate.SignCert`, `NewCertSigner`), dials and authenticates with them, and sends `signal` channel requests (`Session.Signal`) | `docs/measured.md` (SSH M1); the Go probe logged in with a certificate it signed | Confirmed. D5, D9, D11 |
| M2 | With `TrustedUserCAKeys` and `AuthorizedPrincipalsFile /etc/ssh/principals/%u`, a certificate logs in only if one of its principals is listed in the file for that user. A certificate whose principal is the username, for a user with no file, is refused | logins with matching and non-matching principals, and for a user without a file | Confirmed. D4 |
| M3 | Options on a principals-file line are enforced for certificate logins: `from=` refuses other source addresses ("Refused by certificate principals options"); `restrict` refuses a local port forward even when the certificate carries `permit-port-forwarding` ("refused local port forward") | a login from the wrong address; `ssh -L` with such a certificate, then a connection through the forward | Confirmed. D4 |
| M4 | A PTY is allocated only if both the certificate carries `permit-pty` and the principals line allows it (`restrict,pty`); without `permit-pty`, "PTY allocation request failed" | `ssh -tt` with and without `permit-pty` | Confirmed. D5. Closes `docs/measured.md` SSH M5 for PTYs |
| M5 | The certificate's `source-address` critical option refuses a login from any other address | certificates with matching and non-matching `source-address` | Confirmed. D5 |
| M6 | A `RevokedKeys` KRL that lists the CA's public key refuses every certificate the CA signed ("revoked by file") | `ssh-keygen -k -f krl ca.pub`, then a login | Confirmed. D4, §5.6 |
| M7 | sshd without PAM refuses an account whose password field is `!` ("User not allowed because account is locked"), certificate or not; `*` (no password can match) logs in | Alpine's `adduser -D` writes `!`; changed to `*` | Confirmed. D3: the script writes `*`. PAM-based distributions not measured; `*` works with or without PAM |
| M8 | `Match User <name>` with `AuthorizedKeysFile none` in a drop-in under `/etc/ssh/sshd_config.d/` refuses that user's plain keys while certificate logins still work, and leaves other users unchanged | a key in the user's `authorized_keys`: refused; a certificate: accepted; another user's key: accepted | Confirmed. D3 |
| M9 | NOPASSWD sudo works for a certificate login with no TTY: `sudo -n id -u` prints `0` | as stated | Confirmed. D7 |
| M10 | Closing the connection doesn't stop a command run without a PTY: it is reparented to init and keeps running, under sudo too. With a PTY, the command ended (sshd closes the PTY, which hangs it up) | dropped the connection during `sleep`, then `ps` on the host | Confirmed. D11 |
| M11 | A `signal` request with `TERM` stops the command, including through `sudo` and for `a; b`; `KILL` stops a plain command and `a; b`, but under `sudo` it kills only sudo and leaves the root child running | Go probe: `Session.Signal`, then `ps` | Confirmed. D11: `TERM` first |
| M12 | sshd logs the certificate's key ID and serial on login (`… ED25519-CERT SHA256:… ID nyyrikki:<id> (serial N) CA ED25519 …`) | sshd log at `LogLevel VERBOSE` | Confirmed, as `docs/measured.md` SSH M4. D5 |
| M13 | `ssh` joins its command arguments with single spaces and sends one string, which the remote user's shell interprets | ssh(1); OpenSSH `ssh.c` | Re-read; confirmed. D1 |
| M14 | Debian 12+, Ubuntu 22.04+ and RHEL 9+ ship `Include /etc/ssh/sshd_config.d/*.conf` as the first line of `sshd_config` other than comments, so a drop-in's settings win over the main file's for keywords where the first value counts | read `sshd_config` | Confirmed on Debian 13 (OpenSSH 10.0p2), 2026-10-29. **Not yet measured** on Ubuntu and RHEL; SH5 measures them before the script relies on it |
| M15 | RHEL-family sudo with `Defaults requiretty` refuses a command without a TTY unless `!requiretty` applies to the user | sudoers(5) | **Not yet measured**. SH5 |
| M16 | `AuthorizedKeysFile none` in the `Match User` block does **not** turn off a global `AuthorizedKeysCommand` (as EC2 Instance Connect images set): a plain key the command returns logs in to the Nyyrikki account. Adding `AuthenticationMethods publickey`, `AuthorizedKeysCommand none`, `KbdInteractiveAuthentication no`, `HostbasedAuthentication no` and `GSSAPIAuthentication no` to the block refuses it, certificates still work, and `sshd -T -C user=<account>,…` shows each value. On a build without GSSAPI (Alpine's), `GSSAPIAuthentication` logs "Unsupported option" and `sshd -t` still passes | global `AuthorizedKeysCommand` that prints the client's key; plain key and certificate with each block, 2026-10-29 (review of #25) | Confirmed. D3, §5.7 steps 4 and 7 |
| M17 | `ssh-keygen -k -u -f <file>` refuses a zero-byte file ("KRL file has invalid magic number"), though sshd accepts one as `RevokedKeys`. `ssh-keygen -k -f <file>` with no keys writes a valid empty KRL (44 bytes) that sshd accepts and `-u` then extends; `ssh-keygen -Q` reports the added key as revoked | as stated, 2026-10-29 (review of #25) | Confirmed. §5.6, §5.7 step 2 |
| M18 | On a systemd host whose sshd uses PAM with `pam_systemd` (Debian 13: systemd 257, OpenSSH 10.0p2, sudo 1.9.16p2), a command run through sudo stays in the SSH session's scope (`session-N.scope`), root processes included: sudo's PAM stack doesn't move it. By default the scope outlives the connection ("logged out. Waiting for processes to exit"), and a sudo command that ignores `TERM` keeps running. With logind's `KillUserProcesses=yes` and `KillOnlyUsers=ny-owner`, closing the connection stops the scope: `TERM` to every process in it, then `KILL` after the scope's `TimeoutStopSec` (gone after 92 s by default; after 6 s with a `session-.scope.d` drop-in setting `TimeoutStopSec=5s`). A `setsid nohup` process started under sudo is gone too. `KillOnlyUsers` without `KillUserProcesses=yes` kills nothing | Debian 13 container running systemd; Go probe started `sudo -n sh -c 'trap "" TERM HUP INT; …'` and closed the connection; `ps` and the journal, 2026-10-29 (review of #25) | Confirmed. D11, §5.7 step 6 |
| M19 | sshd's `StrictModes` refuses a group- or world-writable principals file or directory ("bad ownership or modes"), and the login then fails as "Certificate does not contain an authorized principal" | a principals file written with umask 0 | Confirmed. §5.7: the script sets `umask 022` and explicit modes |
| M20 | `AuthorizedKeysCommand none` without `AuthorizedKeysCommandUser` logs `error: No user for AuthorizedKeysCommand specified, skipping` on every login; adding `AuthorizedKeysCommandUser nobody` silences it | Debian 13, as stated | Confirmed. D3 |
| M21 | With `ClientAliveInterval 5` and `ClientAliveCountMax 3` in the `Match User` block, a network partition ends the session on the host ("Timeout, client not responding") about 15 s in, and with session kill (M18) a sudo command that ignores `TERM` was gone 23 s into the partition. Without them, sshd waits for TCP keepalive (about 2 h on Linux by default) | Debian 13 container with session kill; `docker network disconnect` while the probe held the session open, 2026-10-29 (review of #25) | Confirmed. D3, D11 |
| M22 | A file that ends with `main "$@" <<'NYYRIKKI_VALUES_END'`, then data lines, then the terminator, run piped into `dash` or `bash`, gives `main` the data lines on stdin and never executes them; with `main` ending in `exit`, a line after the terminator never runs. The checksum of the file up to and including the `main` line equals that of the body alone | ran good, injected (`$(…)` in a value) and trailing-code variants in `debian:trixie`, 2026-10-29 (review of #25) | Confirmed. D16, §5.7 |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | How do commands get root? A root login, the human's own account with sudo, or a separate account? | **Passwordless sudo, opt-in per host and human, on a separate local account per human that only Nyyrikki's certificates can reach. Never a root login** (owner, 2026-10-29). NOPASSWD on the human's normal account would also apply to their normal logins, so an agent holding the human's own SSH key could get root without Nyyrikki. |
| OD2 | What may the sudo rule allow? | **`ALL`** (owner, 2026-10-29). A list of commands is easy to escape (`sudo vi`, `find -exec`, `tar`) and would only look like a boundary; the approver reading the command is the boundary. |
| OD3 | How is the host setup script delivered? The owner asked for an endpoint on Nyyrikki that serves it, so onboarding is one `curl … \| sudo sh`. | **Served by Nyyrikki, as a static script** (owner, 2026-10-29): the script's body is built into the binary, byte for byte the file in the repo, with its checksum published per release; the path is fixed and takes no query parameters; the target must be in the registry; every value comes from config; the script prints the CA key's fingerprint for comparison (D16, §5.7). Weighed against a release asset with values pasted as arguments: hosting on Nyyrikki means the trust anchor (the CA public key) never comes from a pasted line, so a steered agent can't hand the owner a ready-made command carrying its own CA key, and the script always matches the running server. Its costs: a new unauthenticated path on `:8443`; hosts must reach Nyyrikki and trust its TLS certificate; and someone who controls the pod controls what it serves, which adds root on hosts onboarded later to what the CA key in the same pod already gives. Manual setup stays documented. |
| OD4 | Interactive sessions (`-t`: a login shell, or a command with a PTY) under a one-off approval, or only under an elevation? Approving one is approving "anything on this host, as this account, for a while", and a one-off run has no "End now" (docs/05 D7). | **Allowed under a one-off approval, with an "End now" button on the message of every interactive run, SSH and kubectl alike** (owner, 2026-10-29). The session lasts at most `run.max_interactive` and is cut when it ends, when what covers it ends, or when the approver taps "End now" (D17). Considered: one-off without "End now" (as kubectl had: up to 30 minutes, possibly of root, that the approver can't stop); elevation-only (an honest window with "End now" already, at the cost of two calls); no interactive SSH runs. |
| OD5 | Local port forwarding (`ssh -L`), for example to reach a database behind the host? | **Not offered at this time** (owner, 2026-10-29), like kubectl's `port-forward` (docs/04 D5). It would need a listener on the agent's machine and carry bytes the approver can't see, to whatever the host can reach. The setup refuses it on the host as well (`restrict`, M3), so adding it later is a decision on both sides. |
| OD6 | stdin on Telegram. docs/04 D14 redacts secret values from kubectl stdin by structure; a host command's stdin has none. Show it as text, accepting that a secret sent on stdin reaches the Telegram chat, or show only its size and hash? | **Never shown as text: only its size and hash, with a warning. What the approver must read goes in the command** (owner, 2026-10-29: leaking secrets to Telegram would be bad). stdin is for data (`sudo tee /etc/app/env`); a script the approver should read is sent as part of the command string, for example as a heredoc, which is shown in full (D2). Since a command can run what it reads (`sh`, `bash -s`, `python3 -`, `tee x; sh x`), the message says so next to the size, and the approver denies a command that executes hidden input. The `run` tool's description and the CLI's help tell agents the same. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **The request** is `args` and optional `stdin`, as for kubectl (docs/04 D1). `args` is joined with single spaces into one **command string**, as `ssh` does (M13); that string is the canonical request. It is sent to the host as one `exec` request and the remote account's shell interprets it. `args` may be empty only for an interactive run, which then asks for a login shell. The command string is at most 16 KiB; it may contain tab and newline, and any other C0 or C1 control character, or NUL, is `invalid_request`. | 1:1 with what agents already type after `ssh host`. The string is the request: there is no argv on the host side to put in canonical form, so the approver judges the string, and Nyyrikki guarantees that exactly that string runs (INV-02). Control characters could make the displayed string differ from what the shell reads. |
| D2 | **What the approver sees, what the approval binds to and what runs are one value**: the command string, stdin, the interactive flag, the target and the remote account. The digest is docs/04 §5.3's with the prefix `nyyrikki-ssh-request-v1` and those fields, length-prefixed. The command is shown in `<pre>` with docs/04 §5.2's escapes for bidi and zero-width characters; stdin is never shown: only `‹stdin: N bytes, sha256:<first 12 hex>, not shown›` (OD6). Nothing is redacted from the command string; a secret typed into it reaches Telegram and the audit log, as docs/04 D14 already accepts for positional arguments. | INV-02; docs/05 D5. A shell command has no structure to find a secret in. |
| D3 | **One dedicated account per human per host**, `ny-<human id>`, created by the setup (§5.7): password field `*` (M7), a home directory, `/bin/sh`, and an `sshd` `Match User` block that leaves only Nyyrikki's certificates: `AuthenticationMethods publickey`, `AuthorizedKeysFile none`, `AuthorizedKeysCommand none` (with `AuthorizedKeysCommandUser nobody`, M20), `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `HostbasedAuthentication no`, `GSSAPIAuthentication no` (M8, M16); and `ClientAliveInterval 5` with `ClientAliveCountMax 3`, so the host ends a session within about 15 s of losing Nyyrikki (M21). So no keys file, keys command (a global one, as EC2 Instance Connect sets, included), `.shosts`, `.k5login` or PAM prompt reaches it, whatever is later written to its home or the main config. *Revised 2026-10-29 (review of #25)*: the block first held only `AuthorizedKeysFile none` and `PasswordAuthentication no`, which a global `AuthorizedKeysCommand` gets past (M16); the client-alive settings were added the same day, for a cut during a network partition (M21). Nyyrikki never logs in to an existing account. The account has no groups and no sudo unless the setup gave them (D7). The name comes from the human registry, never from the request. Human IDs used with SSH targets are at most 29 characters, so the name fits Linux's 32. | OD1. INV-05: the target sees the human. Because the account is Nyyrikki's alone, what it can do is exactly what the setup gave it, and nothing reaches it outside Nyyrikki. |
| D4 | **Host side of the trust**: `TrustedUserCAKeys` holds Nyyrikki's user CA public key (several during rotation); `AuthorizedPrincipalsFile /etc/ssh/nyyrikki/principals/%u`; `RevokedKeys /etc/ssh/nyyrikki/revoked.krl`. The principals file of `ny-<human>` holds one line: `restrict,pty,from="<source addresses>" nyyrikki:<human id>@<target name>`. | M2, M3, M6. Principals are namespaced, so another CA the host trusts can't produce one by accident, and include the target, so a certificate for one host doesn't work on another. `restrict` and `from=` are enforced by the host even if Nyyrikki issues a wider certificate. |
| D5 | **One certificate per run**, over an ed25519 key pair generated in memory for that run and never written down: type user; principal `nyyrikki:<human id>@<target name>`; key ID `nyyrikki:<run_id>`; a random 64-bit serial; valid from now − 60 s to now + 2 min; critical option `source-address` = `ssh.source_addresses`; extensions: only `permit-pty`, and only for an interactive run. Run ID and serial go into the audit record. | `CLAUDE.md`: issued credentials scoped as narrowly and living as briefly as works, inside Nyyrikki. sshd checks the certificate only at login, so 2 min covers the handshake, not the run. M4, M5, M12: the host's log ties the login to Nyyrikki's audit. |
| D6 | **The user CA private key** is an ed25519 OpenSSH key in a Secret, mounted as the file `ssh.user_ca_key_file`, read on each use (docs/06 D4), never logged. Rotation: add the new public key to the hosts' `TrustedUserCAKeys`, replace the Secret, then remove the old key. Nyyrikki doesn't generate it (§5.6). | docs/01 D15. The CA key is the credential with the widest blast radius in this doc: every principal every host lists. |
| D7 | **Root through sudo**, when the target has `sudo: true` (opt-in per host; the setup reads it from config, §5.7): `/etc/sudoers.d/50-nyyrikki-ny-<human>` holds `Defaults:ny-<human> !requiretty` and `ny-<human> ALL=(ALL) NOPASSWD: ALL` (OD2, M9). Every message for that target says so (D12). With `sudo: false`, the account has no sudo. | OD1, OD2. sudo logs each command under `ny-<human>`, so the host keeps the human's name. |
| D8 | **Nyyrikki verifies the host** before it authenticates: the host key must equal one of the target's `host_keys` (compared as marshalled keys), or be a host certificate signed by one of its `host_cas`, valid now, with the target's host name among its principals. There is no trust on first use. A mismatch is `unavailable` with detail `host_key_mismatch`, audited, and the run never authenticates. | A wrong host would receive the command and the stdin. |
| D9 | **Running**, in-process with `golang.org/x/crypto/ssh` (M1): dial `address` with `ssh.connect_timeout` (default `10s`) under the run's context; verify the host (D8); authenticate with the certificate (D5); open one session; send no `env` request; for an interactive run, `pty-req` with the client's `TERM` (matching `[a-z0-9.+-]{1,32}`, default `xterm-256color`) and size; then `exec` with the command string, or `shell` for an interactive run without one; write stdin and close it. stdout, stderr, limits and truncation are docs/04 D7's. The result's `exit_code` is the remote exit status; on `exit-signal` it is 128 plus the signal's number, with the signal's name in `detail`. One connection per run, closed when the run ends. | No external binary, no shell on Nyyrikki's side, nothing inherited from the pod's environment (docs/04 D6's reasons). `env` requests are a way to inject `LD_PRELOAD`-style variables. |
| D10 | **What reaches the agent** is the remote exit status, stdout and stderr, as they came (docs/04 D13). The certificate and its key are never in a result, an error, a log or a message (INV-08). | `CLAUDE.md`: responses unredacted; Nyyrikki's own credentials never handed over. |
| D11 | **Cut**: when the run's grant context ends (timeout, elevation expiry, "End now"; docs/04 D8), Nyyrikki sends `signal TERM`, waits up to 2 s for the session to end, sends `signal KILL`, and closes the connection; `run_cut` is audited. Closing alone would leave a command without a PTY running (M10), and `KILL` doesn't reach a command run through sudo (M11), so **the host finishes the cut**: on a systemd host the setup makes logind stop the Nyyrikki account's session scope when the connection closes, which sends `TERM`, then `KILL` after 5 s, to every process the session started, root ones under sudo and detached ones included (M18). If the host can't be reached when the cut comes, so `TERM`, `KILL` and the close never arrive, the host ends the session itself within about 15 s of losing Nyyrikki (D3's client-alive settings), with the same effect (M21). The target's `session_kill` says whether its host does this (§5.5); where it doesn't (no systemd, or no `pam_systemd` in sshd's PAM stack), a sudo command that ignores `TERM` can outlive the cut, and the messages say so (D12). Work a command moves out of its session (a service, a timer, a cron job) is not cut; that is a non-goal, and the approver sees the command. *Revised 2026-10-29 (owner decision, review of #25)*: first `TERM`, `KILL` and close only, which a sudo command ignoring `TERM` survives. | `CODE-REVIEW.md`: long-lived requests are cut when what covers them ends. Only the host can kill root processes of a session, and logind does it by cgroup, which a process can't leave by detaching. |
| D12 | **Messages** (extending docs/05 D5 and D7): "Runs as" shows `ny-<human> on <address>`, and for a `sudo: true` target the line "**root via sudo**"; an interactive run adds "Interactive: what is typed is not shown" (OD4); a run with stdin adds, next to its size and hash, "stdin is not shown. If the command runs it, you can't see what runs" (OD6). An elevation message names, per target, whether it has root via sudo, so the approver knows that a window on that host is a window of root. For a `sudo: true` target with `session_kill: false`, every message adds "a cut may not stop a sudo command that ignores TERM" (D11). | `CLAUDE.md`: the approver sees what will run, and as whom. `sudo: true` comes from config, not the host; §6 says what that means. |
| D13 | **Registry and limits**: an SSH target has an `ssh` block (§5.5) instead of `kubernetes`; `list_targets` returns `type: "ssh"`. `run` takes the same arguments for both types; for SSH, `args` may be empty when `interactive` is set (revising docs/02 D13 for SSH only). The run limits of docs/04 D7 apply unchanged. | One operation set (docs/02 D1); the target type decides how `args` is read. |
| D14 | **Hosts are set up out of band** by an administrator, by hand or with the setup script (§5.7). Nyyrikki has no way to change a host's SSH or sudo configuration other than an approved command, and never runs one on its own. | Nyyrikki configuring its own trust would need standing root on every host. |
| D15 | **The setup script** (§5.7) is the documented manual steps, automated: it refuses rather than guesses, never edits `sshd_config` itself, validates with `sshd -t` and `visudo -cf` before activating anything, rolls back on failure, and prints each host key for the administrator to copy into the registry. | It runs as root on the owner's servers. Reading the host key on the host itself is what makes D8's pins trustworthy without `ssh-keyscan`. |
| D16 | **The setup endpoint** (OD3): `GET /hosts/<target>/setup.sh` on `:8443`, without authentication, since a host has no token. It answers only `GET`; any query string is `400`; a target that isn't an SSH target in the registry is `404`, the same for every such name. The response is the static body built into the binary (`//go:embed` of `deploy/ssh-host/nyyrikki-host-setup.sh`), which ends with the line `main "$@" <<'NYYRIKKI_VALUES_END'`, then generated **data lines** `NAME=value`, then the terminator. The values are a quoted heredoc that `main` reads and checks; they are never executed, and `main` ends in `exit`, so nothing after the terminator runs (M22). They come only from config, each of a format checked when the config is loaded and again by the body: the target name; the human IDs of the target and their account names (slugs); `ssh.user_ca_public_keys` (ed25519, base64 characters only); `ssh.source_addresses` (CIDRs); `sudo` (`true` or `false`). Each fetch is audited (`host_setup_served`, with the target and the client address). The endpoint never reads the CA private key. | OD3. Values from config, not from the request, so the URL can't be crafted to change what the script does. Everything that executes is the fixed body, which anyone can compare with the repo and the published checksum (§5.7); the per-host part is data. *Revised 2026-10-29 (review of #25)*: the values were first a block of `readonly` assignments in front of the body, which ran as code before the body's checks and outside the checksum. |
| D17 | **"End now" on interactive runs** (OD4), for SSH and kubectl targets alike. When an interactive run's stream attaches (docs/02 D10), its approval message is edited to "Session live since 12:03:04" with an **"End now"** button; for a run covered by an elevation, the elevation's own "End now" already ends it. The button's callback is checked as docs/05 D4 checks any callback, and it acts only while the run is live. Tapping it cancels the run's grant context, so the run is cut as for any other end (D11 for SSH, docs/04 D8 for kubectl), audited `run_cut` with detail `ended_by_approver`. When the run ends for any reason, the message is edited to "Session ended at …" without buttons. A stream ticket that is never used leaves the message as approved, with no button. | OD4. An approver who approved a session can take it back. Revises docs/04 D12 and extends docs/05 D7, by dated notes when this doc is approved. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Logging in as `root`, with `PermitRootLogin prohibit-password` | Loses the human's name on the host (OD1). |
| NOPASSWD sudo on the human's own account | Applies to every login of that account, including an agent holding the human's own key: root with no Nyyrikki in the path (OD1). |
| A sudo command allowlist | Easy to escape; it would look like a boundary without being one (OD2). |
| cert-manager for the SSH user CA | It issues only X.509 certificates, so at most it could generate the key. Its renewal makes a new key and switches to it at once: hosts can't be given the next key before the switch, so every host would fail at each renewal, unless renewal is turned off and nothing is gained. The hard part of a rotation is the hosts (§5.6). cert-manager does fit Nyyrikki's own TLS certificate, which the chart mounts from a Secret; a publicly trusted one lets hosts fetch the setup script without `--cacert` (§5.7). |
| A long-lived key per host, held by Nyyrikki, in `authorized_keys` | A reusable credential on every host. Certificates cost nothing per run and expire on their own (D5). |
| `ssh-keyscan`, or trusting the first host key seen | Trust on first use (D8). The setup script prints the key from the host itself instead (D15). |
| Parsing the command string as shell, to show it as argv or to refuse parts of it | A second shell parser that can disagree with the host's shell: exactly the parser difference docs/04 D2 avoids. |
| Running the OpenSSH `ssh` binary | A second binary in the image, its config files and environment to lock down; `x/crypto/ssh` does all of D9 in-process. |
| A protocol proxy that unmodified `ssh` connects to | The set-aside Warden model (`CLAUDE.md`). |
| A setup script attached to each release, with the CA key and other values passed as arguments | OD3: the owner would paste the trust anchor, and a steered agent can offer a command with its own CA key in it. |
| A setup script generated per request, or one that takes query parameters | Its bytes would differ per host and couldn't be checked against the repo; parameters would let a crafted URL change what runs as root (D16). |
| A "register this host" endpoint the setup script calls | A write path into the target registry that the agent's network can reach, and the host key would be trusted on first use. The registry stays config (docs/01 D12). |
| sudo with the human's password, held by Nyyrikki | A long-lived secret per human per host, in a place it doesn't belong. |

## 5. Design

### 5.1 Flow

```
run(target, args, stdin, interactive) ── join ─► command string ─► Display ─► approver
                                                       │
                                                       └─► Digest ─► approval / elevation ─► Grant
Grant ─► mint cert (D5) ─► dial ─► verify host (D8) ─► auth ─► session ─► exec / shell ─► result
                                                                      ▲
                          grant context ends ─► TERM, 2 s, KILL, close (D11)
```

### 5.2 Package

`internal/sshtarget`: request building and validation (D1), display and
digest (D2), certificate minting (D5), host verification (D8), the runner
(D9, D11). The runner takes a `Grant` (docs/02 D6), checks its digest
against the request before it dials, and is wired to `/stream` for
interactive runs as docs/04 D12 is.

### 5.3 What a run looks like

```sh
nyyrikki run --reason "nginx returns 502 after the config change" db-1 -- sudo systemctl restart nginx
```

The approver sees:

```
Run request: db-1
Runs as: ny-owner on db-1.example.com:22
root via sudo
Agent: … (claimed name), key 3f9a…, signed in 12:01
┌──────────────────────────────────────┐
│ sudo systemctl restart nginx          │
└──────────────────────────────────────┘
Agent's claim (unverified): nginx returns 502 after the config change
Expires 12:06:04          [Approve] [Deny]
```

On the host, the journal shows the login with key ID
`nyyrikki:<run_id>`, and sudo logs `ny-owner : COMMAND=/usr/bin/systemctl
restart nginx`.

### 5.4 The CLI

`nyyrikki run TARGET -- ARGS...` as in docs/02 §5.5. For an SSH target:
stdin is sent only with `-i`; otherwise the remote command reads an empty
stdin, like `ssh -n`, so a CLI run from a harness never hangs on input.
`-t` with a terminal makes the run interactive; `nyyrikki run -t db-1`
with no arguments opens a login shell. The exit code is the remote
command's.

### 5.5 Configuration

```yaml
ssh:
  user_ca_key_file: /etc/nyyrikki/ssh/user-ca     # mounted Secret (D6)
  user_ca_public_keys:                            # what hosts trust; served by D16
    - ssh-ed25519 AAAAC3Nza… nyyrikki-user-ca
  source_addresses: [203.0.113.10/32]             # Nyyrikki's egress, ideally its own (§6); required (D4, D5)
  connect_timeout: 10s
targets:
  - name: db-1
    description: Primary database host
    humans: [owner]
    ssh:
      address: db-1.example.com:22
      host_keys:                                  # pins (D8), from the setup script's output
        - ssh-ed25519 AAAAC3Nza…
      host_cas: []                                # or host CA public keys
      sudo: true                                  # D7, D12
      session_kill: true                          # D11, from the setup script's output
```

`address` is `host:port`. `source_addresses` and `user_ca_public_keys`
are required as soon as one SSH target exists. `user_ca_public_keys`
must include the public key of `user_ca_key_file`, checked whenever the
key is read; a mismatch makes every SSH run `unavailable`. It holds two
keys during a rotation (D6), so hosts set up meanwhile trust both. A
target with empty `host_keys` and `host_cas` is valid, so that its setup
script can be served before its host keys are known (§5.7), but every
run on it is `unavailable` with detail `host_not_pinned`.
Each knob's consumer: `user_ca_key_file`, `source_addresses` → the
certificate minter (D5); `user_ca_public_keys`, `source_addresses`,
`humans`, `sudo` → the setup endpoint (D16); `connect_timeout`,
`address` → the runner (D9); `host_keys`, `host_cas` → host
verification (D8); `sudo` → messages (D12); `session_kill` → messages
(D12). `session_kill` defaults to `false`, and like `sudo` it states what
the host does, as the setup script reported it. The chart mounts the CA Secret (`secrets.sshUserCA`) at the fixed
path, as docs/06 §10 does for the others, and its config test checks
that every field reaches the binary.

### 5.6 Creating and rotating the CA

**Creating it**, once, by the administrator, on a machine no agent runs
on (`CLAUDE.md`: no target credential on the agent's machine), in a
temporary directory that is removed afterwards:

```sh
d=$(mktemp -d) && chmod 700 "$d"
ssh-keygen -q -t ed25519 -N '' -C nyyrikki-user-ca -f "$d/user-ca"
kubectl -n nyyrikki create secret generic nyyrikki-ssh-user-ca --from-file=user-ca="$d/user-ca"
cat "$d/user-ca.pub"     # goes into ssh.user_ca_public_keys
rm -rf "$d"
```

Not in a pod with `kubectl run -i`: what such a pod prints is kept as its
container log, which the agents can read (docs/01 OD7).

**Planned rotation**, three rollouts (D6):

1. Create a new key pair as above, but keep the private key aside, not
   yet in the Secret. Add the new public key to `user_ca_public_keys`,
   next to the old one, and roll out. Re-run the setup command on every
   host: each now trusts both keys.
2. Put the new private key into the Secret. Nyyrikki signs with it from
   the next run on (it reads the file on each use); the new key's public
   half is already in the list, so the check of §5.5 passes.
3. Remove the old public key from `user_ca_public_keys`, roll out, and
   re-run the setup command on every host.

**After a leak**, revoke first, then rotate:

1. On every host, add the leaked public key to the revocation list
   (`ssh-keygen -k -u -f /etc/ssh/nyyrikki/revoked.krl old-user-ca.pub`;
   the setup wrote a valid empty KRL for this, M17, and
   `ssh-keygen -Q -f /etc/ssh/nyyrikki/revoked.krl old-user-ca.pub`
   confirms it). Every certificate it signed is refused at once (M6), Nyyrikki's
   included: SSH runs fail closed until step 2.
2. Create a new key pair, put it into the Secret and make it the only
   key in `user_ca_public_keys`, roll out, and re-run the setup command
   on every host. The script keeps an existing revocation list (§5.7
   step 2).

Both procedures touch every host. Automating that is outside this item
(§9).

### 5.7 Host setup

**Manual**, in `docs/setup/ssh-hosts.md`; the script does the same
steps:

1. Check: run as root; OpenSSH ≥ 9.0; `sshd_config`'s first effective
   line includes `/etc/ssh/sshd_config.d/*.conf` (M14); `sshd -T` shows
   no `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` or `RevokedKeys`
   other than Nyyrikki's own; on a systemd host, no logind
   configuration file other than Nyyrikki's own drop-in sets
   `KillUserProcesses`, `KillOnlyUsers` or `KillExcludeUsers` (read with
   `systemd-analyze cat-config systemd/logind.conf`, skipping
   `50-nyyrikki.conf`), since Nyyrikki's drop-in would otherwise change
   how logind treats every other user. Excluding its own files is what
   lets the script run again on a host it set up. If any check fails, stop, and point
   at the manual steps: an existing setup has to be merged by a person.
2. Write `/etc/ssh/nyyrikki/user_ca.pub` (every key of `user_ca_public_keys`),
   `/etc/ssh/nyyrikki/revoked.krl` (unless one exists: a valid empty KRL
   from `ssh-keygen -k -f` with no keys, never a zero-byte file, which
   §5.6's `-u` would refuse, M17), and
   `/etc/ssh/nyyrikki/principals/ny-<human>` (D4).
3. Create `ny-<human>` (D3) if it doesn't exist. If it exists and its
   GECOS field isn't `nyyrikki`, stop: Nyyrikki never takes over an
   account it didn't create.
4. Write `/etc/ssh/sshd_config.d/50-nyyrikki.conf`: the three keywords
   of D4 and one `Match User` block per Nyyrikki account, with every
   keyword of D3.
5. If the target has `sudo: true`: write the sudoers file of D7 to a
   temporary path, `visudo -cf` it, install it with mode 0440. Otherwise
   remove it if a previous run wrote one. The host gets sudo exactly
   when the target says so, so the message's sudo marker (D12) matches
   what the setup did.
6. On a systemd host whose sshd uses PAM with `pam_systemd`: write
   `/etc/systemd/logind.conf.d/50-nyyrikki.conf` (`KillUserProcesses=yes`,
   `KillOnlyUsers=` the Nyyrikki accounts) and
   `/etc/systemd/system/session-.scope.d/50-nyyrikki.conf`
   (`TimeoutStopSec=5s`), then `systemctl daemon-reload` and restart
   `systemd-logind`, and check that logind reports both values (M18).
   Otherwise skip this, and step 9 reports `session_kill: false`.
7. `sshd -t`, then `sshd -T -C user=ny-<human>,host=<host>,addr=<a
   source address>` for each account: the effective values must be D3's
   (`authenticationmethods publickey`, `authorizedkeyscommand none`,
   `clientaliveinterval 5`, and so on) and D4's three. This catches a main config whose own values
   win over the drop-in's. If either fails, restore every file from steps 2–6 and
   stop. Otherwise reload sshd.
8. Every file the script writes gets explicit modes (0755 directories,
   0644 files, 0440 sudoers) under `umask 022`: sshd refuses a writable
   principals file (M19).
9. Print the target's `host_keys` entry with the host's own public keys
   from `/etc/ssh/ssh_host_*_key.pub` and their fingerprints, and its
   `session_kill` value.

`--uninstall` removes the accounts, their homes, the script's files and
the drop-in, then `sshd -t` and reload. Re-running replaces only the
script's own files. `--dry-run` prints every check and every file it
would write, and changes nothing.

**The script** is `deploy/ssh-host/nyyrikki-host-setup.sh`, POSIX `sh`,
wrapped in functions, ending with the `main` line that reads D16's
data lines, so a cut-off download does nothing. Nyyrikki serves it with
the values after it (OD3). It accepts only `--dry-run` and `--uninstall`;
everything else comes from the data lines, which it reads as text and
checks in full before it acts: every line must match `^[A-Z_]+=` and
its name's format (each CA key must parse with `ssh-keygen -l` and be
ed25519, each address must be a CIDR, names must be slugs), and one bad
line stops it before it changes a file. Before anything
else it prints the target, the accounts, whether it will grant sudo,
and the fingerprint of each CA key, to compare with
`ssh-keygen -lf nyyrikki-user-ca.pub` on the administrator's own copy.
The chart's `NOTES.txt` prints, per SSH target:

```sh
curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh
```

and the longer form for whoever wants to read or check it first:

```sh
curl -fsSL -o setup.sh https://nyyrikki.example.com/hosts/db-1/setup.sh
sed '/^main "\$@" <<.NYYRIKKI_VALUES_END.$/q' setup.sh | sha256sum   # equals the release's published checksum
sed '1,/^main "\$@" <<.NYYRIKKI_VALUES_END.$/d' setup.sh            # the data lines: read them
sudo sh setup.sh --dry-run && sudo sh setup.sh
```

What executes is exactly the checksummed part; the rest is data the
body checks, which the administrator can also read. (A file whose
checksummed part differs, or that has anything but data lines and the
terminator after it, is not Nyyrikki's script.)

The host must trust Nyyrikki's TLS certificate. If it is issued by a
private CA, the setup page says to pass `--cacert` with that CA, never
`-k`: a script fetched without checking the server can come from
anyone.

**Onboarding a host**, start to finish: add the target to the values
with empty `host_keys` and roll it out; run the command on the host;
copy the `host_keys` it prints into the values and roll out again. Runs
on the target are refused until then (§5.5).

## 6. Security considerations

- **Inputs.** `args` and `stdin`, attacker-controlled: joined and
  checked by D1, shown by D2, run as exactly that string. The host's
  responses: returned as they came (D10). The host key: checked against
  config (D8). The setup endpoint's path: one target name, checked
  against the registry; no query (D16). The setup script's values come
  from config, reach the host as data lines, never as code, and are
  checked again there before anything changes (D16, §5.7).
- **Dependency failures.** CA key unreadable, host unreachable, host key
  mismatch, authentication refused, session refused: each is
  `unavailable` before the command is sent, audited, with a test each.
  A cut that can't reach the host still closes the connection.
- **What reaches Telegram and the audit log.** The command string, as
  sent (D2); stdin only as size and hash, on Telegram and in the
  audit log (OD6, docs/03 D6); the remote
  account, address and the sudo marker. Never the CA key, a certificate,
  or a run's private key.
- **New ways to reach a target.** `run` and `/stream`, as for kubectl;
  the runner takes only a `Grant` whose digest matches. The setup
  endpoint reaches no target: it returns a script to whoever asks, and
  only a root administrator running it changes a host.
- **New unauthenticated path.** `/hosts/<target>/setup.sh` (D16). It
  reveals SSH target names, human IDs, the CA public key and Nyyrikki's
  source addresses to anyone who can reach `:8443`; the agents can read
  all of these in the config already (docs/01 OD7). It reads no secret.
- **Identity on the target.** `ny-<human>`, from the registry (D3). The
  host keeps the human's name in its auth log (M12) and sudo log (D7).
- **Credentials issued.** One certificate per run: one principal, one
  host, one source address, 2 minutes, no forwarding, a PTY only when
  interactive (D5). Its private key lives in memory for one run. There
  is nothing to revoke afterwards; a leaked CA is revoked by KRL (§5.6).
- **Blast radius.**
  - *The CA key* reaches every `ny-*` account on every host that trusts
    it, from `ssh.source_addresses` only (`from=` and `source-address`,
    D4, D5): root on every host set up with `sudo: true`. That
    restriction singles out Nyyrikki only if no agent shares the
    address. Under docs/01 OD7 the agents may run in Nyyrikki's
    cluster, where pod traffic usually leaves through the node's address
    or a shared NAT gateway; then the restriction stops use from outside
    that egress, not from an agent pod. The setup page recommends a
    dedicated egress address for Nyyrikki (an egress gateway or a fixed
    egress IP), and egress NetworkPolicies that keep agent pods off the
    hosts' SSH port. It sits next to the target tokens
    and the Telegram token in the pod (docs/01 D3); a Nyyrikki
    compromise already has those.
  - *An elevation on a `sudo: true` target* is up to 30 minutes of root
    on that host with no prompt per command (D12 tells the approver).
  - *The sudo marker comes from config*, not from the host. The setup
    script grants sudo exactly when the target says `sudo: true` (§5.7
    step 5), so they agree after setup. If someone later gives
    `ny-<human>` sudo by hand, or a command does, the approver is told
    less than is true; Nyyrikki can't check without running a command
    nobody approved.
  - *Whoever controls the pod controls the setup script* (OD3). An
    attacker there could serve a different script and get root on every
    host onboarded afterwards. The same attacker already holds the CA
    key, which is root on every host already set up with sudo. What
    executes is the fixed body, so its published checksum lets a careful
    administrator notice a changed script; the data lines after it are
    short and readable (§5.7).
- **Accepted risks, as for kubectl** (docs/04 OD3): an approved command,
  or one under an elevation, can do anything its account can. With
  sudo, that includes rewriting the host's SSH and sudo setup, adding a
  key or CA of its own, or installing a backdoor: INV-01 and INV-10 then
  no longer hold for that host. The defence is the approver reading the
  command. SECURITY.md (Accepted risks) gets this case when the doc is
  approved.
- **The setup script runs as root.** Its body is the same for every
  host, reviewed in the repo and checksummed per release; only the data
  lines differ, built from config and never executed (D16, M22).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 The command string is the joined `args`; NUL and control characters other than tab and newline are refused; an empty `args` is refused unless interactive; the display escapes bidi and zero-width characters | `TestSSHRequest*`, `TestSSHDisplayHostile` |
| G2 The runner refuses a `Grant` whose digest differs from the request, and the digest changes with each of target, account, command, stdin and the interactive flag | `TestSSHDigest*`, `TestSSHRunDigestMismatch` |
| G3 The certificate has exactly D5's principal, key ID, validity, `source-address` and extensions; its key is never written to disk, logged or returned | `TestMintCert`, `TestSSHNeverLeaksKey` (marker scan of logs, audit, results) |
| G4 A host key that matches no pin and no host CA, an expired host certificate, or one for another host name is refused before authentication, audited | `TestHostKey*` against an in-process SSH server |
| G5 No `env` request is sent; `pty-req` only for interactive runs, with a validated `TERM` | `TestSSHRunRequests` (in-process server records the requests) |
| G6 A cut sends `TERM`, then `KILL` after 2 s, then closes. On a host set up with session kill, a command that ignores `TERM`, run with and without sudo, and a process it detached with `setsid`, are gone within 10 s of the cut; the same when the host can't be reached at the cut (packets dropped), within 30 s; on a host without session kill, a plain command is gone and the message for a sudo target carries D12's warning | `TestSSHCut` (unit); e2e against an OpenSSH container |
| G7 End to end: an approved command runs as `ny-<human>` with sudo, the host's log shows key ID `nyyrikki:<run_id>`, and the result returns; a denied one never connects | e2e: Nyyrikki in kind, an OpenSSH container set up by the script |
| G8 The setup script: refuses each bad input and each failed check of §5.7 without changing a file; `sshd -t` failure rolls back; re-running is idempotent, including on a host it set up with session kill; `--uninstall` leaves no file; no plain key reaches `ny-<human>`, through its `authorized_keys` or through a global `AuthorizedKeysCommand`; the revocation list it writes takes §5.6's `ssh-keygen -k -u` | `test/ssh-host`: the script run in Debian, Ubuntu and Rocky containers |
| G9 The manual steps and the script produce the same files | `test/ssh-host`: a check that the files the script writes match the manual page's listing |
| G10 Messages show the account, the address, the sudo marker and the interactive marker; stdin appears only as size and hash with its warning, never as content (a marker secret on stdin is absent from every message) | `TestRenderSSH*` (docs/05 TG2's tests extended) |
| G11 An elevation covers an SSH target as it does a Kubernetes one, and an interactive session under it is cut at expiry | `TestElevation*` with an SSH target; e2e |
| G12 A real command on a real host, approved on a real phone, set up with the script | manual, by the owner |
| G13 The setup endpoint needs no token; refuses a query string and every method but `GET`; answers `404` alike for an unknown, a Kubernetes and a malformed target; its body equals the repo's file; the data lines hold only config values; a data line carrying shell syntax is refused by the body and never executed; each fetch is audited | `TestHostSetupEndpoint*`; the release workflow publishes the body's checksum |
| G14 "End now" appears on an interactive run's message once its stream attaches, for SSH and kubectl; a tap cuts the run and edits the message; a tap after the run ended, from another user, or replayed does nothing and is audited | `TestEndNowInteractive*` against the fake Bot API; e2e for one SSH and one kubectl session |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **SH1** | request, display, digest, config and validation, `list_targets` type | G1, G2 |
| **SH2** | CA key loading, certificate minting, host verification | G3, G4 |
| **SH3** | the runner, cut, interactive runs on `/stream` | G5, G6 (unit), G11 (unit) |
| **SH4** | messages and audit fields; "End now" on interactive runs, SSH and kubectl (D17); dated notes in docs/01, 02, 03, 04, 05, 06 and SECURITY.md | G10, G14 |
| **SH5** | the setup script, its endpoint, `docs/setup/ssh-hosts.md`, `test/ssh-host`; measures M14 and M15 first | G8, G9, G13 |
| **SH6** | chart (CA Secret mount, `NOTES.txt` commands), e2e with an OpenSSH container | G6 (e2e), G7, G11 (e2e), G12 |

SH1 lands first: everything else takes its request type. D17's kubectl
half doesn't depend on SSH and may land on its own first. SH5's script
can go in parallel; its endpoint needs SH1's config. SH6 needs all the others.

## 9. Risks and open questions

- **A shell command is opaque in ways an argv isn't**: `$(…)`, aliases
  and the account's shell startup files change what runs. The account is
  Nyyrikki's own (D3), so its startup files are what the setup left,
  unless an approved command changed them. The approver reads the
  string; that is D1's and docs/04 OD1's trade-off, unchanged.
- **Work moved out of the session outlives every cut** (D11): a service
  a command starts, a timer, a cron job, or anything on a host without
  session kill. An elevation's end stops what Nyyrikki started, not what
  that set up elsewhere.
- **Session kill changes two host-wide systemd settings**, limited by
  `KillOnlyUsers` to Nyyrikki's accounts, and a stop timeout of 5 s for
  every session scope on the host, which shortens how long other users'
  sessions get to exit when they are terminated or the host shuts down.
- **Multi-line commands and heredocs** may not fit one Telegram message
  (docs/05 D9 refuses them). A script too long to show has to be split
  into commands that fit: stdin can't carry it, since the approver
  wouldn't see it (OD6).
- **Hosts that already trust a CA** are refused by the script (§5.7
  step 1) and need a person to merge the setup; how common that is
  decides whether the script should learn to merge.
- **PAM-based distributions and locked accounts** (M7) were measured
  only without PAM; `*` avoids the question.
- **Rotating or revoking the CA means visiting every host** (§5.6).
  Fine for a handful; tedious and slow for many, and slow is what hurts
  after a leak. Two later improvements, outside this item
  (`ROADMAP.md` R11): hosts that pull their trusted keys and revocation
  list from Nyyrikki on a timer, accepting a new list only if a key they
  already trust signed it; and an external signer (Vault's SSH engine,
  step-ca, a KMS), so the CA key never sits in Nyyrikki's pod.

## 10. How it was implemented (YYYY-MM-DD)

<!-- Added during implementation. -->

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
