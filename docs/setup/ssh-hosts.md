# SSH hosts

Nyyrikki runs commands on a Linux host as `ny-<human>`, an account
that only its short-lived certificates can reach
([docs/07](../07-ssh-target.md)). The host needs OpenSSH 8.9 or newer,
and its `/etc/ssh/sshd_config` must start with
`Include /etc/ssh/sshd_config.d/*.conf` (Debian 12+, Ubuntu 22.04+,
RHEL 9+ and Alpine 3.22 ship it that way).

Nyyrikki never configures a host itself. An administrator sets each one
up with one setup command, which Nyyrikki serves. There are three ways
to bring a host on board, quickest first
([docs/08](../08-ssh-onboarding.md) D15):

1. [**Enroll**](#enroll-one-command-and-one-tap): one command on the
   host, one tap on Telegram. Nothing about the host goes into the
   values but its address.
2. [**Declarative**](#declarative-pins-or-your-host-ca-from-cloud-init-or-ansible):
   the host's keys, or your organisation's host CA, in the values, and
   the same setup command run from cloud-init or Ansible.
3. [**Manual**](#manual-setup): the files the script writes, by hand.

All three need the CA keys and the source address first.

## Before the first host

### The CA keys

Nyyrikki signs a certificate per run with a user CA key, and a
certificate per enrolled host with a host CA key. It keeps its CA keys
in one Secret, `nyyrikki-ssh-ca` (`secrets.sshCA.name`), mounted whole:
`user-ca`, `host-ca` (enrollment), and `user-ca-next` while a rotation
is staged. The public keys hosts trust are derived from them;
`ssh.userCAPublicKeys` holds only extra keys, if any (docs/08 D1).

**The chart makes the Secret.** On the first install or upgrade with an
SSH target, a hook Job creates it with fresh `user-ca` and `host-ca`
and prints only their fingerprints. It never overwrites a Secret that
exists, and Helm doesn't own it, so `helm uninstall` and `--force` leave
it (D16). To delete it:

```sh
kubectl -n nyyrikki delete secret -l nyyrikki.dev/release=nyyrikki,nyyrikki.dev/component=ssh-ca
```

**Or make it yourself**, with `ssh.generateCA: false`: on a machine no
agent runs on, run `nyyrikkid ssh-ca` from the image (or
`go run ./cmd/nyyrikkid` from a checkout). The keys pass only through
the pipe. Use `create`, never `apply`, so an existing Secret is not
overwritten:

```sh
docker run --rm -i ghcr.io/tuhis/nyyrikki:<version> ssh-ca init --namespace nyyrikki | kubectl create -f -
```

The commands that change an existing Secret (`stage`, `promote`,
`unstage`, `add-host-ca`) read it first and end in `kubectl replace`,
never `apply`: `replace` carries the `resourceVersion` read, so a
concurrent change fails instead of being overwritten, and it drops a key
the command removed, which `apply` could keep:

```sh
kubectl -n nyyrikki get secret nyyrikki-ssh-ca -o yaml | nyyrikkid ssh-ca add-host-ca | kubectl replace -f -
```

A Secret without `host-ca` (made by `ssh-ca` before it had one, by
External Secrets, or an R10 Secret not yet migrated) keeps enrollment
off: `enroll-token` refuses and says how to add one. With the chart's
CronJobs (`ssh.caJobs`) that is
`kubectl -n nyyrikki create job --from=cronjob/nyyrikki-ssh-ca-add-host-ca ssh-ca-add-host-ca-1`.

Rendering the chart without Helm (`helm template | kubectl apply`,
Kustomize's `helmCharts`) also needs `ssh.generateCA: false`: the hook
would become a plain Job, and its namespace-wide grant would stay.

**The hook's grant.** The install hook's ServiceAccount may create any
Secret in the namespace while the hook runs, and Helm deletes it
afterwards, after a failed Job too. If an install was interrupted or
timed out while the hook ran, or the release was uninstalled, check that
nothing is left, and delete what is:

```sh
kubectl -n nyyrikki get serviceaccount,role,rolebinding <release>-ssh-ca-init
kubectl -n nyyrikki delete serviceaccount,role,rolebinding <release>-ssh-ca-init
```

**Upgrading from an R10 release** that has `nyyrikki-ssh-user-ca`: set
`secrets.sshUserCA.name: nyyrikki-ssh-user-ca` in the values (it no
longer has a default), and migrate as `NOTES.txt` says, in this order
(D14):

1. `kubectl -n nyyrikki get secret nyyrikki-ssh-user-ca -o yaml | nyyrikkid ssh-ca import | kubectl -n nyyrikki create -f -`
2. remove that key from `ssh.userCAPublicKeys` and unset
   `secrets.sshUserCA`, in one rollout;
3. after it, delete `nyyrikki-ssh-user-ca`.

If step 1 fails with `AlreadyExists`, compare fingerprints: `import`
printed the old key's, and this prints the existing `user-ca`'s:

```sh
kubectl -n nyyrikki get secret nyyrikki-ssh-ca -o jsonpath='{.data.user-ca}' | base64 -d | ssh-keygen -lf /dev/stdin
```

Equal: the migration is already done. Different: `secrets.sshUserCA`
was unset first and the hook made a fresh CA no host trusts; delete
`nyyrikki-ssh-ca` and run step 1 again.

### The source address

The configuration also needs `ssh.sourceAddresses`: the address or
addresses Nyyrikki's connections to the hosts come from. Hosts accept
Nyyrikki's certificates only from there.

**Give Nyyrikki an egress address of its own.** The CA key reaches every
`ny-*` account on every host that trusts it, but only from
`ssh.sourceAddresses`. That singles out Nyyrikki only if nothing else
shares the address. In a cluster, pod traffic usually leaves through the
node's address or a shared NAT gateway, which agent pods share. Use an
egress gateway or a fixed egress IP for Nyyrikki's pod, and egress
NetworkPolicies that keep agent pods off the hosts' SSH port.

## Enroll: one command and one tap

A target needs only its name and address:

```yaml
targets:
  - name: db-1
    description: Primary database host
    humans: [owner]
    ssh:
      address: db-1.example.com   # port 22 unless given as host:port
      sudo: true                  # unset: ssh.defaults.sudo (false)
```

After the rollout, ask Nyyrikki's pod for a token. It prints the token,
valid 15 minutes for one enrollment, and the command to run on the host:

```sh
kubectl -n nyyrikki exec deploy/nyyrikki-nyyrikki -- nyyrikkid enroll-token db-1
#   curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh -s -- --enroll nye1.…
```

Only someone who may `kubectl exec` into Nyyrikki's pod can make a
token; the agents' cluster-wide read can't. On the host, paste the
command. It sets the host up (below), prints the host key's
fingerprint, and waits for the approval:

```
Enrolling with https://nyyrikki.example.com. This host's key:

    ED25519 SHA256:pr6TBeTH6wi8tgNTw+FSiVQrgmbG3FK9XV/QnVrxPTM

Approve on Telegram only if the message shows this same fingerprint. Waiting for the approval...
```

Every human of the target gets the enrollment message on Telegram, with
the fingerprint as the host sent it. **Approve only if it is the one
the host printed**: an approval makes Nyyrikki trust that key for the
target's address for five years (`ssh.hostCertValidity`). The approver
should be at the host's terminal, or in touch with whoever is.

On approval, Nyyrikki returns a host certificate. The script installs it
as `/etc/ssh/nyyrikki/ssh_host_ed25519_key-cert.pub`, names it in its
sshd drop-in (`HostCertificate`), checks with `sshd -t` and reloads
sshd; if sshd refuses it, the script removes both again. Then Nyyrikki
logs in once as each of the target's accounts, without running anything,
and the script prints the result per account. A refusal comes with a
hint: usually `ssh.sourceAddresses` doesn't hold the address Nyyrikki
connects from, or a principals file is missing.

A failed enrollment (denied, expired, no answer, a refused check) leaves
the host set up, and Nyyrikki refuses it until it is enrolled: run the
command again with a new token. Only an ed25519 host key can be
enrolled; a host without one is pinned instead (next section).

If Nyyrikki's TLS certificate comes from a private CA, pass it to both
`curl` and the script, which keeps it for the trust pull:

```sh
curl -fsSL --cacert nyyrikki-ca.crt https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh -s -- --cacert nyyrikki-ca.crt --enroll nye1.…
```

Never `-k`: a script fetched without checking the server can come from
anyone, and it runs as root.

To stop trusting an enrolled host (decommissioned, or its key leaked),
list its host key in `ssh.revokedHostKeys`. Changing a target's address
means enrolling it again. One machine can be enrolled for one target
only; for a second target, pin it.

## Declarative: pins or your host CA, from cloud-init or Ansible

Anyone who keeps everything in Git can leave enrollment out. The values
say how Nyyrikki verifies the host, either by its keys:

```yaml
targets:
  - name: db-1
    humans: [owner]
    ssh:
      address: db-1.example.com
      hostKeys:                   # the host's own public keys, without the comment
        - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
      sudo: true
      sessionKill: false          # as the setup reported
```

or by your organisation's host CA, once for every target
(`ssh.hostCAs`) or per target (`hostCAs`); the host's certificate must
name the host part of `address` among its principals. A key in
`ssh.revokedHostKeys` is never trusted. `sessionKill` is then the
value the setup reported; only a certificate from Nyyrikki's own
`host-ca` carries it (docs/08 D9).

The host runs the same setup command. Its output ends with the
`host_keys`, `sudo` and `session_kill` values for the target (`hostKeys`
and `sessionKill` in the chart's values), and the host keys'
fingerprints. With cloud-init, the host keys can be set in the
cloud-config itself, so the values can hold them before the host
exists:

```yaml
#cloud-config
ssh_keys:
  ed25519_private: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    …
  ed25519_public: ssh-ed25519 AAAAC3Nza… root@db-1
runcmd:
  - [sh, -c, "curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sh"]
```

With Ansible, fetch the script, then run it; the script brings the host
to what the values say on every run:

```yaml
- name: Fetch the Nyyrikki host setup
  ansible.builtin.get_url:
    url: "https://nyyrikki.example.com/hosts/{{ nyyrikki_target }}/setup.sh"
    dest: /root/nyyrikki-setup.sh
    mode: "0600"
    force: true
- name: Run the Nyyrikki host setup
  ansible.builtin.command: sh /root/nyyrikki-setup.sh
  register: nyyrikki_setup
  changed_when: false
```

Add `--cacert` to both for a private CA (`ca_path` for `get_url`). An
Ansible run fetches a fresh script each time; a setup script saved or
baked into an image is refused once the host has applied a newer trust
bundle (below).

Groups name sets of targets for an elevation (`groups: [{name: web,
targets: [web-1, web-2]}]`); an elevation asked for a group covers the
members it has at that moment.

## The setup command

Nyyrikki serves the script for each SSH target at
`/hosts/<target>/setup.sh`, with that target's values after it:

```sh
curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh
```

To read and check it first:

```sh
curl -fsSL -o setup.sh https://nyyrikki.example.com/hosts/db-1/setup.sh
sed '/^main "\$@" <<.NYYRIKKI_VALUES_END.$/q' setup.sh | sha256sum   # equals the release's published checksum
sed '1,/^main "\$@" <<.NYYRIKKI_VALUES_END.$/d' setup.sh            # the data lines: read them
sudo sh setup.sh --dry-run && sudo sh setup.sh
```

What executes is exactly the checksummed part, which is
`deploy/ssh-host/nyyrikki-host-setup.sh` in the repository at the release
tag, the trust pull included. The rest is data lines that the script
reads as text and checks before it changes anything:

```
TARGET=db-1
HUMAN=owner
CA_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO5pbSGm4zGRplE4S0iomxMC8EJyeD6coNQBlV+rPFky
SIGNER_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO5pbSGm4zGRplE4S0iomxMC8EJyeD6coNQBlV+rPFky
SOURCE=203.0.113.10/32
SUDO=true
ISSUED=1793491200000
URL=https://nyyrikki.example.com
END=8
NYYRIKKI_VALUES_END
```

`CA_KEY` lines are the user CA keys hosts trust; `SIGNER_KEY` lines the
keys that may sign trust bundles (`user-ca`, and `user-ca-next` while
staged), always among the `CA_KEY`s; `REVOKED_CA_KEY` lines (none here)
the keys of `ssh.revokedUserCAKeys`; `ISSUED` the server's time when it
served the script, in Unix milliseconds; `URL` where the host pulls from
and enrolls. A file whose checksummed part differs, or that has anything
other than data lines and the terminator after it, is not Nyyrikki's
script. The script prints the fingerprint of each CA key; compare it
with the fingerprints the hook Job or `ssh-ca` printed.

Options (with `curl | sudo sh`, pass them as `sudo sh -s -- --dry-run`):

| Option | |
|---|---|
| `--enroll TOKEN` | enroll the host after setting it up (above) |
| `--cacert FILE` | Nyyrikki's TLS CA, kept for the trust pull and used to enroll |
| `--reset-pull-state` | set the pull's mark to this script's `ISSUED` even if a newer bundle was applied; for the leak procedure (below) |
| `--dry-run` | print every check and every file, change nothing |
| `--status` | print what is installed, the pull's schedule, its last bundle, the signers and the host certificate; change nothing |
| `--uninstall` | remove everything (below) |

### What it does

1. **Checks**, and stops without changing anything if one fails: run as
   root; OpenSSH 8.9 or newer; the `Include` line comes first in
   `sshd_config`; `sshd -t` passes; no sshd configuration but Nyyrikki's
   sets `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` or
   `RevokedKeys`; on a systemd host, no logind configuration but
   Nyyrikki's sets `KillUserProcesses`, `KillOnlyUsers` or
   `KillExcludeUsers`; each `ny-*` account is either new, or one the
   script created and nobody changed since (password field `*`, shell
   `/bin/sh`, home `/home/ny-<human>` owned by it). An existing account it
   didn't create, or a `/home/ny-<human>` left without its account, is
   refused: a person has to sort it out. The script's `ISSUED` must be no
   more than 10 minutes ahead of the host's clock ("set the clock"), and
   not older than the last trust bundle the pull applied ("this setup
   script is older than the last bundle applied; fetch it again"; it
   prints the mark, and `--reset-pull-state` overrides it).
2. **Takes away** the sudo rules of humans removed from the target (and
   every one, if the target now has `sudo: false`), then their
   principals files, and adds each `REVOKED_CA_KEY` to the revocation
   list.
3. **Restricts**: sets the pull's mark (`pull.state`) to this script's
   `ISSUED`, writes the bundle signers, the trusted CA keys, a revocation
   list if there is none (with the revoked keys), and the sshd drop-in
   (with `HostCertificate` if the host is enrolled); checks with
   `sshd -t` and `sshd -T -C user=ny-<human>,…` that the drop-in's values
   are the effective ones; reloads sshd.
4. **Creates** the new accounts and writes each account's principals
   file.
5. **Removes** the accounts of humans no longer on the target, with their
   homes. An account with processes stops the run: end them first with
   `loginctl terminate-user ny-<human>`. If logind no longer knows the
   user (a `systemd --user` left after logind restarted), use
   `systemctl stop user@<uid>.service`; the message names both.
6. **Grants sudo**, if the target has `sudo: true`.
7. **Session kill**: on a Debian 13 or newer, or Ubuntu 22.04 or newer,
   host where systemd is PID 1 and sshd's PAM stack reaches
   `pam_systemd`, makes logind stop a `ny-*` account's session when its
   connection closes, so that a cut run's processes, root ones under
   sudo included, are gone within seconds. Other distributions report
   `session_kill: false` until this has been measured on them.
8. **Installs the trust pull** (next section): `pull.sh`, `pull.conf`,
   the `--cacert` file, and a schedule where a cron runs it.
9. **Prints** `pull: cron.d`, `periodic` or `none`, then the
   `host_keys`, `sudo` and `session_kill` lines for the target, and the
   host keys' fingerprints.
10. **Enrolls**, with `--enroll` (above).

If anything fails from step 2 to step 8, or the script gets `INT`,
`TERM` or `HUP`, it rolls back: every file it changed returns to what it
was, the accounts it created are deleted, and sshd and logind are
reloaded. What step 2 took away stays away, since the target no longer
grants it. If the script is killed in a way it can't catch, every state
between steps still fails closed; run it again, or run `--uninstall`.
Enrollment (step 10) comes after all that: it never undoes steps 2 to 9.

Run the command again whenever the target's humans, source addresses or
`sudo` change: the pull never adds access. Re-running is safe: it brings
the host to what the values say. The script and the pull take the same
lock (`flock` on `/run/nyyrikki-ssh.lock`, which needs util-linux's or
BusyBox's `flock`), so they never change the trust files at once.

**Turning `sudo` off doesn't undo root an account already used.** A
re-run with `sudo: false` removes Nyyrikki's sudoers file, and refuses
an account it finds with UID 0, in a root-equivalent group (root, sudo,
wheel, admin, docker, lxd, incus, disk), or named in another sudoers
file. A sudoers rule for `ALL` users blocks the setup on every run, a
first one included: it would give each `ny-*` account more than the
setup does. That check is best effort: a command that ran as root could have
kept root in ways it can't see (a key in root's `authorized_keys`, a
setuid binary, a cron job). Treat a host that had `sudo: true` as
possibly still giving root to its `ny-*` accounts until they are made
again: run `--uninstall`, then the setup.

### Uninstalling

```sh
curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh -s -- --uninstall
```

It removes the pull's schedule first, then every Nyyrikki sudoers and
principals file, then the accounts and their homes (it stops if one has
processes: end them with `loginctl terminate-user ny-<human>`, or the
`systemctl stop user@<uid>.service` the message names, and run it
again), the logind and session-scope drop-ins, the sshd drop-in (and with
it the `HostCertificate` line), and `/etc/ssh/nyyrikki` with the pull,
its state, the signers, the CA file and the host certificate; and it
reloads sshd and logind.

It refuses, changing nothing, if `sshd -t` fails first. If it is
Nyyrikki's drop-in that sshd rejects (a newer OpenSSH dropping a
keyword), remove it by hand, check and reload, then run `--uninstall`:

```sh
rm /etc/ssh/sshd_config.d/50-nyyrikki.conf && sshd -t && systemctl reload ssh   # sshd on RHEL-family hosts
```

`/etc/ssh/nyyrikki` is removed only after sshd has reloaded without the
drop-in, since sshd refuses every key login while its `RevokedKeys` file
is missing.

## The trust pull

A host with cron keeps up with CA rotations, revocations and removed
humans on its own (docs/08 D5). Every 15 minutes, `pull.sh` fetches the
target's trust bundle from `<URL>/hosts/<target>/trust` with `curl`,
checks its signature with `ssh-keygen -Y verify` against the signers the
setup wrote (`signers.pub`, minus any key in the revocation list),
checks every line, and requires the bundle to be this target's, issued
after the last one applied, and no more than 10 minutes ahead of the
host's clock. Then it applies, taking access away first:

- each `REVOKED_CA_KEY` goes into the revocation list;
- the principals and sudoers files of accounts whose human is no longer
  on the target are removed (the account stays until the setup runs);
- with `SUDO=false`, every Nyyrikki sudoers file is removed;
- last, `user_ca.pub` and `signers.pub` are replaced.

It never reloads sshd, which reads those files at each login. It never
creates an account, writes a principals file for a new human, grants
sudo or changes `from=`: for those it logs "re-run the setup to add …".
The signers may change only by a **stage** (the new set adds keys, signed
by a key the host has) or a **promote** (the new set drops keys, signed
by a key it keeps); any other change refuses the whole bundle. Every
signer change is logged with the old and new fingerprints. On any
failure it changes nothing more, logs, and exits non-zero, so cron mails
root. It logs through `logger -t nyyrikki` (syslog or the journal) where
`logger` exists.

The setup installs the schedule where it finds a cron that runs it:

- `/etc/cron.d/nyyrikki`, mode 0644, where `/etc/cron.d` exists and a
  `cron` or `crond` other than BusyBox's is installed (Debian's `cron`,
  RHEL's `cronie`). The minute is taken from the target name, so hosts
  don't all pull at once.
- `/etc/periodic/15min/nyyrikki-pull`, mode 0755, where
  `/etc/periodic/15min` exists and root's crontab runs it (Alpine's
  BusyBox `crond`, which ignores `/etc/cron.d`).
- Nothing otherwise, and without `curl` (BusyBox `wget` can't be given a
  CA file): the script prints `pull: none`. Such a host takes up changes
  when the setup runs again, or when `/etc/ssh/nyyrikki/pull.sh` is run by
  hand.

`sudo sh setup.sh --status` shows the schedule, the last bundle applied
(when it was issued and when the pull applied it) and the current
signers. The audit log's `host_trust_served` records show which targets
have fetched a bundle lately; a fetch is not an apply, so check
`--status` on a host in doubt. A host whose clock runs more than 10
minutes behind Nyyrikki's refuses every bundle, and the setup refuses
too, both naming the clock: hosts need NTP.

## Rotating the CA

Rotation changes the Secret, never the values, and needs no rollout:
Nyyrikki reads the keys on each use (docs/08 §5.4). With the chart's
CronJobs (`ssh.caJobs`):

1. **Stage**: `kubectl -n nyyrikki create job --from=cronjob/nyyrikki-ssh-ca-stage ssh-ca-stage-1`,
   or, for keys kept outside the chart,
   `kubectl -n nyyrikki get secret nyyrikki-ssh-ca -o yaml | nyyrikkid ssh-ca stage | kubectl replace -f -`.
   Within a minute or two the pod sees `user-ca-next`, and the bundles
   trust both keys. Hosts with a pull trust both within 15 minutes;
   `host_trust_served` in the audit shows which targets have fetched.
   Re-run the setup by hand on hosts without a pull.
2. **Promote**: `kubectl -n nyyrikki create job --from=cronjob/nyyrikki-ssh-ca-promote ssh-ca-promote-1`,
   or `… | nyyrikkid ssh-ca promote | kubectl replace -f -`. Nyyrikki
   signs runs and bundles with the new key; the old key drops out of the
   bundles, and the pulls stop trusting it. The Job's log shows the old
   public key. **Promote only after every target has fetched a bundle
   issued after the stage** (`host_trust_served`), and re-run the setup
   on the rest first. A fetch is not an apply: a host whose pull refused
   the bundle still shows as fetched, so check `--status` on any host in
   doubt.

**Undoing a stage**: `kubectl -n nyyrikki create job --from=cronjob/nyyrikki-ssh-ca-unstage ssh-ca-unstage-1`,
or `… | nyyrikkid ssh-ca unstage | kubectl replace -f -`, removes
`user-ca-next`. The next bundle, signed by `user-ca`, drops it (a
promote). Stage again only after every target has fetched a bundle
issued after the unstage, as before a promote.

**A host that misses steps**: one that missed step 1 can't check bundles
signed by the new key. One that missed step 2 and then the next stage
has `{A,B}` and is offered `{B,C}`, which is neither a stage nor a
promote, so it refuses. One that missed an unstage and then a new stage
has `{A,B}` and is offered `{A,C}`: refused for the same reason. All
fail loudly; re-run their setup.

### After a leak

A leak of `user-ca`, or of a staged `user-ca-next` (a signer on every
host since the stage, so its holder can do what a `user-ca` holder can):

1. For `user-ca-next`: unstage it and list it in
   `ssh.revokedUserCAKeys`. For `user-ca`: stage and promote (steps 1 and
   2 above, with the promote's gate), then add the old public key
   (printed by `promote`, in its log) to `ssh.revokedUserCAKeys`. Roll
   out. Hosts with a pull add it to their revocation list within 15
   minutes, and that stops the leaked key.
2. **Re-run the setup on every host with `--reset-pull-state`.** The
   revocation doesn't undo what the leaked key may already have signed:
   a bundle signed with it could have added the holder's own CA and
   signer (a stage) before the revocation, and that key is not in
   `ssh.revokedUserCAKeys`. The re-run rewrites `user_ca.pub` and
   `signers.pub` from the values, and `--reset-pull-state` sets the mark
   to the script's `ISSUED` even when a bundle the leaked key signed set
   it just ahead:

   ```sh
   curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh -s -- --reset-pull-state
   ```

   If the setup refuses because the host's revocation list lists a key
   the values trust (the leaked key can have revoked the staged one
   through a bundle), rebuild the list, then run the setup again. The
   re-run adds every `ssh.revokedUserCAKeys` back itself, so the new list
   needs only the keys you revoked by hand, if any; with none, it starts
   empty. `ssh-keygen -Q -l -f /etc/ssh/nyyrikki/revoked.krl` shows what
   the list holds now. Hold the lock the setup and the pull take, so a
   pull can't write the old list back meanwhile:

   ```sh
   sudo flock /run/nyyrikki-ssh.lock sh -c '
     ssh-keygen -k -f /etc/ssh/nyyrikki/revoked.krl.new hand-revoked.pub &&
     chmod 0644 /etc/ssh/nyyrikki/revoked.krl.new &&
     mv /etc/ssh/nyyrikki/revoked.krl.new /etc/ssh/nyyrikki/revoked.krl'
   ```

   (Leave out `hand-revoked.pub` to start empty.)

The pull recovers a host from the revocation of extra keys, not from a
leak of a key that was ever a signer. `--status` and the `logger` lines
show a host whose signers changed unexpectedly.

For an immediate stop on one host, before any rollout, add the leaked
public key to its revocation list by hand, and check it:

```sh
ssh-keygen -k -u -f /etc/ssh/nyyrikki/revoked.krl old-user-ca.pub
ssh-keygen -Q -f /etc/ssh/nyyrikki/revoked.krl old-user-ca.pub
```

Every certificate it signed is refused at once, Nyyrikki's included, and
the host's pull refuses bundles it signed.

## Manual setup

These are the files the script writes, for the sample values above
(target `db-1`, human `owner`, `sudo: true`). Every file is owned by
root; directories are mode 0755. Write them in this order, so that every
state on the way fails closed.

The pull's mark: the `ISSUED` of the setup (the `--status` of a host
shows it). The pull refuses every bundle issued before it:

<!-- file: /etc/ssh/nyyrikki/pull.state 0644 -->
```
ISSUED=1793491200000
BY=setup
```

The keys that may sign the trust bundles the pull applies (the
`SIGNER_KEY` data lines):

<!-- file: /etc/ssh/nyyrikki/signers.pub 0644 -->
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO5pbSGm4zGRplE4S0iomxMC8EJyeD6coNQBlV+rPFky
```

The trusted CA keys, one `ssh-ed25519` line per trusted key: the CA
Secret's `user-ca`, its `user-ca-next` if staged, then the extra keys of
`ssh.userCAPublicKeys`, minus `ssh.revokedUserCAKeys` (the
`CA_KEY` data lines):

<!-- file: /etc/ssh/nyyrikki/user_ca.pub 0644 -->
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO5pbSGm4zGRplE4S0iomxMC8EJyeD6coNQBlV+rPFky
```

A revocation list, if there is none yet, with the keys of
`ssh.revokedUserCAKeys` if any (a file of their `ssh-ed25519` lines at
the end of the command). Make it with `ssh-keygen`, never as an empty
file, which `ssh-keygen -k -u` refuses. An existing list is kept; add
revoked keys to it with `ssh-keygen -k -u -f`:

```sh
ssh-keygen -k -f /etc/ssh/nyyrikki/revoked.krl && chmod 0644 /etc/ssh/nyyrikki/revoked.krl
```

The sshd drop-in, with a `Match User` block for each account. An
enrolled host also has the line
`HostCertificate /etc/ssh/nyyrikki/ssh_host_ed25519_key-cert.pub` right
after `RevokedKeys`, before any `Match` block:

<!-- file: /etc/ssh/sshd_config.d/50-nyyrikki.conf 0644 -->
```
# Written by the Nyyrikki host setup (docs/07-ssh-target.md 5.7, D3, D4).
# Re-run the setup to change it; --uninstall removes it.
TrustedUserCAKeys /etc/ssh/nyyrikki/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/nyyrikki/principals/%u
RevokedKeys /etc/ssh/nyyrikki/revoked.krl

Match User ny-owner
	AuthenticationMethods publickey
	AuthorizedKeysFile none
	AuthorizedKeysCommand none
	AuthorizedKeysCommandUser nobody
	AuthorizedPrincipalsCommand none
	AuthorizedPrincipalsCommandUser nobody
	PasswordAuthentication no
	KbdInteractiveAuthentication no
	HostbasedAuthentication no
	GSSAPIAuthentication no
	ClientAliveInterval 5
	ClientAliveCountMax 3
```

Check it, and check that its values are the effective ones (another
file whose values win shows up here), then reload sshd:

```sh
sshd -t
sshd -T -C user=ny-owner,host=203.0.113.10,addr=203.0.113.10 | grep -E '^(authenticationmethods|authorizedkeys|authorizedprincipals|permituserenvironment|passwordauth|kbdinteractive|hostbased|gssapiauth|clientalive|trustedusercakeys|revokedkeys) '
systemctl reload ssh     # sshd on RHEL-family hosts
```

The list of accounts Nyyrikki owns, one per line. Add an account here
before creating it:

<!-- file: /etc/ssh/nyyrikki/accounts 0644 -->
```
ny-owner
```

The account, with password field `*` (`!` would lock it), shell
`/bin/sh` and its own home:

```sh
useradd -m -d /home/ny-owner -s /bin/sh -U -p '*' -c 'Nyyrikki account of owner' ny-owner
```

Its principals file, in `/etc/ssh/nyyrikki/principals/` (mode 0755).
`from=` lists `ssh.sourceAddresses`, comma-separated:

<!-- file: /etc/ssh/nyyrikki/principals/ny-owner 0644 -->
```
restrict,pty,from="203.0.113.10/32" nyyrikki:owner@db-1
```

Only for a target with `sudo: true`, the sudoers file. Check it with
`visudo -cf` before putting it in place:

<!-- file: /etc/sudoers.d/50-nyyrikki-ny-owner 0440 -->
```
Defaults:ny-owner !requiretty
ny-owner ALL=(ALL) NOPASSWD: ALL
```

Session kill, only on a host where it was measured (Debian 13 or newer,
Ubuntu 22.04 or newer, systemd as PID 1, `UsePAM yes`, `pam_systemd` in
sshd's PAM session stack) and where no other logind file sets these values. `KillOnlyUsers`
lists every account, space-separated:

<!-- file: /etc/systemd/logind.conf.d/50-nyyrikki.conf 0644 -->
```
# Written by the Nyyrikki host setup (docs/07-ssh-target.md 5.7, D11).
[Login]
KillUserProcesses=yes
KillOnlyUsers=ny-owner
```

<!-- file: /etc/systemd/system/session-.scope.d/50-nyyrikki.conf 0644 -->
```
# Written by the Nyyrikki host setup (docs/07-ssh-target.md 5.7, D11).
[Scope]
TimeoutStopSec=5s
```

```sh
systemctl daemon-reload && systemctl restart systemd-logind
busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses   # b true
```

The scope timeout applies to every session on the host: other users'
sessions get 5 s, not 90, to exit when they are ended or the host shuts
down.

The trust pull. `pull.sh` is the part of the setup script between the
lines `cat >"$1" <<'NYYRIKKI_PULL_END'` and `NYYRIKKI_PULL_END`; take it
from a script you checked as above:

<!-- file-from-script: /etc/ssh/nyyrikki/pull.sh 0755 -->
```sh
awk '/^NYYRIKKI_PULL_END$/ { p = 0 } p; /<<.NYYRIKKI_PULL_END.$/ { p = 1 }' setup.sh > pull.sh
install -o root -g root -m 0755 pull.sh /etc/ssh/nyyrikki/pull.sh
```

What it reads: the `URL` and `TARGET` data lines, and, with a private
CA, the line `CACERT=/etc/ssh/nyyrikki/server-ca.pem` before `END` (then
`END=3`) and that CA file, mode 0644:

<!-- file: /etc/ssh/nyyrikki/pull.conf 0644 -->
```
URL=https://nyyrikki.example.com
TARGET=db-1
END=2
```

Last, its schedule, only where a cron runs it (above). On a host with a
cron that reads `/etc/cron.d` (not BusyBox's), with the minute (here
13) anywhere from 0 to 14:

<!-- file: /etc/cron.d/nyyrikki 0644 -->
```
# Written by the Nyyrikki host setup (docs/08-ssh-onboarding.md D5): the
# trust pull, every 15 minutes. Re-run the setup to change it; --uninstall removes it.
13-59/15 * * * * root /etc/ssh/nyyrikki/pull.sh
```

On a host whose root crontab runs `/etc/periodic/15min` (Alpine):

<!-- file: /etc/periodic/15min/nyyrikki-pull 0755 -->
```
#!/bin/sh
# Written by the Nyyrikki host setup (docs/08-ssh-onboarding.md D5): the
# trust pull, every 15 minutes. Re-run the setup to change it; --uninstall removes it.
exec /etc/ssh/nyyrikki/pull.sh
```

For a host verified by its keys, put the host's own public keys
(`/etc/ssh/ssh_host_*_key.pub`, without the comment) into the target's
`hostKeys`, and set `sessionKill: true` if you set up session kill. To
enroll a hand-made host, run the setup command with `--enroll`; it
finds its own files in place.

## Alpine

Alpine 3.22 works with the packages `openssh`, `shadow` (for `useradd`
and `userdel`), `sudo` (for `sudo: true`) and `curl` (for the pull):

```sh
apk add openssh shadow sudo curl
```

Its `sshd_config` already starts with the `Include` line, and its sudo
reads `/etc/sudoers.d`. sshd runs without PAM there, so session kill is
off (`sessionKill: false`), and the account's password field `*` keeps
it unlocked for key logins, where `!` (`adduser -D`) would lock it. The
pull runs from `/etc/periodic/15min`, which BusyBox `crond` runs through
root's stock crontab; `crond` must be running (`rc-update add crond`).
