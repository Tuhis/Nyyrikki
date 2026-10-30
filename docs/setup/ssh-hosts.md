# SSH hosts

Nyyrikki runs commands on a Linux host as `ny-<human>`, an account
that only its short-lived certificates can reach
([docs/07](../07-ssh-target.md)). The host needs OpenSSH 9.0 or newer,
and its `/etc/ssh/sshd_config` must start with
`Include /etc/ssh/sshd_config.d/*.conf` (Debian 12+, Ubuntu 22.04+ and
RHEL 9+ ship it that way).

Nyyrikki never configures a host itself. An administrator sets each one
up, with the setup script or by hand. Both write the same files, listed
under [Manual setup](#manual-setup).

## The user CA

Nyyrikki signs a certificate per run with a user CA key that you create
once. Do it on a machine no agent runs on, in a temporary directory that
is removed afterwards:

```sh
d=$(mktemp -d) && chmod 700 "$d"
ssh-keygen -q -t ed25519 -N '' -C nyyrikki-user-ca -f "$d/user-ca"
kubectl -n nyyrikki create secret generic nyyrikki-ssh-user-ca --from-file=user-ca="$d/user-ca"
cat "$d/user-ca.pub"     # goes into ssh.user_ca_public_keys
rm -rf "$d"
```

Not in a pod with `kubectl run -i`: what such a pod prints is kept as its
container log, which the agents can read.

The configuration also needs `ssh.source_addresses`: the address or
addresses Nyyrikki's connections to the hosts come from. Hosts accept
Nyyrikki's certificates only from there.

**Give Nyyrikki an egress address of its own.** The CA key reaches every
`ny-*` account on every host that trusts it, but only from
`ssh.source_addresses`. That singles out Nyyrikki only if nothing else
shares the address. In a cluster, pod traffic usually leaves through the
node's address or a shared NAT gateway, which agent pods share. Use an
egress gateway or a fixed egress IP for Nyyrikki's pod, and egress
NetworkPolicies that keep agent pods off the hosts' SSH port.

## Onboarding a host

1. Add the target to the values with empty `host_keys` and roll out:

   ```yaml
   targets:
     - name: db-1
       description: Primary database host
       humans: [owner]
       ssh:
         address: db-1.example.com:22
         host_keys: []
         host_cas: []
         sudo: true
   ```

   Runs on the target are refused until its host keys are pinned.
2. On the host, run the setup command (next section).
3. Copy the `host_keys` and `session_kill` it prints into the target's
   `ssh` block and roll out again.

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
tag. The rest is data lines that the script reads as text and checks
before it changes anything:

```
TARGET=db-1
HUMAN=owner
CA_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO5pbSGm4zGRplE4S0iomxMC8EJyeD6coNQBlV+rPFky
SOURCE=203.0.113.10/32
SUDO=true
END=5
NYYRIKKI_VALUES_END
```

A file whose checksummed part differs, or that has anything other than
data lines and the terminator after it, is not Nyyrikki's script. The
script prints the fingerprint of each CA key; compare it with
`ssh-keygen -lf` of your `user-ca.pub`.

The host must trust Nyyrikki's TLS certificate. If it comes from a
private CA, pass that CA with `--cacert`:

```sh
curl -fsSL --cacert nyyrikki-ca.crt https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh
```

Never `-k`: a script fetched without checking the server can come from
anyone, and it runs as root.

The script accepts two options, `--dry-run` (print every check and every
file, change nothing) and `--uninstall`. With `curl | sudo sh`, pass them
as `sudo sh -s -- --dry-run`.

### What it does

1. **Checks**, and stops without changing anything if one fails: run as
   root; OpenSSH 9.0 or newer; the `Include` line comes first in
   `sshd_config`; `sshd -t` passes; no sshd configuration but Nyyrikki's
   sets `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` or
   `RevokedKeys`; on a systemd host, no logind configuration but
   Nyyrikki's sets `KillUserProcesses`, `KillOnlyUsers` or
   `KillExcludeUsers`; each `ny-*` account is either new, or one the
   script created and nobody changed since (password field `*`, shell
   `/bin/sh`, home `/home/ny-<human>` owned by it). An existing account it
   didn't create, or a `/home/ny-<human>` left without its account, is
   refused: a person has to sort it out.
2. **Takes away** the sudo rules of humans removed from the target (and
   every one, if the target now has `sudo: false`), then their
   principals files.
3. **Restricts**: writes the trusted CA keys, an empty revocation list
   if there is none, and the sshd drop-in; checks with `sshd -t` and
   `sshd -T -C user=ny-<human>,…` that the drop-in's values are the
   effective ones; reloads sshd.
4. **Creates** the new accounts and writes each account's principals
   file.
5. **Removes** the accounts of humans no longer on the target, with their
   homes. An account with processes stops the run: end them first with
   `loginctl terminate-user ny-<human>`. If logind no longer knows the
   user (a `systemd --user` left after logind restarted), use
   `systemctl stop user@<uid>.service`; the message names both.
6. **Grants sudo**, if the target has `sudo: true`.
7. **Session kill**: on a Debian 13 or newer host where systemd is PID 1
   and sshd's PAM stack reaches `pam_systemd`, makes logind stop a
   `ny-*` account's session when its connection closes, so that a cut
   run's processes, root ones under sudo included, are gone within
   seconds. Other distributions report `session_kill: false` until this
   has been measured on them.
8. **Prints** the `host_keys`, `sudo` and `session_kill` lines for the
   target, and the host keys' fingerprints.

If anything fails from step 2 on, or the script gets `INT`, `TERM` or
`HUP`, it rolls back: every file it changed returns to what it was, the
accounts it created are deleted, and sshd and logind are reloaded. What
step 2 took away stays away, since the target no longer grants it. If
the script is killed in a way it can't catch, every state between steps
still fails closed; run it again, or run `--uninstall`.

Run the command again whenever the target's humans, CA keys, source
addresses or `sudo` change, and on every host during a CA rotation.
Re-running is safe: it brings the host to what the values say.

### Uninstalling

```sh
curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh -s -- --uninstall
```

It removes every Nyyrikki sudoers and principals file, then the accounts
and their homes (it stops if one has processes: end them with
`loginctl terminate-user ny-<human>`, or the
`systemctl stop user@<uid>.service` the message names, and run it again), the logind and
session-scope drop-ins, the sshd drop-in, and `/etc/ssh/nyyrikki`, and
reloads sshd and logind.

## Manual setup

These are the files the script writes, for the sample values above
(target `db-1`, human `owner`, `sudo: true`). Every file is owned by
root; directories are mode 0755. Write them in this order, so that every
state on the way fails closed.

The trusted CA keys, one `ssh-ed25519` line per key of
`ssh.user_ca_public_keys`:

<!-- file: /etc/ssh/nyyrikki/user_ca.pub 0644 -->
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO5pbSGm4zGRplE4S0iomxMC8EJyeD6coNQBlV+rPFky
```

An empty revocation list, if there is none yet. Make it with
`ssh-keygen`, never as an empty file, which `ssh-keygen -k -u` refuses:

```sh
ssh-keygen -k -f /etc/ssh/nyyrikki/revoked.krl && chmod 0644 /etc/ssh/nyyrikki/revoked.krl
```

The sshd drop-in, with a `Match User` block for each account:

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
sshd -T -C user=ny-owner,host=203.0.113.10,addr=203.0.113.10 | grep -E '^(authenticationmethods|authorizedkeys|passwordauth|kbdinteractive|hostbased|gssapiauth|clientalive|trustedusercakeys|authorizedprincipalsfile|revokedkeys) '
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
`from=` lists `ssh.source_addresses`, comma-separated:

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
systemd as PID 1, `UsePAM yes`, `pam_systemd` in sshd's PAM session
stack) and where no other logind file sets these values. `KillOnlyUsers`
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

Last, put the host's own public keys (`/etc/ssh/ssh_host_*_key.pub`,
without the comment) into the target's `host_keys`, and set
`session_kill: true` if you set up session kill.

## Rotating the CA

Planned, in three rollouts:

1. Create a new key pair as above, but keep the private key aside, not
   yet in the Secret. Add the new public key to `user_ca_public_keys`,
   next to the old one, and roll out. Re-run the setup command on every
   host: each now trusts both keys.
2. Put the new private key into the Secret. Nyyrikki signs with it from
   the next run on.
3. Remove the old public key from `user_ca_public_keys`, roll out, and
   re-run the setup command on every host.

After a leak, revoke first, then rotate:

1. On every host, add the leaked public key to the revocation list, and
   check it:

   ```sh
   ssh-keygen -k -u -f /etc/ssh/nyyrikki/revoked.krl old-user-ca.pub
   ssh-keygen -Q -f /etc/ssh/nyyrikki/revoked.krl old-user-ca.pub
   ```

   Every certificate it signed is refused at once, Nyyrikki's included:
   SSH runs fail until step 2.
2. Create a new key pair, put it into the Secret and make it the only
   key in `user_ca_public_keys`, roll out, and re-run the setup command
   on every host. The script keeps an existing revocation list.

Both touch every host.
