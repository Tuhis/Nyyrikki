# Gotchas

Hard-won lessons, each of which cost real debugging time. This file is the
consolidated list. The details live in the linked design docs. The rule in
[CLAUDE.md](../CLAUDE.md) is that a gotcha has exactly one home, here,
rather than being restated in the doc that discovered it.

The entries below were found while writing the design docs of the
replaced Warden plan (2026-10-25). They are facts about Kubernetes, Go,
Telegram, Keycloak and MCP clients, so they still apply. Their links
point to those docs as of the commit they were written in, where the
evidence is. The measurements behind them are also in
[`measured.md`](measured.md).

Add to it when a new gotcha lands in `docs/`. Group entries under a bold
heading per area, one bullet each: the trap, why it bites, and a link to
the doc.

---

**Kubernetes**

- **`RequestInfo` doesn't produce `exec`, `attach`, `portforward` or
  `proxy` verbs.** It reports the HTTP-method verb plus the
  subresource, so a WebSocket exec is `get pods` with subresource
  `exec`, and it passes as a read unless the verb is overridden.
  ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M1, D4)
- **kubectl ≥ 1.30 retries over SPDY after any refused WebSocket
  upgrade**, a 403 included. Every exec denial shows up twice, and SPDY
  must be refused as well. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M3)
- **Before 1.35, the apiserver has no `create` check for WebSocket
  exec.** On those versions, `get pods/exec` alone permits exec, so a
  broad `get *` RBAC role grants it. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md)
  M5, OD1)
- **For `nodes/<n>/proxy/<path>`, the proxied path only appears in
  `RequestInfo.Parts`**, not in `Name` or `Subresource`, so policy can't
  see it. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M2)
- **Every impersonated user is also in `system:authenticated`.** The
  apiserver adds the group itself, so anything a cluster binds to it is
  part of every profile's RBAC. ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M9)
- **`SelfSubjectRulesReview` never comes back empty, and it sees one
  namespace.** Every identity gets the bootstrap discovery and
  self-review rules, and `spec.namespace` is required, so a RoleBinding
  in a namespace you didn't ask about is invisible.
  ([docs/07](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/07-kubernetes-proxy.md) M10, D11)
- **A RoleBinding can name a ServiceAccount as `kind: User`**, with the
  username `system:serviceaccount:<ns>:<name>`. An audit that looks only
  for `kind: ServiceAccount` subjects misses it.
  ([docs/09](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/09-packaging-and-deployment.md) §5.4)
- **Client-side `kubectl apply` copies the whole object into the
  `kubectl.kubernetes.io/last-applied-configuration` annotation**, as a
  JSON string. Redacting a Secret's `data` but keeping its metadata
  still leaks the values through it. ([docs/03](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/03-audit-log.md) §5.9)

- **kubectl ≥ 1.33 reads a kuberc preferences file** (`~/.kube/kuberc`,
  or `$KUBERC`) that can define aliases and default flags, so the same
  argv can mean something else on another machine. Turn it off with
  `KUBERC=off` and refuse `--kuberc`. ([docs/04](04-kubectl-passthrough.md) M3)
- **kubectl reads files and URLs from the machine it runs on**: `-f`
  paths and URLs, `-k`, `--from-file`, `--from-env-file`,
  `-o jsonpath-file=`, `debug --custom`. Server-side, those are
  Nyyrikki's disk. ([docs/04](04-kubectl-passthrough.md) M7)

**Go: TLS and HTTP**

- **`tls.Config.VerifyPeerCertificate` is not called on resumed
  connections.** Revocation checks belong in `VerifyConnection`, which
  runs on every connection, and in a per-request check, because a
  kept-alive connection outlives a revocation.
  ([docs/02](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/02-grant-core.md) M2, D7)
- **`httputil.ReverseProxy.Director` can be defeated by the client**,
  which can list any header in `Connection` and so strip headers the
  proxy added. Use `Rewrite`. ([docs/06](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/06-http-proxy.md) M1)
- **`http.DefaultTransport` honours `HTTP(S)_PROXY`.** Upstream
  transports need `Proxy: nil`, or an environment variable on G can
  redirect privileged traffic. ([docs/06](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/06-http-proxy.md) M2)
- **`url.PathEscape("..")` is `".."`.** A dot-segment check on raw
  segments, followed by decoding and re-encoding, forwards `%2e%2e` as a
  literal `..`. Decode first, then check. ([docs/06](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/06-http-proxy.md)
  M4)

**Telegram Bot API**

- **`callback_data` is client-controlled.** A modified client can send
  any bytes for any message it can see, so it can only ever be an opaque
  key to server-side state. ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M2)
- **`getUpdates` fails while a webhook is set.** Unconfirmed updates are
  kept for only 24 h, and a crash between processing an update and
  confirming it redelivers it. ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M5)
- **A `409 Conflict` from `getUpdates` means someone else is using the
  token**, through a webhook or a second poller. Backing off and
  retrying hands them the approvals. Stop instead.
  ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M17)
- **Bots can delete only messages younger than 48 h, but can edit
  without a time limit.** Retire prompts by editing them.
  ([docs/04](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/04-telegram-escalation.md) M8)

**Keycloak**

- **`PUT …/users/{id}/reset-password` sends the new password as a bare
  `{"type":"password","value":"…"}`**, with `value` at the root, so
  redacting only `credentials[].value` leaks it.
  ([docs/03](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/03-audit-log.md) §5.9)
- **`sid` is the browser's SSO session, not one sign-in.** Every sign-in
  in the same browser session shares it, and very likely so does a
  sign-in that made the user authenticate again (`prompt=login`, or no
  Cookie authenticator). Keying an agent on it merges sign-ins.
  ([docs/01](01-foundations.md) OD14)

- **Keycloak 26.8 introspects a token only for a client in the token's
  audience.** Any other client gets `active: false`, logged as `Client '…'
  is not in the token audience`, which looks exactly like a revoked
  session. Name the introspection client after the resource's audience.
  ([docs/01](01-foundations.md) M9, D7)
- **Keycloak's default `roles` client scope adds `account` to `aud`**
  (through its audience-resolve mapper), so a resource that requires a
  single audience refuses every token. Remove the scope from the clients.
  ([docs/01](01-foundations.md) M9)
- **A client registered through DCR gets the realm's default scopes**,
  not the ones a client set up by hand has. Take `roles` out of the
  realm's defaults, or every registered client gets it; offer
  `offline_access` only if you mean to (OD17). ([docs/01](01-foundations.md) M9)
- **Claude Code asks for `offline_access` when it registers through
  DCR**, and Keycloak's Allowed Client Scopes policy refuses the whole
  registration if that scope isn't allowed (`Not permitted to use
  specified clientScope`). Allow it, or the harness can't sign in.
  ([docs/01](01-foundations.md) OD17)
- **An offline token also needs the user to hold the `offline_access`
  realm role.** A realm imported with its own users and client scopes
  may give the user no roles; consent then succeeds and the token
  request fails with `Offline tokens not allowed for the user or
  client`. ([docs/01](01-foundations.md) OD17)
- **Signing out a user's browser sessions doesn't end an offline
  harness.** Its token's `sid` is also its offline session, which signing
  out the browser (online) sessions leaves alone. Revoke its consent, or sign the user out (that sets a
  not-before time offline tokens are checked against).
  ([docs/01](01-foundations.md) M9)
- **Every CLI login shares the `nyyrikki-cli` client**, so revoking its
  consent ends all of them. End one by its own offline session (ID = its
  tokens' `sid`). A CLI client without the `offline_access` scope makes
  Keycloak answer `invalid_scope`; `nyyrikki login` then falls back to a
  session-bound login. ([docs/01](01-foundations.md) OD18)
- **Keycloak requires PKCE in the device grant for a client with PKCE
  set**, which the pkce-enforcer client policy does for every registered
  client: without `code_challenge` the device authorization request fails
  with `Missing parameter: code_challenge_method`. Send PKCE there too.
  ([docs/01](01-foundations.md) M9)
- **Any registered confidential client gets a client-credentials token
  carrying your audience.** Its `sub` is a service account; only a check
  of `sub` against the human registry refuses it. Never accept a token on
  audience alone. ([docs/01](01-foundations.md) M9, D8)

**MCP**

- **The go-sdk's `auth.RequireBearerToken` accepts only the `Bearer`
  scheme**, and turns any verifier error that isn't `ErrInvalidToken`
  into a 500. DPoP-bound tokens need your own middleware.
  ([docs/01](01-foundations.md) M2)
- **Claude Code reads credential-like variables as empty in a remote
  server's `url` and `headers`, and strips variables whose names contain
  `TOKEN`, `SECRET`, `PASSWORD`, `KEY` or `AUTH` from a project
  `.mcp.json`'s `headersHelper`.** Name the helper's variables
  accordingly. ([docs/01](01-foundations.md) M14)

**OpenSSH and sudo**

- **sshd without PAM refuses an account whose password field is `!`**,
  even for a certificate or key login ("User not allowed because account
  is locked"). Alpine's `adduser -D` writes `!`. Use `*` for an account
  that must have no password but still log in.
  ([docs/07](07-ssh-target.md) M7)
- **Closing an SSH connection doesn't stop a command run without a
  PTY**: it is reparented to init and keeps running, as root under
  sudo. Send a `signal` request first, and `TERM` rather than `KILL`:
  `KILL` kills `sudo` itself and leaves its child running.
  ([docs/07](07-ssh-target.md) M10, M11)
- **`AuthorizedKeysFile none` doesn't turn off a global
  `AuthorizedKeysCommand`**, such as EC2 Instance Connect's. To leave
  an account only to certificates, a `Match User` block also needs
  `AuthorizedKeysCommand none` and `AuthenticationMethods publickey`
  (and hostbased, GSSAPI and keyboard-interactive off). Check the result
  with `sshd -T -C user=…`. ([docs/07](07-ssh-target.md) M16)
- **An "empty" `RevokedKeys` file must be a real KRL.** sshd accepts a
  zero-byte file, but `ssh-keygen -k -u` refuses it ("invalid magic
  number"), so revoking a key fails exactly when it is needed. Create
  it with `ssh-keygen -k -f <file>`. ([docs/07](07-ssh-target.md) M17)
- **A sudo command outlives its SSH session unless logind kills the
  session.** sudo's child stays in the session's scope, but by default
  logind leaves the scope running after logout. `KillOnlyUsers=` does
  nothing without `KillUserProcesses=yes`, and the kill waits for the
  scope's `TimeoutStopSec` (90 s) before `KILL`.
  ([docs/07](07-ssh-target.md) M18)
- **`sshd -V` doesn't exist before OpenSSH 9.x.** 8.9 answers "unknown
  option -- V", then prints its version in the usage message. Read
  `sshd -V 2>&1` and look for `OpenSSH_`, not the first line.
  ([docs/07](07-ssh-target.md) §10, OD7)
- **A writable principals file fails as "Certificate does not contain an
  authorized principal"**, with "bad ownership or modes" only in the
  line before. Write it with `umask 022`. ([docs/07](07-ssh-target.md) M19)
- **sshd notices a vanished client only through TCP keepalive by
  default**, about 2 h on Linux, so a session (and whatever runs in it)
  outlives a network partition by that long. Set `ClientAliveInterval`
  and `ClientAliveCountMax`. ([docs/07](07-ssh-target.md) M21)
- **A heredoc cut off by end of file still runs its command.** bash only
  warns ("delimited by end-of-file"), dash says nothing, so a truncated
  `curl | sh` with data after the command acts on part of the data. End
  the data with a line the command checks, such as a count.
  ([docs/07](07-ssh-target.md) M23)
- **`ssh.CertChecker` takes a certificate with no principals as valid
  for every host or user.** `x/crypto/ssh` follows OpenSSH's old rule;
  refuse an empty `ValidPrincipals` yourself when a name must match.
  ([docs/07](07-ssh-target.md) D8, `internal/sshtarget/hostkey.go`)
- **Restarting logind repeatedly trips systemd's start rate limit**;
  run `systemctl reset-failed systemd-logind` before each restart. A
  logind restart during an account's stop delay can also leave its
  `user@<uid>.service` running with no session, which `loginctl
  terminate-user` can't end: `systemctl stop user@<uid>.service` does.
  ([docs/07](07-ssh-target.md) §10, `test/ssh-host`)
- **POSIX sh has no `local`.** A helper's loop variable overwrites its
  caller's of the same name; in the setup script that dropped the wrong
  file from the rollback journal. Give every function its own variable
  names. ([docs/07](07-ssh-target.md) §10)
- **Closing an `x/crypto/ssh` client right after `Session.Signal` can
  lose the signal.** A test host saw `KILL` only some of the time when
  the connection closed right after it. Give the session a moment to
  end before closing. ([docs/07](07-ssh-target.md) §10)
- **A shell splits words only on ASCII blanks, but Telegram shows any
  Unicode space as a space.** `cat notes<U+00A0># ; curl … | sh` reads
  as a command and a comment, yet `#` starts no comment on the host.
  Show every space but U+0020 escaped. Lookalike punctuation, such as
  U+FF03 for `#`, is not escaped: read a command with non-ASCII
  characters with care. ([docs/07](07-ssh-target.md) D2)
- **Debian's cron ignores files in `/etc/cron.d` whose names contain a
  dot**, so `nyyrikki.conf` never runs while cronie runs it. BusyBox
  `crond` ignores `/etc/cron.d` entirely; on Alpine use
  `/etc/periodic/15min`. Name cron files `[A-Za-z0-9_-]` only.
  ([docs/08](08-ssh-onboarding.md) M3)
- **OpenSSH 10 penalises an address after one failed login**
  (`PerSourcePenalties`, on by default): its next connections are
  dropped for a while, so a retry loop after a refusal looks like an
  unreachable host. Try once, then stop. ([docs/08](08-ssh-onboarding.md) M5)
- **BusyBox `wget` can't be given a CA file**: its only TLS option is
  `--no-check-certificate`. Use `curl --cacert`.
  ([docs/08](08-ssh-onboarding.md) M6)
- **BusyBox `tr` has no character classes**: `tr -c '[:print:]' '?'`
  takes the class as the literal characters `[:print]` and replaces
  everything else. Write the range: `tr -c ' -~' '?'`.
  ([docs/08](08-ssh-onboarding.md) §10, SE6)
- **Not every host has `cmp`**: a minimal Rocky 9 has no `diffutils`.
  A script that must run there compares small files another way.
  ([docs/08](08-ssh-onboarding.md) §10, SE6)
- **A job a non-interactive shell starts with `&` has `SIGINT` and
  `SIGQUIT` ignored, and a shell started with a signal ignored can't
  trap it.** A test that sends Ctrl-C to a script it started that way
  proves nothing; start it detached instead (`docker exec -d`, `setsid`).
  ([docs/08](08-ssh-onboarding.md) §10, SE6)

**Tooling and dependencies**

- **SQLite can't change a table's `CHECK` constraint in place.**
  `CREATE TABLE IF NOT EXISTS` leaves an existing table as it was, so a
  new allowed value needs the table rebuilt, with foreign keys off on
  that one connection and `PRAGMA foreign_key_check` before the commit.
  ([docs/08](08-ssh-onboarding.md) §10, SE5)
- **A `pre-install` hook can't create an object the chart also
  templates**: Helm checks for conflicts before hooks run, then fails
  the first install with "already exists". And a Helm-owned Secret
  filled in by a hook is replaced by `helm upgrade --force`, so the hook
  then makes new contents. Keep generated keys out of the release.
  ([docs/08](08-ssh-onboarding.md) M7, M8)
- **Argo CD's label tracking claims any object labelled
  `app.kubernetes.io/instance: <app>`**, rendered or not, and auto-sync
  with prune deletes the ones that aren't in the manifests. Don't put
  that label on objects a hook creates. ([docs/08](08-ssh-onboarding.md) D16)
- **`gopkg.in/yaml.v3` has been unmaintained since 2022.** Use
  `go.yaml.in/yaml/v3`. ([docs/01](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/01-foundations.md) M4)
- **Claude Code never reads `mcpServers` from `settings.json`.** Servers
  live in `~/.claude.json` or `.mcp.json`. Also, `claude mcp add`
  rejects the server name if it directly follows `--env`.
  ([docs/05](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/05-agent-integration.md) M1, M2)
- **Codex's MCP timeout defaults differ between its docs and its
  source.** Set `startup_timeout_sec` and `tool_timeout_sec` explicitly.
  ([docs/05](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/05-agent-integration.md) M5)
- **asciicast v3 (the asciinema 3.x default) isn't readable by
  asciinema 2.x**, and its timestamps are relative intervals rather than
  absolute times. ([docs/03](https://github.com/Tuhis/Nyyrikki/blob/0ea8b56/docs/03-audit-log.md) M2)
- **Go's `GET /path` mux pattern also matches `HEAD`.** An endpoint that
  must answer only `GET` checks the method itself.
  ([docs/07](07-ssh-target.md) D16, `internal/hostsetup`)
- **`helm template` never renders `NOTES.txt`, and sprig's `required`
  accepts an empty list.** Test NOTES by rendering a copy as an ordinary
  template, and fail on `(not .Values.x)` for lists.
  ([docs/07](07-ssh-target.md) §10, `deploy/chart/chart_test.go`)
- **Files copied from the Go module cache are read-only (0444).** A
  second `cp` over a copy fails for a non-root user; root, as in a
  Docker build, never notices. `chmod -R u+w` what you copy out.
  ([docs/09](09-public-release.md) §10, `scripts/save-licenses.sh`)
- **`cmd | grep -q` under `pipefail` can read a match as no match.**
  `grep -q` exits at the first match, the writer dies of SIGPIPE, and
  the pipeline fails. Read the output whole, then grep it.
  ([docs/09](09-public-release.md) §10, `scripts/save-licenses.sh`)
- **`helm push` prints `Digest:` on stderr in Helm 3 and on stdout in
  Helm 4.** Capture both (`2>&1`) and require exactly one well-formed
  digest. ([docs/09](09-public-release.md) §10, `release.yml`)
- **`go test -coverpkg` can fail with `go tool covdata: … text file
  busy`** on a cold build cache: the tool is built while parallel test
  processes exec it (golang/go#22315). Build it first with
  `go tool -n covdata`. ([docs/09](09-public-release.md) §10,
  `scripts/gates.sh`)
