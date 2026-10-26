# R4 — Pass-through, identity propagation and credential custody: kubectl, 1:1 (docs/04)

**Status**: drafted 2026-10-26, owner decision OD1 taken the same day.
Awaiting the owner's approval of the doc as a whole; merging the PR that
adds it is that approval. Status lives in [`ROADMAP.md`](../ROADMAP.md).

Chunks **PT1–PT5** (`PT` = pass-through; unused).

**Relationship to earlier work**: builds on [docs/01](01-foundations.md)
D1, D13, D15 and [docs/02](02-gateway-core.md) D6, D10. Answers
`ROADMAP.md` M2's open question "a raw API request or a CLI line": a
kubectl command line (OD1).

---

## 1. Purpose

Agents already know kubectl. The request an agent wants run is a kubectl
command line, and the approver reads a kubectl command line faster than
an HTTP request. This doc decides how that line is parsed into the form
the approver sees and the approval binds to, how exactly that form runs
as the human against the target, with Nyyrikki's credential, and how
nothing else runs: no other flags, no files on Nyyrikki's disk, no
second cluster, no other identity.

### Non-goals

- Other target types (docs/01 OD9).
- `port-forward`, `proxy`, `cp`, `edit` and the other commands of D5's
  list of commands not offered.
- Temporary credentials issued on the target: Kubernetes impersonates,
  so nothing is issued (`ROADMAP.md`, not in the first version).
- Redacting responses (R9).

## 2. Measured and verified before writing

All checked on 2026-10-26 with Go 1.26.8.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | `k8s.io/kubectl` v0.37.1's `cmd.NewKubectlCommand` builds kubectl's full cobra tree. `root.Find(args)` resolves the command (global flags before the command included, e.g. `-nshop exec …`), and `cmd.ParseFlags(rest)` parses flags with kubectl's own definitions: `-it` becomes `stdin` and `tty`, `-nshop` becomes `namespace=shop`, `--` is reported by `ArgsLenAtDash`. Unknown commands and flags are errors; `-v` is unknown, because klog's flags are added only by kubectl's `main` | ran a probe against v0.37.1 | Confirmed. D2 |
| M2 | `NewKubectlCommand` doesn't dispatch plugins; plugin lookup lives in `NewDefaultKubectlCommandWithArgs`, and only when a `PluginHandler` is set | read `pkg/cmd/cmd.go` at v0.37.1 | Confirmed. D6 |
| M3 | kubectl ≥ 1.33 reads a preferences file (kuberc) that can add aliases and default flags; it is turned off by `KUBERC=off`, and a `--kuberc` flag and a `kuberc` command exist | read `pkg/kuberc/kuberc.go` at v0.37.1 | Confirmed. D4, D6 |
| M4 | kubeconfig `AuthInfo.tokenFile` is re-read by client-go and takes precedence over `token`; `AuthInfo` has `as`, `as-groups` and `as-uid` for impersonation | `docs/measured.md` (Kubernetes M8), `go doc k8s.io/client-go/tools/clientcmd/api.AuthInfo` v0.37.1 | Confirmed. D9 |
| M5 | Impersonation needs verb `impersonate` on `users` and `groups`, restrictable by `resourceNames`; every impersonated user is also in `system:authenticated` | `docs/measured.md` (Kubernetes M6, M9) | Re-read; confirmed. D10 |
| M6 | Before 1.35, `get pods/exec` alone allows WebSocket exec | `docs/gotchas.md`, `docs/measured.md` (Kubernetes M5) | Confirmed. D11 refuses targets older than 1.35 |
| M7 | kubectl fetches `-f https://…` itself and reads local paths, `-k` directories, `--from-file`, `--from-env-file`, `-o jsonpath-file=`/`go-template-file=`/`templatefile=` and `debug --custom` files from the machine it runs on | kubectl help output and source at v0.37.1 | Confirmed. D4's file rules |
| M8 | `github.com/creack/pty` v1.1.24 (MIT) starts a process on a new pseudo-terminal and resizes it | pkg.go.dev, LICENSE | Confirmed. D12 |
| M9 | A `k8s.io/kubectl` v0.37.1 build adds about 100 MB to a static binary | built the probe | Confirmed. Accepted (D6) |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | What form does a request take? | **A kubectl command line, 1:1**: the agent sends the arguments it would give `kubectl`, and that is what runs (owner, 2026-10-26). |
| OD2 | Interactive exec and attach? | **Included** (owner, 2026-10-26; docs/02 OD3). |
| OD3 | Requests run as the human. If the human can reach Nyyrikki's own credentials (read its Secrets, mint its ServiceAccount's tokens, exec into its pod, mount them in a pod of their own, reach its node) or can mint a standing credential on a target, a request the agent gets approved, or any request under an elevation on that target, returns them (review of the docs PR). Enforce an RBAC check, refuse such requests by argv, require a separate cluster, or accept? | **Accept the risk** (owner, 2026-10-27; reconfirmed the same day for requests under an elevation, which get no message of their own). The defence is the approver's tap, on the exact request or on the elevation that covers it. SECURITY.md (Accepted risks) lists what it costs, which invariants it suspends, the rights that narrow it and the separate cluster that closes it; INV-08 and `CLAUDE.md` say what Nyyrikki itself guarantees: it never adds its credentials to a response, an error, a log or a message. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **The request** is `args`, the kubectl arguments without the leading `kubectl`, plus optional `stdin` bytes. Nothing is ever passed through a shell; `args` stays an argv array from the agent to kubectl. | `CODE-REVIEW.md`: nothing passes through a shell. |
| D2 | **Parsed once, with kubectl's own definitions.** `kubectl.Parse(args)` builds kubectl's command tree from the same `k8s.io/kubectl` version that runs it (D6), resolves the command with `Find` and the flags with `ParseFlags` (M1), and produces a `Canonical`: the command path, every flag that was set with its resolved long name and value(s), the positional arguments, the position of `--`, and the stdin bytes. A parse error is `invalid_request`. | Parsing with the executor's own code removes parser differences: what Nyyrikki checks is what kubectl will do. |
| D3 | **What the approver sees, what the approval binds to and what runs are one value.** The `Canonical` renders to a canonical argv: the command path, then every set flag as `--name=value` (one per element for slice and array flags) sorted by name, then the positional arguments before `--`, then `--` if it was present, then the positional arguments after it. That argv, shell-quoted for display (§5.2), is what the approver sees (docs/05). The approval binds to the SHA-256 of the canonical argv and stdin (§5.3). The runner executes the canonical argv, never the agent's original. `Parse` re-parses the rendered argv and refuses the request unless the result is identical (`invalid_request`, `canonical_mismatch`). | INV-02. The round-trip check catches any value the renderer can't express faithfully (for example a slice element containing a comma), and refuses it instead of guessing. |
| D4 | **What may run.** An allowlist of command paths (§5.4); anything else is `invalid_request` naming the command. A deny list of flags by resolved long name, for every command: the connection and identity flags (`kubeconfig`, `context`, `cluster`, `user`, `server`, `token`, `username`, `password`, `client-certificate`, `client-key`, `certificate-authority`, `insecure-skip-tls-verify`, `tls-server-name`, `as`, `as-group`, `as-uid`, `cache-dir`, `kuberc`, `profile`, `profile-output`), and the flags that read Nyyrikki's own disk or network: `filename` unless its only value is `-`, `kustomize`, `from-file`, `from-env-file`, `custom`, `edit`, and `output` values starting with `jsonpath-file=`, `go-template-file=` or `templatefile=`. | Kubernetes impersonation can't be widened by the request if the request can't name a cluster, user or identity (INV-05). Files on Nyyrikki's disk include its credentials. *Revised 2026-10-26, while writing PT1's tests*: `cert` and `key` (`create secret tls` reads both files), `patch-file` and the `custom-columns-file` output are denied too; file-based output formats are refused by format name, case-insensitively, since the path can sit in `--template`. |
| D5 | **Not offered**: `config` (it would print the kubeconfig), `proxy`, `port-forward` and `cp` (they open listeners or touch Nyyrikki's disk), `edit` and `apply edit-last-applied` (they need an editor), `diff` (it runs an external program), `plugin`, `kuberc`, `completion`, `kustomize`, `alpha`, `cluster-info dump` (it writes files). | Each would act on Nyyrikki's machine rather than the target, or can't work without a terminal program Nyyrikki doesn't ship. Port-forward was not asked for (OD2). |
| D6 | **Running.** `nyyrikkid` re-executes itself (`os.Executable`) as `nyyrikkid kubectl-child`, which runs `cmd.NewKubectlCommand` with no plugin handler (M2) on the canonical argv. One process per run: kubectl's global state, `os.Exit` calls and klog stay in the child; killing the child's process group cuts the run. The child's environment is exactly `KUBECONFIG=<run dir>/kubeconfig`, `KUBERC=off`, `HOME=<run dir>`, `KUBECACHEDIR=<run dir>/cache`, `PATH=` (empty), `LANG=C.UTF-8`; nothing is inherited, so no `HTTPS_PROXY` or `KUBECONFIG` from the pod applies. | The executor is the parser's own code (D2), with no separate kubectl binary whose version could drift. A child process is the unit that can be killed when what covers it ends (D8). |
| D7 | **Limits.** A non-interactive run ends after its timeout: the agent's `timeout`, default `run.default_timeout` (`60s`), at most `run.max_timeout` (`10m`). Under an elevation, never later than the elevation's expiry. An interactive run (D12) lasts at most `run.max_interactive` (`30m`) under a one-off approval, and never past its elevation's expiry. stdout and stderr are each captured up to `run.max_output` (1 MiB); beyond that the run continues, the rest is discarded, and the result says it was truncated. | A watch or `logs -f` has to end; a one-off approval covers one bounded run. |
| D8 | **Cut at expiry.** Every run's context is derived from its `Grant`'s context (docs/02 §5.4). When that context ends (timeout, elevation expiry, "End now"), the runner sends `SIGKILL` to the child's process group, closes the stream, and records `cut` in the audit log. | `CODE-REVIEW.md`: streaming and long-lived requests are cut when the elevation ends. |
| D9 | **Targets and credential custody.** A target's `kubernetes` block is either `in_cluster: true` (server from `KUBERNETES_SERVICE_HOST`/`_PORT`, CA and token from the pod's projected ServiceAccount files) or `server`, `ca_file` and `token_file` (a mounted Secret). Per run, Nyyrikki writes a kubeconfig, mode 0600, in a fresh directory under `runtime_dir` (an in-memory `emptyDir`): the cluster's `server` and `certificate-authority` path, a user with `tokenFile` (M4) set to the credential's path, so the token is never copied, and `as`/`as-groups` from the human registry (docs/02 D4). The directory is removed when the run ends, on every path. | docs/01 D15. The kubeconfig holds only paths and the human's identity, never a secret. |
| D10 | **Identity.** Every request runs as the human's `kubernetes.user` and `groups`, through impersonation set only in the kubeconfig Nyyrikki writes. The request can't change it: D4 refuses `--as`, `--as-group`, `--as-uid`, `--kubeconfig`, `--user` and `--context`. Nyyrikki's ServiceAccounts may impersonate only those names (`resourceNames`, docs/06). | INV-05, docs/01 D15. |
| D11 | **Target version check.** Before the first run on a target, and then at most every 10 minutes, Nyyrikki reads `/version` with its own credential (no impersonation) and refuses the target below 1.35 (`unavailable`, `target_version`). An unreachable target is `unavailable`. | docs/01 D13; M6. |
| D12 | **Interactive runs.** `run` with `interactive: true` is allowed only for `exec` and `attach` with `stdin` and `tty` set. The approval is the same as for any run. The run starts only when the client attaches to `/stream` with the ticket (docs/02 D10): the child gets a pseudo-terminal (M8), WebSocket binary messages carry terminal bytes both ways, and a text message `{"resize": {"cols", "rows"}}` resizes it. When the child exits, the server sends `{"exit_code": n}` and closes. | OD2. A pty is what makes kubectl ask for a TTY, as it does on the owner's laptop. |
| D13 | **Output to the agent.** The result is kubectl's exit status and its stdout and stderr, as they came, apart from truncation (D7). Nyyrikki adds none of its credentials to them: the kubeconfig holds no secret (D9), verbosity flags don't exist (M1), and `config` isn't offered (D5). *Revised 2026-10-27 (OD3)*: a request, approved one-off or under an elevation, that reads Nyyrikki's credentials on the target, because the human can, returns them like any response; that is an accepted risk. | `CLAUDE.md`: responses unredacted; Nyyrikki's credentials never put in a response by Nyyrikki. |
| D14 | **Secret-bearing values in what Nyyrikki shows and logs.** In the approver's view and the audit record, these are replaced by `‹redacted: N bytes, sha256:<first 12 hex>›`: the values of `--from-literal` (the part after the first `=`) and `--docker-password`; `patch`'s `--patch` when a positional names a Secret (the resource token, matched case-insensitively up to the first `/` or `.`, is `secret` or `secrets`) or when the target comes from `-f`; and, in stdin, `data`, `stringData` and the `kubectl.kubernetes.io/last-applied-configuration` annotation of every document whose `kind` is `Secret`, including Secrets inside a `List`'s `items`. They still run as sent; the hash binds the approval to them. Not covered, and accepted: a Secret's values typed into another command's positional argument (for example `annotate secret x kubectl.kubernetes.io/last-applied-configuration='{…}'`). *Revised 2026-10-27 (review of the docs PR)*: the patch, `List` and annotation cases were added. | `CLAUDE.md`: secrets never reach logs or Telegram. The approver still sees that a secret is being set, and its size. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| A raw Kubernetes API request, parsed with `RequestInfo` | OD1. |
| Shipping a separate `kubectl` binary and executing it | Its version could drift from the parser's; D6 runs the parser's own code. |
| Running kubectl's command tree inside the `nyyrikkid` process | kubectl calls `os.Exit`, keeps global state and isn't safe to run concurrently; a run couldn't be killed cleanly. |
| Translating the command line into API requests in Nyyrikki | A second implementation of kubectl, and exactly the parser difference D2 avoids. |
| A flag allowlist per command | kubectl has hundreds of flags; with the parse done by kubectl's own definitions, a deny list of the flags that leave the target or the human is precise and reviewable. Commands, which can act on Nyyrikki's own machine, are allowlisted. |
| Agent-side kubectl pointed at a Nyyrikki API proxy | The Warden plan (set aside in `CLAUDE.md`). |

## 5. Design

### 5.1 Flow

```
args, stdin ──Parse──► Canonical ──Render──► canonical argv ──(re-Parse, compare)──┐
                              │                                                      │
                              ├──► Display (shell-quoted, redacted) ──► approver     │
                              └──► Digest (sha256) ──► approval binds to it          │
Grant(decision) + Canonical ──Run──► kubectl-child(canonical argv) ◄────────────────┘
```

### 5.2 Display

Each argv element is shown shell-quoted (`'…'` with `'\''` for quotes)
when it contains anything outside `[A-Za-z0-9@%+=:,./_-]`; control
characters, bidi controls and zero-width characters are shown as `\u{…}`
escapes. stdin is shown as text when it is valid UTF-8 without control
characters (after D14), otherwise as `‹binary: N bytes, sha256:…›`.

### 5.3 Digest

`sha256("nyyrikki-request-v1\x00" + target + "\x00" + len-prefixed
argv elements + "\x00" + stdin)`. The approval row stores it, and the
runner checks the `Grant`'s digest against the `Canonical` it is given
before starting the child.

### 5.4 Allowed commands

`get`, `describe`, `logs`, `events`, `top node`, `top pod`, `explain`,
`api-resources`, `api-versions`, `version`, `cluster-info`, `auth can-i`,
`auth whoami`, `auth reconcile`, `wait`, `create` and its subcommands,
`apply`, `apply view-last-applied`, `apply set-last-applied`, `delete`,
`patch`, `replace`, `label`, `annotate`, `scale`, `autoscale`, `expose`,
`run`, `set` and its subcommands, `rollout` and its subcommands,
`cordon`, `uncordon`, `drain`, `taint`, `certificate approve`,
`certificate deny`, `exec`, `attach`, `debug`.

### 5.5 Configuration

```yaml
run:
  default_timeout: 60s
  max_timeout: 10m
  max_interactive: 30m
  max_output: 1MiB
targets:
  - name: prod-k8s
    description: Production cluster
    humans: [owner]
    kubernetes:
      in_cluster: true
  - name: lab
    humans: [owner]
    kubernetes:
      server: https://lab.example.com:6443
      ca_file: /etc/nyyrikki/targets/lab/ca.crt
      token_file: /etc/nyyrikki/targets/lab/token
```

## 6. Security considerations

- **Inputs.** `args` and `stdin`, attacker-controlled: parsed by D2,
  checked by D4 and D5, round-tripped by D3. The target's response:
  returned as it came (D13).
- **Dependency failures.** Parse error, version check failure, a
  kubeconfig that can't be written, a child that can't start: each is a
  deny or `unavailable` before anything reaches the target.
- **Ways to reach the target.** Only the child, only with a `Grant`
  whose digest matches.
- **Identity.** The human, from the registry, in a kubeconfig the
  request can't influence (D9, D10).
- **Credentials.** The ServiceAccount token, by path only. Nothing is
  issued, so nothing has to be revoked.
- **What runs on Nyyrikki's machine.** Only kubectl's own code, with no
  plugins, no kuberc, no shell, no editor, no external diff, an empty
  `PATH`, and no flag that reads a file other than stdin (D4–D6).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 Every denied command and flag of D4 and D5 is refused, in every spelling pflag accepts (`--x=v`, `--x v`, `-xv`, combined shorts, before or after the command) | `TestParseDenied` table, plus a fuzz test that rendering round-trips |
| G2 The canonical argv round-trips, and a request that doesn't is refused | `TestRenderRoundTrip`, `FuzzParse` |
| G3 The runner refuses a `Grant` whose digest differs from the request | `TestRunDigestMismatch` |
| G4 The child sees only D6's environment and the kubeconfig of D9, which holds no secret | `TestChildEnvironment`, `TestKubeconfigHasNoSecret` |
| G5 A run is killed at its timeout and when its grant's context ends; the run directory is removed on every path | `TestRunCut*`, `TestRunDirRemoved` |
| G6 Requests run as the human: impersonation from the registry, never from the request | `TestKubeconfigImpersonation`; e2e against kind, checking the apiserver audit log for the impersonated user |
| G7 A target older than 1.35 is refused | `TestVersionCheck` |
| G8 Interactive exec over `/stream` works and is cut at expiry | `TestInteractiveExec` (fake apiserver), e2e |
| G9 Secret-bearing values are redacted in the display and the audit record, in every spelling of D14 (`secret`, `secrets/x`, `Secret`, `secrets.v1`, `patch -f -`) | `TestDisplayRedaction`, `TestDisplayRedactsSecretPatch` |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **PT1** | `Parse`, `Render`, `Display`, `Digest`, the allow and deny lists | G1, G2, G9 |
| **PT2** | kubeconfig writing, target version check | G4 (kubeconfig), G6 (unit), G7 |
| **PT3** | `kubectl-child`, the runner, limits, cutting | G3, G4, G5 |
| **PT4** | interactive runs on a pty, wired to `/stream` (docs/02 GW6) | G8 |
| **PT5** | e2e against kind | G6, G8 (e2e) |

## 9. Risks and open questions

- **kubectl adds roughly 100 MB to `nyyrikkid`** (M9), and a large
  dependency tree to review (docs/01 D14). Accepted: it is the price of
  D2.
- **A command line can expand to many API calls** (`delete --all`,
  `drain`). The approver approves the line; that is what OD1 chose.
- **Large stdin documents** may not fit in one Telegram message
  (docs/05 D9 refuses them rather than show part of a request).
- **An approved request, or any request under an elevation, can read
  Nyyrikki's own credentials, or mint a standing credential**, when the
  human can (OD3). Accepted by the owner; SECURITY.md (Accepted risks)
  lists what it costs, the rights that narrow it and the separate cluster
  that closes it. Marking such requests on the Telegram message, without
  refusing them, is a possible strengthening of the one defence, the
  approver's tap.

## 10. How it was implemented (2026-10-26)

- **D4** gained four file-reading flags (dated note in the row). Found by
  reading kubectl's flag set while writing PT1's tests.
- **§5.3, the digest** also encodes the number of argv elements. Without
  it the encoding is ambiguous at the argv/stdin boundary; PT1 built a
  colliding pair to show it.
- **D2**: building kubectl's command tree writes a package-level global,
  so `Parse` is serialised behind a mutex. strace shows the build reads
  no files, opens no connection and starts no process; it only lists the
  `$PATH` directories for plugin names in help text.
- **§5.4**: bare `rollout` and `set` are refused (they only print help).
- **D14** also redacts the `last-applied-configuration` annotation of a
  Secret and Secrets inside a `List`. stdin that doesn't decode but
  mentions "secret" is shown only as its size and hash. `patch`'s
  `--patch` is redacted as D14 says, after review of the docs PR.
- **`debug --profile`** is refused, because it shares the name of the
  denied global `--profile`. A per-command rule could allow it later.
- **D7, cut runs**: a cut returns the partial output and `expired`, with
  detail `run_timeout`, `grant_expired` or `grant_ended`.
- **PT5 (e2e against kind)** isn't done yet: G6 and G8 are verified with
  a fake apiserver, not a real cluster.

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
