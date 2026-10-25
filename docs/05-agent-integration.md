# R8 — Agent integration: `nyyrikki-mcp` (docs/05)

**Status**: drafted 2026-10-25, adapted from the Warden design. Status
lives in [`ROADMAP.md`](../ROADMAP.md). There are no open owner
decisions. Decisions D1–D12 await the owner's approval.

Chunks **AG1–AG4** (`AG` = agent; unused).

**Relationship to earlier work**: the agent-side client of the control
API in [docs/02](02-grant-core.md) §5.13. It writes the credential files
that the proxies in [docs/06](06-http-proxy.md),
[docs/07](07-kubernetes-proxy.md) and [docs/08](08-ssh-proxy.md) expect.
It surfaces the delivery status from
[docs/04](04-telegram-escalation.md) §5.9. It corrects the Warden
design, which wrongly placed the MCP registration in `settings.json`
(M1).

---

## 1. Purpose

The agent knows when it is stuck: `forbidden` from the apiserver,
`Permission denied (publickey)` from a server. What it lacks is a way to
ask for more from inside the thread, and a way to use the answer without
anyone copying credentials around.

`nyyrikki-mcp` is the one Nyyrikki component on A. It is a stdio MCP
server that gives the agent six tools:

- list what it may ask for;
- request a grant;
- wait for the approval;
- check status;
- extend;
- release.

On approval it writes ready-to-use config for `kubectl`, `curl` and
`ssh`, and hands the agent the exact command lines. Nothing in it can
approve anything.

### Non-goals

- **Policy or security decisions.** All of those are on G.
- **A UI in the coding tool.** The approval happens in Telegram
  (SECURITY.md "central assumption").
- **Wrapping `kubectl` or `ssh`.** The standard tools run unchanged
  against generated config.
- **Discovering the thread's identity.** There is no trusted thread ID.
  `label` is display text supplied by the agent.

## 2. Measured and verified before writing

All checked 2026-10-25.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | Claude Code stores MCP servers per scope:<br>• local: `~/.claude.json` under `projects["<path>"].mcpServers`<br>• user: `~/.claude.json`, top-level `mcpServers`<br>• project: `.mcp.json` at the repository root<br>`mcpServers` is **not** read from any `settings.json`. | [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp) (installation scopes), [debug-your-config](https://code.claude.com/docs/en/debug-your-config): "`settings.json` does not read an `mcpServers` key" | Confirmed. The Warden design was wrong on this point |
| M2 | `claude mcp add [options] <name> -- <command> [args…]` with `-s/--scope local\|project\|user`, `-e/--env KEY=value` and `-t/--transport stdio`. **Gotcha**: if the server name comes directly after `--env`, the CLI parses it as another `KEY=value` and rejects it. | code.claude.com/docs/en/mcp | Confirmed. §5.7 never puts the name after `--env` |
| M3 | Claude Agent SDK (which T3 Code's Claude adapter uses): `settingSources: "project"` loads `.mcp.json`. `~/.claude.json` is read whatever `settingSources` says. The SDK also accepts servers programmatically through `options.mcpServers`. | code.claude.com/docs/en/agent-sdk/mcp, …/agent-sdk/claude-code-features | **Partly**: that user-scope servers from `~/.claude.json` reach a T3 Code thread is inferred from these docs, **not tested**. AG4 measures it |
| M4 | Claude Code: `MCP_TIMEOUT` (server startup, default 30 000 ms) and `MCP_TOOL_TIMEOUT` (default 100 000 000 ms). Stdio servers "have no per-request timer". Calls still running after 2 min move to the background. | code.claude.com/docs/en/env-vars, …/mcp#time-limits-on-mcp-tool-calls | Confirmed. A 55 s long-poll per call (D6) is safe |
| M5 | Codex reads `[mcp_servers.<name>]` from `~/.codex/config.toml`, with `command`, `args`, `env`, `env_vars`, `startup_timeout_sec` and `tool_timeout_sec`. `codex mcp add <name> -- <cmd…>` writes the user config and has no timeout flags. The **defaults conflict**: the docs say 10 s startup and 60 s per tool, but source release rust-v0.164.0 (2026-10-23) uses 30 s and 300 s. | learn.chatgpt.com config reference; github.com/openai/codex `codex-rs/codex-mcp/src/rmcp_client.rs`, `codex-rs/cli/src/mcp_cmd.rs` | Partly. §5.7 sets both timeouts explicitly |
| M6 | MCP progress notifications (`notifications/progress` with `progressToken`) exist in the current spec revision **2026-07-28**. That revision replaces the `initialize` handshake with `server/discover`. | [modelcontextprotocol.io/specification/2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/utilities/progress) | Confirmed |
| M7 | `github.com/modelcontextprotocol/go-sdk` v1.8.0 supports spec 2026-07-28 and provides a stdio transport | docs/01 M7 | Confirmed |

## 3. Owner decisions

None open.

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **`nyyrikki-mcp` is a thin client** of the control API (`pkg/controlclient`). It makes no decisions, and it exposes **no tool that approves, denies or changes step mode**. | INV-02: approval is off A by design. |
| D2 | **A stdio MCP server** built on the official Go SDK (M7). | It works with every MCP client the owner uses (M1–M5). |
| D3 | **Secrets never appear in tool output.** Usage strings reference file paths, never token values. | Tool results go to the model provider (CLAUDE.md: secrets never reach prompts). |
| D4 | **State directory** `~/.local/state/nyyrikki` (overridable with `NYYRIKKI_STATE_DIR`). Directories are `0700` and files `0600`. `nyyrikki-mcp` refuses to run if they are looser. | Other users on A shouldn't read them. The agent itself can. That is RR-1. |
| D5 | **Credentials are materialized once, on activation.** If the files are lost, release the grant and request a new one. | docs/02 D9. |
| D6 | **`nyyrikki_wait` long-polls for at most 55 s per call** and sends MCP progress notifications while waiting. The agent calls it again until a terminal or active state. | M4–M6: no MCP client cuts it off, and the agent stays responsive. |
| D7 | **Registration**: Claude Code at **user scope** through `claude mcp add` (into `~/.claude.json`), and Codex in `~/.codex/config.toml` with explicit timeouts (§5.7). | User scope lets every thread on A elevate. M1, M2, M5. |
| D8 | **The per-grant SSH key is generated on A** when a profile with an `ssh` section is requested. Only the public key is sent. | docs/02 §5.12. |
| D9 | **The client certificate auto-renews** when less than 20% of its lifetime remains, using the current certificate (docs/02 §5.11). | No operator action every 90 days. |
| D10 | **Enrolment pins G's CA by fingerprint** (`--ca-sha256`), and aborts on a mismatch. | First contact can't be intercepted. |
| D11 | **The grant directory is removed** on release, expiry, revoke or deny: overwritten first, best-effort. | Leaves nothing reusable lying around, even though the token is dead anyway (INV-09). |
| D12 | **`label` is the agent's own text** (usually the thread title). It is untrusted on G. | No trusted thread identity exists. Pretending otherwise would be false assurance. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| An "approve" tool, or answering a `user_input` prompt in the thread | The agent could call it itself (SECURITY.md). |
| Returning the token in tool output for the agent to use | D3: it would travel to the model provider. |
| Wrapper CLIs (`nyyrikki kubectl …`) | Generated config makes the unmodified tools work, and a wrapper adds nothing a proxy doesn't enforce already. |
| Project-scoped `.mcp.json` registration | Per-repository opt-in, and Claude Code asks for approval before using project servers in interactive sessions ([code.claude.com/docs/en/mcp#project-scope](https://code.claude.com/docs/en/mcp)). User scope matches "any thread can elevate". |

## 5. Design

### 5.1 Invocation

```
nyyrikki-mcp --server nyyrikki.internal:8443          # stdio MCP server (the default mode)
nyyrikki-mcp enroll --server … --token nye_… --ca-sha256 <hex>
nyyrikki-mcp version
```

| Flag / env | Default | Consumed by |
|---|---|---|
| `--server` | none (required) | `controlclient.New` |
| `NYYRIKKI_STATE_DIR` | `~/.local/state/nyyrikki` | `state.Open` |

### 5.2 State directory

```
~/.local/state/nyyrikki/
  client.key  client.crt  internal-ca.pem          # transport identity (docs/02 §5.11)
  grants/<grant_id>/
    token                                          # nyg_…  (0600)
    env                                            # export lines (KUBECONFIG, NYYRIKKI_*)
    kube/<cluster>.kubeconfig                      # docs/07 §5.10
    curlrc  auth-header                            # docs/06 §5.8
    ssh/{id_ed25519, id_ed25519.pub, config, known_hosts}   # docs/08 §5.10
    meta.json                                      # id, profile, expires_at, step, usage strings
```

### 5.3 Tools

Every tool returns structured JSON content plus one short text the agent
can relay. Error results carry the API error code and
`X-Nyyrikki-Request-Id` (docs/02 §5.13).

| Tool | Calls | Returns |
|---|---|---|
| `nyyrikki_profiles()` | `GET /v1/profiles` | requestable profiles: name, description, TTLs, step, capabilities |
| `nyyrikki_request(profile, reason, ttl_minutes?, label?, step?)` | creates the SSH key if needed, then `POST /v1/grants` | `{grant_id, state:"pending"}`, plus text: "Requested **k8s-node-maint** for 60 min. Approval requested on Telegram. Call `nyyrikki_wait` with this grant_id." |
| `nyyrikki_wait(grant_id, timeout_s?=55)` | `GET /v1/grants/{id}/wait` | on `active`, materializes the files (§5.4) and returns usage (§5.5). On a terminal state, says why. Otherwise reports "still pending", plus the delivery status (docs/04 §5.9) |
| `nyyrikki_status(grant_id?)` | `GET /v1/grants/{id}` or this client's grants | state, time left, sessions, pending steps (visibility only) |
| `nyyrikki_extend(grant_id, ttl_minutes)` | `POST …/extend` with the token | `{extension_id, state:"pending"}`, plus "Extension requested on Telegram; call `nyyrikki_wait`." |
| `nyyrikki_release(grant_id)` | `POST …/release` with the token | `released`, and deletes the grant directory (D11). Idempotent |

The tool descriptions tell the model:

- `reason` is shown to a human approver, so it should say exactly what
  will be done and why;
- `label` should carry the thread's title;
- never print the token or key files.

`nyyrikki_wait` emits a progress notification every 10 s (M6): "waiting
for approval (1 approver notified)". If `delivered` is still 0 after
30 s, the text says that Telegram delivery is failing.

### 5.4 Materializing credentials on activation

When `nyyrikki_wait` sees the transition to `active` with `credentials`
(returned once, docs/02 D9), it writes:

1. `token` (`0600`).
2. One kubeconfig per cluster, `kube/<cluster>.kubeconfig` (docs/07
   §5.10). Each references `token`, `client.crt`, `client.key` and
   `internal-ca.pem` by path.
3. `curlrc` for the HTTP upstreams (docs/06 §5.8).
4. `ssh/config` and `ssh/known_hosts`. The known_hosts entry pins the
   proxy host key from the response under the alias `nyyrikki`. The
   SSH key generated at request time is already present (docs/08 §5.10).
5. `env`: `KUBECONFIG` (the per-cluster files joined with `:`),
   `NYYRIKKI_GRANT`, `NYYRIKKI_SSH_CONFIG`, and one
   `NYYRIKKI_<UPSTREAM>` base URL per upstream.
6. `meta.json`.

If `credentials` is absent because they were already delivered, and the
files exist, they are kept. If they are missing, the tool tells the
agent to `nyyrikki_release` and request again.

### 5.5 Usage strings

The usage text references paths only (D3). For example:

```
ACTIVE as k8s-node-maint until 14:33 UTC (59 min). Use:
  export KUBECONFIG=~/.local/state/nyyrikki/grants/gr_…/kube/prod.kubeconfig
  kubectl get nodes
  kubectl drain node-1 --ignore-daemonsets      # evictions are held for approval on Telegram
  ssh -F ~/.local/state/nyyrikki/grants/gr_…/ssh/config root+node-1@nyyrikki 'apt-get -y upgrade'
  curl -K ~/.local/state/nyyrikki/grants/gr_…/curlrc https://nyyrikki.internal:8443/u/keycloak-admin/realms/acme/users
Held operations wait up to 5 min for the approver. Near expiry: nyyrikki_extend. When done: nyyrikki_release.
Never print the files under grants/; they contain credentials.
```

### 5.6 Enrolment

`nyyrikki-mcp enroll` (docs/02 §5.11):

1. Generates an ECDSA P-256 key into `client.key`.
2. Connects to `--server`, and accepts the server only if its
   certificate chain's root has the SHA-256 given by `--ca-sha256` (D10).
3. POSTs a CSR together with the `nye_` token.
4. Stores `client.crt` and `internal-ca.pem`.

It is run once per A, by whoever sets up A. Renewal (D9) runs in the
background whenever the MCP server is up. If the certificate has already
expired, the tool output says so and points to re-enrolment.

### 5.7 Registration

**Claude Code** (and T3 Code's Claude threads, subject to M3), at user
scope:

```bash
claude mcp add --scope user --transport stdio nyyrikki -- nyyrikki-mcp --server nyyrikki.internal:8443
```

This writes the following to the top level of `~/.claude.json` (M1).
Don't hand-edit that file; Claude Code writes it for itself.

```json
{ "mcpServers": { "nyyrikki": {
    "type": "stdio", "command": "nyyrikki-mcp",
    "args": ["--server", "nyyrikki.internal:8443"] } } }
```

If a non-default state directory is needed, add
`--env NYYRIKKI_STATE_DIR=…` *before* `--scope`, never directly before
the name (M2).

**Codex**, in `~/.codex/config.toml`:

```toml
[mcp_servers.nyyrikki]
command = "nyyrikki-mcp"
args = ["--server", "nyyrikki.internal:8443"]
startup_timeout_sec = 30
tool_timeout_sec = 120     # the long-poll is 55 s; the defaults conflict (M5)
```

Nothing in the T3 Code, Claude or Codex UI needs to change. The thread
experience is:

1. the agent requests;
2. the approver taps in Telegram;
3. `nyyrikki_wait` returns the usage text;
4. the agent continues.

### 5.8 Resilience

- **Restarts**: waits are idempotent. After a restart, `nyyrikki-mcp`
  rebuilds its view from `grants/*/meta.json` plus `GET` calls.
- **Errors**: the API codes map to clear, non-leaky texts.
- **Logging**: stderr only, and never the token, key or file contents.
- **Shutdown**: SIGTERM leaves nothing to flush. The grant token is
  already on disk, and it dies with the grant.

## 6. Security considerations

- **No new trust boundary.** `nyyrikki-mcp` runs on A and is as
  untrusted as A. Everything it sends is validated on G (docs/02 §6).
  Compromising it gains nothing that A didn't already have.
- **What reaches the model.** The model gets tool output, which holds
  profile names, states and paths. It never gets tokens or keys (D3).
  The agent can still `cat` the files. Leaking them is bounded:
  - the token is useless without the client key;
  - both work only from A's address (`source_cidrs`, plus G's firewall);
  - both die with the grant (INV-09).
- **What reaches Telegram and the audit log**: `reason` and `label`,
  which are untrusted, escaped and labelled (docs/04 §5.7).
- **Dependency failures.** If G is unreachable, the tools error and
  nothing is granted. A failed renewal leaves the old certificate valid
  until its expiry, then enrolment fails closed.
- **New ways to reach an upstream**: none. The generated files point
  only at G.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1. Each tool in §5.3 behaves as specified against the control API, including the error mappings | integration tests against an in-process `nyyrikkid` |
| G2. The state directory and its files have the D4 modes, and `nyyrikki-mcp` refuses looser ones. No tool output, log line or MCP message contains a token or key. The state directory never contains an upstream credential (INV-01) | tests that capture every MCP message and stderr line and scan for the planted grant token; a scan of the state directory against canary upstream secrets |
| G3. Enrolment aborts on a CA fingerprint mismatch and on a reused token | integration tests |
| G4. The tool list contains no tool that can approve, deny, or change step mode | a test that enumerates the registered tools against an allowlist |
| G5. Registration works: Claude Code at user scope, Codex with the §5.7 config, and **a T3 Code thread lists the tools** (M3) | manual, by the owner, recorded in §2 with the client versions |
| G6. Credentials survive an MCP server restart. A lost credential set leads to a clear "release and re-request" message | integration test |
| G7. The client certificate renews at 80% of its lifetime with no operator action | integration test with a fake clock |
| G8. `nyyrikki_wait` emits progress notifications and returns within 55 s | integration test |
| G9. Release, expiry, revoke and deny remove the grant directory (D11) | integration test |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **AG1** | `pkg/controlclient`; `nyyrikki-mcp enroll`; certificate renewal | G3, G7 |
| **AG2** | MCP server and the six tools; the state directory; the wait loop with progress | G1, G4, G8 |
| **AG3** | Credential materialization: kubeconfig, curlrc, SSH config; usage strings; cleanup | G2, G6, G9 |
| **AG4** | Registration instructions verified in Claude Code, Codex and T3 Code | G5 |

Ordering notes:

- AG1 needs docs/02 GC3.
- AG2 needs GC5.
- AG3's file formats come from docs/06–08, but it can land with the
  HTTP format first (docs/06) and add the others as those proxies land.
- AG4 is last.

## 9. Risks and open questions

- **M3**: if T3 Code's Claude threads don't pick up user-scope servers,
  the fallback is project-scope `.mcp.json` in the repositories the agent
  works in. That is less convenient, but it is a documentation change
  only.
- **MCP spec drift.** 2026-07-28 changed the handshake (M6). Pin the SDK,
  and let Renovate propose updates (docs/01 D9).

## 10. How it was implemented

Not started.

## 11. Post-implementation review

Not started.
