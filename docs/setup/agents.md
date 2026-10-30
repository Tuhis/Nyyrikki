# Signing agents in

An agent holds only its own Nyyrikki token. It can't approve anything, and
it never sees a target credential.

## The CLI (recommended where separation matters)

Install the `nyyrikki` binary from a release, then, as the agent's user:

```sh
nyyrikki login --server https://nyyrikki.example.com
# open the printed URL on your phone or laptop, enter the code, sign in
nyyrikki targets
nyyrikki run --reason "restart the stuck pod" prod -- delete pod api-7f -n shop
export NYYRIKKI_ELEVATION=$(nyyrikki elevate --reason "roll out 1.4" --for 20m prod)
nyyrikki run --reason "check rollout" prod -- rollout status deploy/api -n shop
nyyrikki run -t --reason "debug" prod -- exec -it api-7f -n shop -- sh
```

Each `nyyrikki login` makes a new key, so it is a new agent (docs/01
OD14). The login file (`~/.config/nyyrikki/login.json`) must be readable
by that agent only. `NYYRIKKI_ELEVATION` must never be set anywhere
another agent can read: not in a pod spec, not in a ConfigMap.

Exit codes: kubectl's own when the request ran; 64 usage, 67 not signed
in, 69 Nyyrikki unavailable, 75 nobody answered, 77 denied
([docs/02](../02-gateway-core.md) §5.5).

## An MCP harness through its own sign-in

Claude Code:

```sh
claude mcp add --transport http nyyrikki https://nyyrikki.example.com/mcp
claude mcp login nyyrikki --no-browser   # in a pod: paste the redirect URL back
```

Codex: add the server to `~/.codex/config.toml` and set
`tool_timeout_sec = 300`. A call waits for the approver for up to 3
minutes, and Codex's default timeout may be shorter.

## An MCP harness through `nyyrikki mcp-headers`

For a repository `.mcp.json` shared by all sessions. Sign in once per
agent environment:

```sh
nyyrikki login --mcp --server https://nyyrikki.example.com
```

```json
{
  "mcpServers": {
    "nyyrikki": {
      "type": "http",
      "url": "https://nyyrikki.example.com/mcp",
      "headersHelper": "nyyrikki mcp-headers"
    }
  }
}
```

The helper refuses to give a token to any URL other than the one it signed
in for, and prints nothing when it can't produce a fresh token (docs/01
D25). Where the authorization server lists `offline_access` in its
`scopes_supported` (a Keycloak realm does by default), `login --mcp`
asks for it, so the sign-in outlives the browser session it was made in
(docs/01 OD17); revoke it as `docs/setup/keycloak.md` says. Because `login --mcp`
uses the device grant, any shell the harness can run, a T3 Code thread
included, can start it: the owner only opens the printed URL and
consents. All sessions using this login are one agent; each keeps its own
elevation handle.
