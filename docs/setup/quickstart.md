# Try it locally

`dev/quickstart.sh up` runs Nyyrikki on your machine to try it out:
a kind cluster, Keycloak and Nyyrikki, all built from your checkout,
plus a pod in the cluster for the agent. Approvals go through a real
Telegram bot that you make for the purpose. `dev/quickstart.sh down`
removes everything it made.

This is not a deployment. Keycloak runs in development mode, and every
password is generated and kept in `dev/.quickstart/`. To deploy, follow
the [setup](README.md) instead.

## Your machine is the human's, the pod is the agent's

While the quickstart is up, **run no AI agent on the machine you started
it on.** That machine holds kind's admin kubeconfig
(`dev/.quickstart/kubeconfig`). The kubeconfig can read the Secret that
holds the bot token, and it administers the cluster that Nyyrikki
guards. With the token, an agent could fetch the bot's updates and take
your taps before Nyyrikki sees them. With the kubeconfig it wouldn't
need Nyyrikki at all.

The agent's machine is the pod `nyyrikki-agent` in the namespace
`nyyrikki-agent`. It holds the `nyyrikki` CLI, the stack's CA and, once
you sign it in, its own Nyyrikki login. It has no ServiceAccount token
and no rights in the cluster. `dev/quickstart.sh agent` opens a shell in
it. Run your agent there, or on another machine that holds nothing but
its Nyyrikki login ([agents.md](agents.md)).

## What you need

- **Linux with Docker Engine.** The issuer and Nyyrikki's URL are
  addresses on a docker network. A Linux host reaches them, but Docker
  Desktop (macOS, Windows) doesn't, so the script refuses to run there.
- `docker`, `kind`, `helm`, `kubectl` and Go (the version in `go.mod`) on
  `PATH`.
- Internet access for pulling Keycloak, busybox and the kind node image,
  for Go modules, and for nyyrikkid to reach `api.telegram.org`.
- The docker subnet `10.232.0.0/24` free. The end-to-end test uses
  `10.231.0.0/24` and other names, so the two can run side by side.
- A few minutes for the first run, which builds the image.

## A throwaway bot

1. In Telegram, make a **new** bot with **@BotFather** (`/newbot`). Use
   it only for this, and delete it (`/deletebot`) when you're done.
   **Never use the bot of a real deployment.**
2. Send the bot any message from your own Telegram account. `up` reads
   who has written to the bot and asks you which one is you. Nyyrikki
   then obeys only that account's taps.

## Up

```sh
dev/quickstart.sh up
```

The script explains the above, then asks for the token (not echoed).
It checks the token with Telegram's `getMe`, then lists the accounts that
have written to the bot (from `getUpdates`, which leaves the updates in
place for Nyyrikki) and asks you to confirm or pick yours. All of that
happens before anything is built. The token then goes only into the
cluster's Secret: it isn't written to any file on your machine, and it is
never printed. For a run without a terminal, set
`NYYRIKKI_QUICKSTART_BOT_TOKEN` and `NYYRIKKI_QUICKSTART_TELEGRAM_USER`
(your user ID) for that one command. The script takes the token out of
its environment before it runs anything else. Don't export the token in a
shell profile, where every program you start would inherit it.

At the end it prints what to do next, and keeps a copy in
`dev/.quickstart/info.txt`. In short:

1. **Say hello to the bot.** Send `/start` to your bot. Nyyrikki can
   only write to you after you've written to the bot, and the reply
   shows your ID.
2. **Sign the agent in.** In the agent's shell:

   ```sh
   dev/quickstart.sh agent
   nyyrikki login --server https://10.232.0.x:30443 --ca-file /etc/nyyrikki/ca.crt
   ```

   `login` prints a URL and a code. Open the URL in a browser on your
   machine and accept the certificate warning: the certificate comes from
   the stack's own CA, `dev/.quickstart/ca.crt`. Then sign in as `owner`
   with the password `up` printed. Typing the password is the human's
   part, so it happens in your browser, never in the agent's shell.
3. **Make a request and approve it.** In the agent's shell:

   ```sh
   nyyrikki targets
   nyyrikki run --reason "first try" this-cluster -- auth whoami
   ```

   Listing targets needs no approval. The `run` waits while Telegram
   shows you the request exactly as it will be forwarded, with the
   agent's reason marked as its claim. Tap Approve and it prints
   `owner@example.com`, the user the request ran as. Tap Deny and it
   exits with 77.
4. **Elevate.** In the agent's shell,
   `export NYYRIKKI_ELEVATION=$(nyyrikki elevate --reason "try it" --for 5m this-cluster)`,
   then approve. Runs that carry the handle go through without asking
   until the window ends:

   ```sh
   nyyrikki run --reason "a write" this-cluster -- create configmap hello -n quickstart --from-literal=greeting=hi
   nyyrikki run --reason "read it back" this-cluster -- get configmap hello -n quickstart -o yaml
   ```

   The human, `owner@example.com`, may change things only in the
   namespace `quickstart`, where Pod Security forbids privileged and
   `hostPath` pods. Requests run as the human, so an elevation can do no
   more than that. It can't read Nyyrikki's Secrets (the bot token among
   them), change Nyyrikki, or become root on the kind node, which is your
   machine. A real deployment needs the same narrow rights
   ([SECURITY.md](../../SECURITY.md), Accepted risks). [agents.md](agents.md) covers the rest of the
   CLI and MCP harnesses.

The agent's login lives in the pod's home directory, an `emptyDir`, so
it goes away with the pod. Sign in again after a restart.

## Down

```sh
dev/quickstart.sh down
```

This removes the kind cluster (the agent's pod with it), the Keycloak
container, the docker network, the `nyyrikki:quickstart` and
`nyyrikki-agent:quickstart` images, and `dev/.quickstart/`. It then
checks that none of them is left. Images that were only pulled, such as
Keycloak, busybox and the kind node, stay in docker's cache. Then delete
the bot with @BotFather.

## When it fails

- **The token is refused**, either by `getMe` or by nyyrikkid. Check that
  it's the whole token, or make a new bot.
- **nyyrikkid stopped polling.** Another program polls the same bot. A
  bot has one poller, and Nyyrikki then stops for good (docs/05 D2). Stop
  the other program, then `down` and `up`.
- **Already up.** Run `down` first.
- **Ctrl-C during `up`** stops the step that runs and removes what was
  made so far.
- **Anything else.** `up` prints nyyrikkid's pods and logs, then removes
  what it made. With `NYYRIKKI_QUICKSTART_KEEP=1` it leaves the stack in
  place so you can look, and `down` removes it afterwards.

The quickstart builds its stack with the same code as the end-to-end test
(`test/stack`), so the e2e keeps it working. Only the Telegram side
differs: the e2e uses a fake Bot API that the test drives, and the
quickstart uses the real one.
