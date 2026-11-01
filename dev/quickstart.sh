#!/usr/bin/env bash
# Try Nyyrikki locally (docs/setup/quickstart.md, docs/09 D6).
#   dev/quickstart.sh up      a kind cluster, Keycloak and Nyyrikki from this
#                             checkout, approving through your Telegram bot,
#                             and a pod for the agent to run in
#   dev/quickstart.sh agent   a shell in the agent's pod
#   dev/quickstart.sh down    remove everything up made
#
# The bot token is read without echo, or, for a run without a terminal, from
# NYYRIKKI_QUICKSTART_BOT_TOKEN (never export it in a profile). It goes only
# into the cluster's Secret: it is written to no file on this machine and
# never printed.
#
# This machine is the human's while the quickstart is up: it holds kind's
# admin kubeconfig, which can read the bot token's Secret. Run no AI agent
# on it; run agents in the agent's pod.
set -euo pipefail

# First of all, before any command runs: take the token out of the
# environment, so no child process (docker, kind, go) inherits it.
qs_token=${NYYRIKKI_QUICKSTART_BOT_TOKEN-}
unset NYYRIKKI_QUICKSTART_BOT_TOKEN

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state=$root/dev/.quickstart
name=nyyrikki-quickstart

die() { printf 'quickstart: %s\n' "$*" >&2; exit 1; }

usage() {
  echo "usage: dev/quickstart.sh up|agent|down" >&2
  exit 2
}

need() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH (docs/setup/quickstart.md lists what to install)"
  done
}

preflight() {
  if [ "$(uname -s)" != Linux ]; then
    die "Linux only. The issuer and Nyyrikki's URL are addresses on a docker network, which a Linux host reaches and a Mac (Docker Desktop) does not."
  fi
  need docker kind helm kubectl go
  docker info >/dev/null 2>&1 || die "docker is not running, or this user can't use it"
  case $(docker info --format '{{.OperatingSystem}}' 2>/dev/null) in
    *"Docker Desktop"*) die "Docker Desktop doesn't route the host to container addresses; use Docker Engine on Linux." ;;
  esac
}

up() {
  if kind get clusters 2>/dev/null | grep -qx "$name"; then
    die "a quickstart is already up; remove it with dev/quickstart.sh down first"
  fi
  cat >&2 <<'EOF'
Nyyrikki asks you on Telegram before it runs anything, so the quickstart
needs a Telegram bot of your own (docs/setup/quickstart.md):

  * Make a NEW bot with @BotFather, used only for trying Nyyrikki, and
    delete it (/deletebot) when you are done. Never use the bot of a real
    deployment.

  * Send your new bot any message from your own Telegram account. up
    lists who has written to it and asks which one is you: Nyyrikki
    obeys only that account's taps.

  * While the quickstart is up, run NO AI agent on this machine. The token
    goes into the kind cluster's Secret, and this machine holds kind's
    admin kubeconfig, which can read it: with the token, an agent could
    take your taps before Nyyrikki sees them. Agents run in the agent's
    pod (dev/quickstart.sh agent), which holds only their Nyyrikki login.

EOF
  local token=$qs_token uid=${NYYRIKKI_QUICKSTART_TELEGRAM_USER:-}
  qs_token=
  if [ -z "$token" ]; then
    [ -t 0 ] || die "no terminal to ask on: set NYYRIKKI_QUICKSTART_BOT_TOKEN"
    IFS= read -rsp "Bot token (not shown): " token
    echo >&2
  fi
  [ -n "$token" ] || die "no bot token"
  # Without it, the program finds the ID among who has written to the bot.
  local user_flag=()
  if [ -n "$uid" ]; then
    [[ $uid =~ ^[1-9][0-9]*$ ]] || die "NYYRIKKI_QUICKSTART_TELEGRAM_USER is a Telegram user ID, a number such as 123456789"
    user_flag=(-telegram-user "$uid")
  fi

  cd "$root"
  # The token goes to the program on a pipe: printf is a builtin, so it is
  # in no process's argv or environment, and in no file.
  printf '%s\n' "$token" | go run -tags quickstart ./dev/quickstart up "${user_flag[@]}" "$@"
}

agent() {
  need kubectl
  [ -f "$state/kubeconfig" ] || die "no quickstart is up; start one with dev/quickstart.sh up"
  exec kubectl --kubeconfig "$state/kubeconfig" -n nyyrikki-agent exec -it nyyrikki-agent -- sh
}

down() {
  cd "$root"
  exec go run -tags quickstart ./dev/quickstart down
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
  up)    preflight; up "$@" ;;
  agent) agent ;;
  down)  preflight; down ;;
  *)     usage ;;
esac
