# Telegram

1. In Telegram, talk to **@BotFather**: `/newbot`, then pick a name. Keep
   the token: it goes only into a Kubernetes Secret
   (`secrets.telegram`), never on a machine an agent can reach.
2. `/setjoingroups` → Disable. The bot works only in private chats.
3. **Learn your user ID before installing** (nyyrikkid won't start without
   it). On a trusted machine, never one an agent can reach, send any message
   to the bot, then read it back with the token:

   ```sh
   curl -s "https://api.telegram.org/bot$(cat bot-token)/getUpdates" | grep -o '"from":{"id":[0-9]*'
   ```

   Put the number in the chart's `human.telegramUserID`. Do this before
   installing: once Nyyrikki is polling, it takes the updates itself (and
   a second poller makes it stop, docs/05 D2). After install, `/start`
   answers with your ID as a check.
4. **Protect the approver's account**: turn on 2-Step Verification and a
   passcode lock, and check Settings → Devices for sessions you don't
   know. A bot can't check either (SECURITY.md).

Never sign in to Telegram on anything an agent controls: whoever holds
that session can approve anything.

Nyyrikki uses long polling only (no webhook). If another process polls the
same token, Nyyrikki stops and denies every escalation until restarted
(docs/05 D2). `/readyz` then fails.
