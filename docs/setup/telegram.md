# Telegram

1. In Telegram, talk to **@BotFather**: `/newbot`, then pick a name. Keep
   the token: it goes only into a Kubernetes Secret
   (`secrets.telegram`), never on a machine an agent can reach.
2. `/setjoingroups` → Disable. The bot works only in private chats.
3. After installing Nyyrikki, open a chat with the bot and send `/start`.
   It answers with your numeric user ID; put it in the chart's
   `human.telegramUserID` and upgrade.
4. **Protect the approver's account**: turn on 2-Step Verification and a
   passcode lock, and check Settings → Devices for sessions you don't
   know. A bot can't check either (SECURITY.md).

Never sign in to Telegram on anything an agent controls: whoever holds
that session can approve anything.

Nyyrikki uses long polling only (no webhook). If another process polls the
same token, Nyyrikki stops and denies every escalation until restarted
(docs/05 D2). `/readyz` then fails.
