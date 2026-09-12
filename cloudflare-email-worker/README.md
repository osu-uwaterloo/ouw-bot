# Cloudflare Email Worker

This Worker passes mail addressed to `verify@ouw.s23.moe` to the bot without
altering the raw message. The bot verifies Waterloo's DKIM signature itself.

1. Confirm `BOT_INBOUND_URL` in `wrangler.jsonc` is the public HTTPS URL of the
   bot.
2. Generate a long random secret and put the same value in the bot's
   `EMAIL_VERIFICATION_WEBHOOK_SECRET` setting.
3. Store the Worker copy with `npx wrangler secret put WEBHOOK_SECRET`.
4. Deploy with `npx wrangler deploy`.
5. In Cloudflare Email Routing for `ouw.s23.moe`, create a custom-address rule
   sending `verify@ouw.s23.moe` to this Worker.

Do not store `WEBHOOK_SECRET` in `wrangler.jsonc` or commit it.
