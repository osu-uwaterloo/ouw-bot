# o!uw bot

o!uw bot is a Discord bot for osu!uwaterloo that provides various features to imporove the quality of life for the club server.

> **Warning**
> This bot is highly specialized for osu!uwaterloo. If you want to use this bot for your own server, you will need to modify the code a lot.

## Features

### Verification

- Provides an interface for new members to verify themselves
- Allow UW students to verify themselves with their watiam and email
- Has a voucher system for non-UW students to automatically verify the invited user
- Supports integration with osu! API for osu! account linking
- Allows users to add their social media links to their profile
- Automatically restores previous-verified users' status
- User/message context menu shortcut for adding verified roles to user to simplify the manual verification process for admins

### Sheet integration

- Auto records user's watiam, Discord ID, osu! account and so on to a sheet

### Logging

- Logs all verification events to a channel

### Colour roles

- Allows users to get a custom hex colour role
- Maintains a colour role list and will remove unused roles
- Contrast check to ensure the colour is readable

### Miscellaneous QOL

- Maintains a 2FA code generator for club Twitch account
- Export the watiams of all the reacted members of a message

### Fun

- React 🐱 to meowssages
- Reply a sequence of meow if a message meowed a lot
- Send a message everyday at 7:27 PM (time time time)
- For the "time" messages that posted within +/- 10 minutes of 7:27 PM, react the offset time of that message
- ~~For the "time" messages that posted at else time, DM the user "skill issue"~~ Removed
- Timeout users who post "nailong" tenor gifs for random short durations
- Post messages on behalf of the bot

## Admin ! commands

- `!setupverify` - Setup the verification message (with a request verification button)
- `!setupcolour` - Send a message explaining the colour role system
- `!setuptwitch2fa` - Setup a message with a button which provides the 2FA code for the club Twitch account

## Setup

This bot was written in Node.js and can be deployed very simply.

### Environment variables

There are two ways to set up the environment variables:

1. Create a `env.json` file in the root directory.
2. Or setup an environment variable `CONFIG_JSON` with the content of `env.json`.

Here is a template for the `env.json` file:

```jsonc
{
	"DISCORD_BOT_TOKEN": "The discord bot token",
	"SERVER_ID": "The server you want to run the bot in",
	"ROLE_ID": {
		"CURRENT_UW_STUDENT": "The role ID for 'current UW students'",
		"VERIFIED": "The role ID for 'verified'",
		// Current UW student will have both roles, but non-UW students will only have the 'verified' role
	},
	"SKIP_ROLE_IDS": [
		"727727727727727"
		// A list of role IDs that will be skipped when verifying
		// For example, `Alumni` role, you want the bot to treat this as verified
	],
	"COLOUR_ROLE_IDS": {
		"COLOUR_ROLE_SECTION_BEGIN": "727727727727727",
		"COLOUR_ROLE_SECTION_END": "727727727727727"
		// There is a section in the role list that contains all the colour roles
		// Here are the beginning and ending role IDs of that section (they are seperator roles just for indicate this section in the role list)
		/* For example, a role list:
		----- COLOUR ROLES -----   <-- This is the beginning role ID
		#727727
		#123456
		...
		----- END COLOUR ROLES -----   <-- This is the ending role ID
		*/
	},
	"EXEC_ROLE_ID": "727727727727727", // Role ID of executives
	"VERIFY_CHANNEL_ID": "727727727727727", // Channel ID of the manual verification channel )where the voucher system runs)
	"LOGGING_CHANNEL_ID": "727727727727727", // Channel ID of the logging channel to log the bot events
	"TIME_727_SPAM_CHANNEL_ID": "727727727727727", // Channel ID of the time spam channel (bot posts "time" messages here)
	"ADMIN_IDS": [
		"727727727727727"
		// A list of user IDs that are admins of the bot
	],
	"URL": "http://localhost:3000", // The URL of the bot, where the verification website hosts, without slash at the end
	"SMTP_EMAIL": "osu@clubs.wusa.ca", // The email address of the SMTP server, which sends verification emails
	"SMTP_PASSWORD": "meowmeowmeownyanyanyawysi", // The password of the SMTP server
	"AES_ENCRYPTION_SECRET": "MEOWMEOWMEOW", // The secret for AES encryption, for the verification url state. Generate a random string for this
	"GOOGLE_CLIENT_EMAIL": "ouw-bot@osu-uwaterloo.iam.gserviceaccount.com", // The service account email for Google Sheets API
	"GOOGLE_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----MEOW-----END PRIVATE KEY-----\n", // The private key for Google Sheets API
	"GOOGLE_SHEET_ID": "sheetid", // The ID of the Google Sheet for recording, ID can be found in the URL
	// ### About google sheet API, refer to https://theoephraim.github.io/node-google-spreadsheet/#/guides/authentication?id=service-account
	"OSU_CLIENT_ID": "12345", // osu! oAuth client ID
	"OSU_CLIENT_SECRET": "meowmeowmeownyanyanyawysi", // osu! oAuth client secret
	"TWITCH_2FA_TOTP_URL": "otpauth://totp/Twitch?secret=WYSIWYSIWYSI&issuer=Twitch" // The TOTP URL for the Twitch 2FA code, you can get it by scanning the QR code when setting up the 2FA
}
```


### Deployment

```
npm i
npm start
```

You can also use PM2 to manage the node process (although it is already very stable).

## License

This project is licensed under the MIT License.

## Maintainer

- [@solstice23](https://github.com/solstice23)

