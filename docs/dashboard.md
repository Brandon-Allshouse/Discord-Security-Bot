# The dashboard

Each Discord server with Equinox has its own page on the web dashboard: everything you can do with slash commands and alert buttons, plus the full lists of detections, the allowlist and the audit log. It's deliberately plain for now (no JavaScript, one stylesheet) and gets redesigned in M9.

- [Who can use it](#who-can-use-it)
- [Logging in](#logging-in)
- [Your server's page](#your-servers-page)
- [How it's kept safe](#how-its-kept-safe)
- [Setting it up (operators)](#setting-it-up-operators)
- [Troubleshooting](#troubleshooting)

## Who can use it

Anyone can log in with Discord, but you only see servers where you have **Manage Server** (or are the owner or an Administrator) **and** Equinox is installed. That's the same "admin" as for `/equinox setup`. People with only the mod role use the buttons on alerts in Discord instead.

## Logging in

1. Open the dashboard (locally: <http://localhost:3000>) and choose **Log in with Discord**.
2. Discord asks you to share your identity and your server list. That's all Equinox asks for; it can't read your messages or act as you.
3. Pick a server under **Your servers**.

You stay logged in for an hour. Your server list is read at login, so if you gain or lose Manage Server somewhere, log out and in again (it happens by itself within the hour).

## Your server's page

### Settings

- **Warnings** at the top if something is wrong: no alert channel, the bot can't post in the alert channel any more, or the bot is missing permissions (for example Manage Messages, which it needs to delete scam links).
- **Mode**: `alert_only`, `protect` or `strict`, saved right away. See [getting-started.md](getting-started.md#modes).
- **Alert channel and roles**: the same as `/equinox setup`. The lists only let you pick channels the bot can post in and roles it can use; the bot checks again before saving.
- **Send a test alert**: the same as `/equinox test`. A harmless alert should appear in your alert channel within seconds.

### Detections

The latest 50 detections: when, the verdict and score, the link (defanged, so it can't be clicked), **why** it was flagged (including which threat-intel sources flagged it), who posted it, what the bot did, and the status.

Detections that are still open or confirmed have **Restore**, **False positive** and **Confirm** buttons. They do exactly what the buttons on the Discord alert do (see [getting-started.md](getting-started.md#reviewing-a-detection)), and the alert in Discord is marked resolved so nobody acts on it twice.

### Threat intel

Whether the intel worker is running, when the URLhaus malware list was last downloaded, and whether VirusTotal is on. **Check a link** works like `/equinox check`. See [threat-intel.md](threat-intel.md#using-it-in-the-dashboard).

### Allowlist

Domains that are never flagged in this server, with who added them and when. Add a domain (`example.com`, no path) or remove one. Entries added by a false-positive click show up here too.

### Audit log

The latest 50 entries. Changes made on the dashboard are marked `via: dashboard`. See [getting-started.md](getting-started.md#the-audit-log) for what each entry means.

## How it's kept safe

- **The dashboard holds nothing.** It's the frontend: it renders pages and gets everything from the API, through requests signed with `API_SIGNING_KEY` that can't be forged, changed or replayed. It has no database, Redis or Discord credentials, and on Docker's network it can reach only the API. See [architecture.md](architecture.md).
- **No bot token outside the bot.** Things that need Discord permissions (review, setup, test alert) go from the API to the bot as requests signed with a second key, `INTERNAL_SIGNING_KEY`. The bot refuses any request that isn't signed, or is more than two minutes old, checks everything again, and records it in the audit log under your Discord ID.
- **Only your servers.** Every page and every button checks that you manage that server. Another server's page answers "Not found", the same as a server that doesn't exist.
- **Forms can't be forged from other sites.** Every form carries a secret token tied to your session.
- **Short sessions.** The API keeps sessions: they last an hour, get a new ID at every login, and are stored under a hash so reading Redis doesn't hand out sessions. Discord's access token is handed back right after login, never stored.
- **Strict pages.** No scripts are allowed at all (Content-Security-Policy), pages can't be framed, and nothing is cached. Over https, cookies are `Secure` and use the `__Host-` prefix, and HSTS is sent.
- **Rate limits.** The dashboard limits each address (120 requests and 10 logins a minute); the API limits each person (10 link checks and 30 review, setup or test requests a minute).

Details and the standards behind them: [SECURITY.md](../SECURITY.md) and [security-controls.md](security-controls.md#dashboard).

## Setting it up (operators)

In the [Discord developer portal](https://discord.com/developers/applications), open your application → **OAuth2**:

1. Copy the **Client Secret** into `DISCORD_CLIENT_SECRET` in `.env`. Only the API gets it.
2. Under **Redirects**, add `http://localhost:3000/auth/callback` (or your public address + `/auth/callback`) and click **Save Changes**.

In `.env`:

| Variable | What it is |
|---|---|
| `DISCORD_CLIENT_SECRET` | From the OAuth2 page. The API only; the dashboard and the bot never see it. |
| `API_SIGNING_KEY` | Required. Signs every dashboard → API request. Generate with `openssl rand -hex 32` in Git Bash; the dashboard and the API both read it from `.env`. |
| `DASHBOARD_URL` | The public address, default `http://localhost:3000`. Must be `https://` in production. |
| `INTERNAL_SIGNING_KEY` | Signs API → bot requests. Generate with `openssl rand -hex 32` in Git Bash (on Windows; it comes with Git for Windows); the API and the bot both read it from `.env`. It must be different from `API_SIGNING_KEY`. Without it, review, setup and test on the dashboard are off and the page says so; everything else works. |

Then `docker compose up -d --build`. The dashboard container gets only `DASHBOARD_URL`, `API_URL` and `API_SIGNING_KEY`.

## Troubleshooting

| What you see | Cause | Fix |
|---|---|---|
| Discord: "Invalid OAuth2 redirect_uri" | The redirect isn't saved in the developer portal. | Add it under OAuth2 → Redirects and click **Save Changes**. |
| "Login failed. The login didn't complete." | You opened the dashboard at a different address than `DASHBOARD_URL` (`127.0.0.1` instead of `localhost`). | Use the exact `DASHBOARD_URL` address. `docker compose logs dashboard` says which check failed. |
| Your server isn't listed | You don't have Manage Server there, or Equinox isn't in it. | Check both, then log out and in again. |
| "This needs INTERNAL_SIGNING_KEY…" | No signing key configured. | Add it to `.env` (see above) and rebuild the bot and dashboard. |
| "The bot refused the request…" | The bot and the API have different `INTERNAL_SIGNING_KEY` values. | Use the same value for both, then rebuild both. |
| "Temporarily unavailable" on every page | The API is down, or the dashboard and the API have different `API_SIGNING_KEY` values (`docker compose logs dashboard` says which). | `docker compose ps api`, `docker compose logs api`; check the key. |
| "Something went wrong. Reference: …" | An unexpected error in the API. | `docker compose logs api` and search for that reference. |
| "The bot isn't reachable" or "didn't answer in time" | The bot is down, restarting, or not connected to Discord. Nothing was changed. | `docker compose ps bot`, then `docker compose logs bot`. |
| "The bot hasn't reported this server's channels and roles yet" | The bot hasn't sent this server's details (they refresh every few minutes and on every channel or role change). | Wait a minute, or check that the bot is running. |
| A warning about missing permissions | The bot's role lost a permission it needs. | Server Settings → Roles → the bot's role. |
