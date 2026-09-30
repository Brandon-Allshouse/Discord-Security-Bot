# Privacy and data

What Equinox reads, what it keeps, where, for how long, and who else ever sees any of it. Everything here is taken from the code (`packages/db/src/schema.ts` and the Redis keys in `packages/core`); if the code and this page ever disagree, that's a bug.

> This page describes how the software handles data. It isn't a legal privacy policy for a hosted service; whoever runs Equinox for others should publish one based on it.

- [What Equinox reads](#what-equinox-reads)
- [What it keeps in the database](#what-it-keeps-in-the-database)
- [What it keeps in Redis](#what-it-keeps-in-redis)
- [Who else sees anything](#who-else-sees-anything)
- [Logs](#logs)
- [Between servers](#between-servers)
- [Your data and deleting it](#your-data-and-deleting-it)

## What Equinox reads

| From | What | Kept? |
|---|---|---|
| Messages in servers it's in | The text, to find links | **No.** The text is scanned in memory and dropped. Discord's message cache is turned off. Only the links it flags are kept, as normalized URLs. |
| Edits to messages | The new text, to catch links added later | No, same as above |
| Servers | ID, name, channels and roles (names and what the bot may do with them) | ID and name in the database; channel and role names for 15 minutes in Redis (for the dashboard) |
| Dashboard logins (Discord OAuth) | Your user ID, username, and the servers you're in with your permissions | ID, username and the servers you manage, for the length of your session (1 hour) |

Equinox never reads direct messages, member lists, voice, or anything in servers it isn't in.

## What it keeps in the database

Postgres. Each server's rows are walled off from every other server's by row-level security.

| Table | What's in a row | How long |
|---|---|---|
| `guilds` | Server ID and name, mode, alert channel ID, mod role IDs, quarantine role ID, when the bot joined and left | While the bot is in the server; kept (deactivated) after it leaves, so settings come back if it's re-added |
| `detections` | Server, user, channel and message IDs; the normalized link; the verdict (level, score, sources, reasons); actions taken (including alert message IDs); review status and who reviewed it | **90 days**, then deleted by an hourly job |
| `guild_allowlist` | Server ID, domain, who added it (user ID), when | Until someone removes it |
| `audit_log` | Server ID, who (user ID or `bot`), what happened, the target (a user ID, domain or similar), details | Kept; nobody, not even Equinox, can edit or delete entries. A retention period comes with the privacy tooling in M9 |
| `provider_results` | A link or domain, which intel source answered, its verdict and small details (engine counts, registration date) | Malicious answers 30 days, others 24 hours; deleted hourly. Contains no server or user IDs |

No table stores message text. `detections` has an `evidence` column for the future; nothing writes to it yet.

## What it keeps in Redis

Redis holds short-lived data. Every key is listed here.

| Key | What | How long |
|---|---|---|
| `equinox:session:<hash>` | A dashboard session: your user ID, username, the servers you manage, a CSRF token. Stored under a hash of the session ID | 1 hour |
| `equinox:guild:<id>:snapshot` | A server's channel and role names, and which permissions the bot is missing | 15 minutes, refreshed while the bot runs |
| `equinox:blocklist:domain` | Known scam domains (no server or user information) | Until removed |
| `equinox:feed:urlhaus:urls`, `…:meta` | URLhaus's public list of malware links, and when it was last downloaded | Replaced every 15 minutes |
| `equinox:intel:summary:<hash>` | What the intel sources said about a link (no server or user information) | 30 days if malicious, otherwise 24 hours |
| `equinox:intel:waiters:<hash>` | Messages waiting for a link's intel answer: server, channel, message and user IDs, and the local score and reasons | 1 hour at most, deleted once answered |
| `equinox:intel:status` | Whether the intel worker is running, whether VirusTotal is on, when URLhaus last synced | 3 minutes, refreshed every minute |
| `equinox:budget:virustotal:*` | How many VirusTotal lookups were made today and in the last minute | 2 days / 61 seconds |
| `equinox:api:nonce:<nonce>` | Nonces of recent dashboard → API requests, to stop replays | 3 minutes |
| `equinox:bot:shards` | How many bot shards are running | Until the next start |
| `equinox:bull:*` | Work queues: intel lookups (a link and a score), VirusTotal lookups, feed syncs, and dashboard requests to the bot (server, user and detection IDs, a decision or chosen channel and roles) | Removed when done; the last 100 failed intel jobs are kept for troubleshooting |

## Who else sees anything

| Who | What they get | When |
|---|---|---|
| Discord | Whatever Equinox does in your server (alerts, deletes, roles), and your dashboard login | Always |
| The domain's registry (RDAP) | A domain name | When a link with an unknown domain is checked |
| The link's own site | A visit, with no cookies or personal information | Only for shortened links and links that already look suspicious, to see where they lead |
| abuse.ch (URLhaus) | Nothing about you; Equinox only downloads their list | Every 15 minutes |
| VirusTotal | A link | Only for links that already show a sign of trouble or turn up in several servers. Never files, never submissions for scanning |

No one gets message text, and no outside source is told which server or user a link came from.

## Logs

Services log to standard output in JSON. Log lines carry IDs (server, user, detection) and route patterns, never message text, full URLs of dashboard requests, tokens, keys, passwords or cookies; those fields are blanked out automatically (`logRedactPaths` in `packages/config`). How long logs are kept is up to whoever runs Equinox.

## Between servers

Nothing about one server's members, messages, settings or detections is visible to another server. The only things shared across the network are indicators (scam domains, links, and from M6 file hashes), and they never say which server saw them. Details: [architecture.md](architecture.md) and [security-controls.md](security-controls.md#tenant-isolation).

## Your data and deleting it

Today, a server's admins can see everything stored about their server on the dashboard, remove allowlist entries, and remove the bot (which deactivates the server's settings). Detections expire on their own after 90 days.

`/equinox data`, which lets anyone see what's stored about them and ask for it to be deleted, comes in M9, along with a retention period for the audit log.
