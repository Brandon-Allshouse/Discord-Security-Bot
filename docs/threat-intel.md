# Threat intel

This page explains what Equinox's threat intel does, how to use it from Discord and from the dashboard, how it decides what's dangerous, and how to run and troubleshoot it.

- [What it's for](#what-its-for)
- [How it works](#how-it-works)
- [The sources](#the-sources)
- [How scores add up](#how-scores-add-up)
- [Using it in Discord](#using-it-in-discord)
- [Using it in the dashboard](#using-it-in-the-dashboard)
- [What happens in each mode](#what-happens-in-each-mode)
- [Limits](#limits)
- [Privacy](#privacy)
- [Setting it up](#setting-it-up)
- [Running it and troubleshooting](#running-it-and-troubleshooting)
- [Questions](#questions)

## What it's for

When someone posts a link, Equinox first judges it with what it knows locally: the network blocklist, your server's allowlist, and its own lookalike checks (`dlscord.gift`, `steamcomnunity.ru` and so on). That's instant, and it catches the classic scams.

It can't catch a scam site that looks like nothing in particular: a random-looking domain, a link hidden behind `bit.ly`, or a malware download on an ordinary host. Threat intel covers that gap. It asks outside sources that track these things, and uses what they say.

In short: **local checks catch lookalikes instantly; threat intel catches what local checks can't recognise, a few seconds to a few minutes later.**

## How it works

1. **The first look (instant).** A link is posted. The bot judges it on everything already known about it, including any threat-intel answer cached from an earlier lookup of the same link, from any server. If that's enough, it acts right away (alert, and delete in `protect` mode).
2. **The lookup (seconds to minutes).** If nothing is known about the link yet, the bot hands it to the intel worker, a separate service. The worker asks the sources below, cheapest first, and stops once it's confident. VirusTotal comes last and has its own slower queue because of its rate limits.
3. **Coming back to the message.** When the answer arrives, the bot runs the message through the same pipeline again:
   - A link that looked fine but turns out bad gets an alert (and is deleted in `protect` mode).
   - A link that already had a "suspicious" alert and turns out malicious is **escalated**: a new alert marked "⬆️ Now malicious: link updated by threat intel" shows the new verdict, and your mode's extra actions run.
   - A detection your mods already handled (confirmed, restored, false positive) is left alone.
4. **Next time.** The answer is cached (30 days if malicious, a day otherwise), so the same link posted anywhere later is judged in step 1.

Only a link and the IDs of the message it was in go to the worker, never the message text.

## The sources

| Source | What it tells us | What's sent, and where |
|---|---|---|
| **Redirects** | Where a shortened link (`bit.ly`, `tinyurl.com` and about 30 others) really leads. The destination then gets the same lookalike checks as the link itself. | The worker visits the link itself, safely (see [SECURITY.md](../SECURITY.md)). Only shorteners and links that already look a little off are visited. |
| **URLhaus** (abuse.ch) | Whether the exact link is on URLhaus's list of links currently serving malware. | Nothing per link. The whole list is downloaded every 15 minutes and checked locally. |
| **Domain age** (RDAP) | When the domain was registered. Scam sites are usually days old. | The domain name (not the full link) goes to the registry that runs that domain's ending, for example Verisign for `.com`. |
| **VirusTotal** | How many of VirusTotal's ~90 security engines flag the link. | The link goes to VirusTotal, only if it already shows a sign of trouble or turns up in several servers. Lookups only: nothing is ever submitted for scanning. |

## How scores add up

Every check gives a weight between 0 and 1. Weights combine so that independent weak signs add up, but never past 100%. A link at **50%** or more is *suspicious*, and at **80%** or more *malicious*. One weak sign on its own never reaches "suspicious": a false alarm is worse than a miss.

| Signal | Weight |
|---|---|
| Listed on URLhaus | 95%, malicious on its own |
| VirusTotal: 3 or more engines say malicious | 90%, malicious on its own |
| VirusTotal: 2 engines say malicious | 45% |
| VirusTotal: 1 engine says malicious | 30% |
| VirusTotal: 3 or more engines say suspicious | 25% |
| Domain registered in the last 7 days | 40% |
| Domain registered in the last 30 days | 20% |
| Redirects to a private or internal address | 30% |
| Goes through 5 or more redirects | 20% |
| A shortened link leads somewhere that fails the lookalike checks | whatever that destination scores |

Some examples:

- A brand-new domain on its own: 40%, no alert.
- A domain that uses the Discord name (45% from the local checks) and was registered 2 days ago (40%): 67%, **suspicious**.
- A `bit.ly` link that leads to a URLhaus-listed download: 95%, **malicious**.

Intel only ever raises a score. A clean answer from VirusTotal doesn't cancel a lookalike domain. Your server's allowlist always wins.

## Using it in Discord

**Alerts.** An alert for a link that threat intel helped catch has a **Threat intel** line ("Found by urlhaus, rdap"), and the **Why** list includes what each source said, for example "Domain was registered 2 days ago" or "Flagged as malicious by 5 VirusTotal engines". An escalation is its own alert, titled "⬆️ Now malicious…", saying what the detection was before. The buttons work the same, and both alerts refer to the same detection.

**`/equinox check url:<link>`** (mods). Checks a link without posting it:

- The first time, for an unknown link, it shows the local verdict and says *"Threat intel: not checked yet. Looking it up now"*. Run it again a minute later for the full answer.
- Once looked up, it shows which sources flagged it, or *"no source knows of problems"*.
- Well-known sites (Discord, Steam, GitHub, YouTube and the like) and allowlisted domains are never sent for lookups.

**`/equinox allow add <domain>`** (admins). If intel flags a site your server trusts, allowlisting its domain overrides every source, in your server only.

## Using it in the dashboard

Open your server's page. Four places relate to threat intel:

- **Detections → Why.** The reasons behind each detection, and which intel sources flagged it.
- **Threat intel.** Whether the worker is running, when the URLhaus list was last downloaded and how many links it has, and whether VirusTotal is on. If the worker isn't running, it says so; detection keeps working on local checks alone.
- **Check a link.** The same as `/equinox check`. Paste a link and press **Check**. For an unknown link it queues a lookup; press **Check again** a minute later.
- **Audit log.** Escalations appear as `detection.escalated`, next to `detection.created`.

## What happens in each mode

When threat intel makes a link worse than it first looked:

| Mode | Link was clean, now suspicious | Link was clean, now malicious | Link was suspicious, now malicious |
|---|---|---|---|
| `alert_only` | Alert | Alert | Escalation alert |
| `protect` | Alert | Delete the message, alert | Delete the message, escalation alert |
| `strict` | Delete the message, alert | Delete the message, alert | Escalation alert (already deleted) |

The message may be gone by the time the answer arrives (deleted by its author or a mod). The alert then shows the delete as ❌ failed, which is harmless.

## Limits

| Limit | Value | Why |
|---|---|---|
| Lookups one server can trigger | 30 a minute | So a server flooding unique links can't crowd out everyone else. Links over the limit are still judged locally. |
| Dashboard link checks | 10 a minute per person | Each check of an unknown link can mean outside lookups. |
| VirusTotal | 4 a minute, 500 a day, across all servers | VirusTotal's free-tier terms. Links seen in several servers go first. When the day's budget is used up, the other sources and local checks carry on until midnight UTC. |
| Queued VirusTotal lookups | 1,000 | 4 a minute can't catch up with more. Lookups past that skip VirusTotal. |
| How long a message waits for its answer | 1 hour | After that, the answer is still cached for next time, but the bot won't go back to that message. |
| Redirects followed | 5 hops, 5 seconds, 1 MB | Safety limits; see [SECURITY.md](../SECURITY.md). |

## Privacy

- The worker gets a link plus the IDs of the message, channel, server and user. Never the message text.
- Outside sources get less: registries get a domain name; VirusTotal gets a link. Nobody gets who posted it or where.
- Which links go to VirusTotal: only links with at least one sign of trouble, or links showing up in several servers. Ordinary links people share aren't sent.
- Which links the worker visits: only shorteners and links that already look off. Ordinary links (including one-time links like password resets) are never visited.
- Cached answers are indicators, not tenant data, and live in a network-wide table no server can read directly. Malicious answers expire after 30 days and everything else after 24 hours.

## Setting it up

Threat intel runs in the `worker` container. It starts with `docker compose up --build`, and works without any keys: redirects, domain age and URLhaus (if abuse.ch allows downloads without a key) all run keyless. VirusTotal needs a key.

In `.env` (never `.env.example`):

| Variable | Needed? | What it is |
|---|---|---|
| `VT_API_KEY` | For VirusTotal | Free account at virustotal.com, then your profile menu → **API key**. 64 characters. |
| `VT_TIER` | No | `public` (default) for the free API. `premium` only with a paid licence. |
| `VT_PER_MINUTE`, `VT_DAILY_BUDGET` | No | Default 4 and 500. With `public`, higher values are refused at startup. |
| `URLHAUS_AUTH_KEY` | Recommended | Free Auth-Key from auth.abuse.ch, sent with the list download. |

After changing `.env`, run `docker compose up -d --build worker`. Then check:

1. `docker compose logs worker` shows `virustotal enabled` (or a warning saying it's off) and, within 15 minutes, `urlhaus feed synced`.
2. The dashboard's **Threat intel** section shows the worker as running.
3. `/equinox check` on a shortened link says "not checked yet" and, a minute later, shows the answer.

The worker never gets the Discord token or the OAuth secret. It's the part that visits links strangers post, so it has as little access as possible.

## Running it and troubleshooting

**Logs.** `docker compose logs -f worker` shows lookups and problems. Keys never appear in logs.

**Operator checks** (these read Redis directly; they aren't shown on the dashboard on purpose, because anyone who installs the bot can see their server's page, and knowing when VirusTotal is used up would help an attacker time a scam):

```bash
# VirusTotal lookups used today (UTC)
docker compose exec redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning get "equinox:budget:virustotal:$(date -u +%F)"'

# Links on the URLhaus list right now
docker compose exec redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning scard equinox:feed:urlhaus:urls'

# VirusTotal lookups waiting in the queue
docker compose exec redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning zcard equinox:bull:intel-virustotal:prioritized'
```

| What you see | What it means | What to do |
|---|---|---|
| Dashboard: "The threat-intel worker isn't running" | No heartbeat for 3 minutes. | `docker compose ps worker`, then `docker compose logs worker`. Detection still works locally meanwhile. |
| Log: `VT_API_KEY not set` | VirusTotal is off. | Add the key (see above), or ignore it: the other sources still run. |
| Log: `VirusTotal rejected VT_API_KEY; pausing…` | The key is wrong or revoked. VirusTotal stays paused until the worker restarts. | Fix the key in `.env`, then `docker compose up -d --build worker`. |
| Log: `urlhaus sync failed, keeping the previous copy` | The download failed. The last good list is still used. | If it says 401 or 403, set or fix `URLHAUS_AUTH_KEY`. Otherwise it retries every 15 minutes. |
| Log: `intel provider failed, continuing without it` | One source timed out or errored for one link (a slow registry, or a link that doesn't exist). | Nothing, unless it's constant for one provider. |
| `/equinox check` keeps saying "not checked yet" | The lookup didn't finish, or the worker is down. | Check the worker as above. If the server hit its 30-a-minute limit, wait a minute. |
| A link VirusTotal flags isn't alerted | 1–2 engines is a weak signal (30–45%) on purpose. It counts, but needs another sign to reach "suspicious". | Nothing, or confirm it by hand. From M5, confirmed links are blocked across the network. |

## Questions

**Why did I get a second alert for the same link?** The first came from the local checks. The second is an escalation: threat intel found the link worse than it first looked. It's marked "⬆️ Now malicious" and refers to the same detection.

**Can I turn threat intel off for my server?** Not yet. You can allowlist domains you trust, which overrides every source in your server.

**Does Equinox upload files or links to VirusTotal?** It never uploads files, and never submits links for scanning. It only looks up reports VirusTotal already has, and only for links that show a sign of trouble or appear in several servers.

**Why isn't everything checked with VirusTotal?** The free API allows 500 lookups a day for every server combined, and sending every link people share to a third party would be bad for privacy. The cheaper sources handle most links.
