# Equinox

A security sensor for Discord servers, backed by a shared threat-intelligence network.

> **Status:** early prototype. Milestones M0–M4 are done: the core pipeline, tenant isolation, onboarding, alerts with review buttons, link protection, a first, bare-bones web dashboard, and threat-intel lookups. Everything from M5 onward is still planned. "Equinox" is a working name; to rebrand, change `BRAND` in `packages/core/src/brand.ts`.

Think of it as [Sublime Security](https://sublime.security) or [Abnormal Security](https://abnormalsecurity.com), but for Discord instead of email. You add the Equinox bot to your server and it acts as a sensor: it watches for phishing links, and later malicious files, hijacked accounts and raids. What it sees goes through a detection engine that scores it, acts on it according to your server's settings, and gives your mods an alert they can triage with one click.

Each server is its own tenant. Your detections, settings, allowlist and audit log belong to your server alone, and the database enforces that. The one thing servers share is indicators. When a scam domain gets confirmed in one server, every other server is protected from it within seconds.

**Guides:** [getting started](docs/getting-started.md) (setup, modes, alerts) · [link protection](docs/link-protection.md) · [threat intel](docs/threat-intel.md) · [dashboard](docs/dashboard.md) · [architecture](docs/architecture.md) · [privacy](docs/privacy.md) · [development](docs/development.md) · [all docs](docs/README.md)

## How it fits together

- **The sensor** (`apps/bot`) is the Discord bot. It reads messages as they arrive, turns anything interesting into a `Signal`, carries out whatever actions the policy calls for, and posts alerts with triage buttons.
- **The detection engine** (`packages/core`) is plain TypeScript with no Discord in it, so it's easy to test. It holds the detectors, the verdict logic, and the policy table that decides what to do in each mode.
- **Tenant data** (`packages/db`) lives in Postgres. Each server's settings, detections, allowlist and audit log are walled off with row-level security.
- **The intel worker** (`apps/worker`) looks up links the sensor knows nothing about: it follows redirects safely, checks how old the domain is, checks the URLhaus malware feed, and asks VirusTotal within its free-tier limits. Answers are cached, and sent back to the sensor if they change a verdict.
- **The dashboard** (`apps/dashboard`) is the web side of a tenant: the frontend. Server admins log in with Discord and see and manage their own server. It renders pages and holds no data or credentials of its own: it gets everything from the API.
- **The API** (`apps/api`) is the backend for the dashboard, and the only thing the dashboard talks to. It handles login, sessions, access checks and every read and write, and it's the part that talks to the database, Redis and (through signed requests) the bot. How the parts talk and what each is trusted with: [docs/architecture.md](docs/architecture.md).
- **The threat network** is the shared list of bad domains, URLs and file hashes. Today that's a Redis blocklist; M5 adds the scoring service that promotes indicators across servers. It never carries message content, and never says which server saw what.

### Tenants

One Discord server is one tenant, and the tenant ID is just the server ID. A tenant is created when Equinox joins a server. When it leaves, the tenant is deactivated, not deleted, so settings come back if it rejoins.

Isolation doesn't depend on every query remembering a `WHERE guild_id = …`. Tenant queries run as a restricted Postgres role (`equinox_tenant`) under row-level security, so a query that forgets its filter still only sees its own server. Writes into another server's data are rejected outright. The only code that runs outside that boundary is a small set of system jobs, like deleting expired data.

Every server sets its own mode, alert channel, mod role, quarantine role and allowlist. If your mods mark something as a false positive, that only affects your server.

## What it does

Done:

- **Tenant isolation.** Covered above.
- **Link protection.** Pulls links out of messages, including disguised ones (`hxxp`, `[.]`, zero-width characters, markdown links, bare domains). It normalizes them and checks them against the blocklist and a lookalike detector for Discord, Steam, Epic, Roblox and the big crypto wallets.
- **Threat intel.** Links nothing is known about yet go to the intel worker. It follows shortened links to where they really go, checks the domain's age, checks the URLhaus malware feed, and asks VirusTotal as a last resort. If the answer makes a link look worse, Equinox comes back to the message: it raises an alert, or escalates the one it already posted and takes whatever action your mode calls for. The full guide is [docs/threat-intel.md](docs/threat-intel.md).
- **Dashboard.** Log in with Discord, pick a server you manage, and do everything the slash commands and alert buttons do: review detections, set the alert channel and roles, change the mode, manage the allowlist, check links, send a test alert, and read the audit log. It's plain on purpose and will be redesigned in M9; see [docs/dashboard.md](docs/dashboard.md).

Planned:

- **Network propagation.** A link confirmed malicious in one server gets blocked in all of them within 10 seconds. A false-positive call un-blocks it just as fast.
- **File scanning.** Hash attachments as they stream in (nothing is written to disk), flag risky and disguised file types, and look up known-bad hashes.
- **Hijacked account detection.** Catch an account posting the same scam across channels or servers. Quarantine it, clean up the spam, and DM the owner how to get their account back.
- **Raid detection.** Notice when joins spike above a server's normal rate, group the suspicious accounts, and offer a temporary lockdown. Mass kicks only happen after a mod confirms.
- **Dashboard redesign.** Incident timeline, filters, reviewing and rolling back detections from the web, and everything else you can do in Discord.
- **Shared reputation.** Cross-server reports about users, weighted by how trustworthy each server's past reports have been, with a real appeal process. This one ships last and carefully.

## Ground rules

1. **A false alarm is worse than a miss.** New servers start in `alert_only`, where Equinox only posts alerts and doesn't act on its own.
2. **One pipeline.** Every detector produces a `Signal`, the verdict engine judges it, the action engine acts, and all of it lands in the audit log. Nothing takes a shortcut.
3. **Keep as little as possible.** We store IDs, hashes and normalized URLs. Message content is only kept as evidence for a confirmed detection, and even then it expires.
4. **Victims are victims.** Someone whose account was hijacked gets quarantined and helped, not banned.
5. **Everything can be undone.** Any automatic action can be reversed from Discord or the dashboard.
6. **Expect people to game it.** Rate limits, trust scores and review queues are there because attackers will probe the blocklist and try to poison reports.

## Modes

| Mode | What happens |
|---|---|
| `alert_only` | The default. Posts an alert with **Restore**, **Mark false positive** and **Confirm** buttons, and takes no action. |
| `protect` | Deletes confirmed threats and quarantines hijacked accounts automatically. |
| `strict` | Also acts on things that only look suspicious. |

The exact behavior lives in one place: the policy table in `packages/core/src/policy.ts`, which maps each combination of mode, signal type and verdict to a list of actions.

## Architecture

```
               Bot shards (apps/bot)
                      │  detectors emit Signals
                      ▼
        Verdict engine (packages/core)  ──►  Action engine ──► Discord
        blocklist · allowlist · heuristics       │
        cached intel · URLhaus feed              ▼
                      │                      Audit log (Postgres)
                      │ nothing known yet
                      ▼
        BullMQ: intel-lookup ──► Intel worker (apps/worker)
                                   redirect expansion (SSRF-safe)
                                   RDAP domain age · URLhaus feed
                                   VirusTotal (own queue, budgeted)
                                        │
        answer cached in Redis  ◄───────┘
        Redis Pub/Sub: equinox:intel:resolved ──► shards re-check waiting messages

        Browser ──► Dashboard (apps/dashboard) ──signed──► API (apps/api) ──► Postgres, Redis, bot
        The dashboard only reaches the API; see docs/architecture.md.

        Planned (M5): a scoring service promotes indicators seen across
        servers and pushes confirmed ones to every shard's cache.
```

Lookups try the cheap options first and stop as soon as they're confident: the local blocklist and allowlist, then local heuristics, then cached results from earlier lookups, then free threat feeds, and only then VirusTotal, which has a tight daily budget.

## Tech stack

TypeScript (strict mode) across the board, on Node 22 in production. CI also tests every change on Node 24, the next LTS. With:

- discord.js v14 for Discord
- PostgreSQL 16 with Drizzle ORM
- Redis 7 for the blocklist, the intel cache, queues (BullMQ) and fan-out (Pub/Sub)
- zod for validating config and input
- Vitest and Testcontainers for tests, so integration tests run against real Postgres and Redis
- pino for structured logs
- pnpm workspaces and Turborepo for the monorepo
- Fastify for the dashboard (plain server-rendered HTML for now) and for the API behind it
- Docker Compose for local development

Next.js for the dashboard redesign and Prometheus (metrics) come in with the milestones that need them.

## Repository layout

```
apps/
  bot/         The sensor: Discord shards, detectors, slash commands, alert buttons
  api/         The backend for the dashboard: login, sessions, access checks, all data access
  dashboard/   The web dashboard (frontend): pages only, talks to the API and nothing else
  worker/      The intel worker: redirect expansion, domain age, URLhaus, VirusTotal
packages/
  core/        Types, policy table, link detection (no Discord code)
  db/          Drizzle schema, migrations, tenant-scoped repositories
  config/      Config loading and validation
docs/          User guides (getting started, link protection, threat intel, dashboard) and the security controls mapping
```



## Getting started

You'll need Node 22 (or 24), pnpm 10 and Docker. On Windows, also Git Bash (it comes with [Git for Windows](https://git-scm.com/download/win)): the `openssl` commands below run there. PowerShell and Command Prompt don't have `openssl`.

1. Create an application in the [Discord developer portal](https://discord.com/developers/applications). On the **Bot** page, turn on the **Message Content** intent and copy the token.
2. Copy the example config:

   ```bash
   cp .env.example .env
   ```

   Fill in `DISCORD_TOKEN`, `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET` (for dashboard logins, from the **OAuth2** page), `DEV_GUILD_ID` (the ID of your test server) `API_SIGNING_KEY` and `INTERNAL_SIGNING_KEY` (two different values from `openssl rand -hex 32`: the first signs the dashboard's requests to the API, the second the API's requests to the bot). `VT_API_KEY` is optional: without it, threat intel runs on everything but VirusTotal. See [VirusTotal](#virustotal). Replace both passwords with long random hex strings, e.g. from `openssl rand -hex 32`. Hex matters here because the passwords end up inside connection URLs.

   Generate each secret in **Git Bash** (on Windows) or any terminal on macOS or Linux. Run the command once per secret, so each gets its own value:

   ```bash
   openssl rand -hex 32
   ```
3. Start everything in Docker:

   ```bash
   docker compose up --build
   ```

   Or run just the databases in Docker and the bot on your machine:

   ```bash
   docker compose up -d postgres redis
   pnpm install
   pnpm build
   pnpm dev:bot
   pnpm --filter @equinox/worker dev   # threat intel, in a second terminal
   ```

When the bot starts, it runs database migrations, loads the seed blocklist, and registers its slash commands (only in `DEV_GUILD_ID` during development). It then logs an invite link that asks for exactly the permissions it needs. Invite it, run `/equinox setup`, then `/equinox test` to push a harmless test signal all the way through.

| Variable | What it's for |
|---|---|
| `DISCORD_TOKEN`, `DISCORD_CLIENT_ID` | Your Discord application |
| `DEV_GUILD_ID` | Test server where commands register during development. Not allowed in production. |
| `DISCORD_CLIENT_SECRET` | API only: lets people log in to the dashboard with Discord. The bot and the dashboard never see it. |
| `API_SIGNING_KEY` | Dashboard and API, same value, required. Signs every request from the dashboard to the API. Must differ from `INTERNAL_SIGNING_KEY`. |
| `API_URL` | Dashboard only: where the API is. Docker Compose sets it to `http://api:4000`. |
| `API_HOST`, `API_PORT` | Where the API listens. Defaults to `127.0.0.1:4000`; never publish it outside your internal network. |
| `DASHBOARD_URL` | Public address of the dashboard. Defaults to `http://localhost:3000`; must be `https` in production. |
| `DASHBOARD_HOST`, `DASHBOARD_PORT` | Where the dashboard listens. Defaults to `127.0.0.1:3000`. |
| `INTERNAL_SIGNING_KEY` | Bot and API, same value. Signs the API's requests to the bot (review, setup, test alert). At least 64 hex characters. Without it those dashboard buttons are off. |
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | Database passwords for Docker Compose |
| `DATABASE_URL`, `REDIS_URL` | Connection strings when you run the bot outside Docker |
| `NODE_ENV`, `LOG_LEVEL` | Environment and how chatty the logs are |
| `VT_API_KEY` | Worker only, optional. Your VirusTotal API key. Without it, VirusTotal is skipped and the other sources still run. |
| `VT_TIER`, `VT_PER_MINUTE`, `VT_DAILY_BUDGET` | Worker only. `public` (the default) caps these at 4 a minute and 500 a day, VirusTotal's free-tier limits. |
| `URLHAUS_AUTH_KEY` | Worker only, optional. An abuse.ch Auth-Key, sent with the URLhaus feed download in case abuse.ch asks for one. |

The worker gets none of the Discord credentials. It's the part that visits links strangers post, so it gets as little as possible.

### Development

```bash
pnpm build        # compile everything
pnpm test         # unit and integration tests (integration tests need Docker)
pnpm lint
pnpm typecheck
pnpm audit:deps   # check dependencies for known vulnerabilities
pnpm coverage     # test coverage for every package
```

### Testing in a live server

**Don't post real scam links in Discord, not even lookalikes like the ones in the test suite.** Discord scans messages for phishing and can suspend the account that posted them, test or not.

Post this instead:

```
https://equinox-test.invalid/anything
```

It's on the seed blocklist, so Equinox treats it as malicious, but it isn't a real site. `.invalid` is a reserved domain that never resolves, so Discord's filters have no reason to flag it. It has to include `https://`, because bare domains only count if they end in a real public suffix. `/equinox check url:<link>` is also safe for trying out anything else, since the link is never posted in a channel.

To see threat intel at work without posting anything, use `/equinox check` on a link. The first time, it says the link hasn't been checked yet and queues a lookup; a minute later it shows what the intel sources said. `docker compose logs worker` shows the lookups as they happen.

A manual pass in a real server has covered setup, status, the test signal, links in `alert_only` and `protect` mode, disguised and edited links, `/equinox check`, the review buttons, and logging in to the dashboard and viewing a server there. The allowlist commands, permissions with a second account, and changing settings from the dashboard are covered by automated tests but still need a hands-on run.

### Commands

Discord hides all of these from members without **Manage Server** unless you change that in your server settings.

| Command | Who | What it does |
|---|---|---|
| `/equinox setup` | Admin | Pick the alert channel, mod role and quarantine role ([guide](docs/getting-started.md#setup)) |
| `/equinox mode` | Admin | Switch between `alert_only`, `protect` and `strict` |
| `/equinox status` | Mod | Show settings, open detections and any missing permissions |
| `/equinox test` | Mod | Send a harmless test signal through the pipeline |
| `/equinox check <url>` | Mod | Check a link without posting it, including what the threat-intel sources say. Mods only, so attackers can't use it to test the blocklist. |
| `/equinox allow add\|remove <domain>` | Admin | Manage your server's allowlist |
| `/equinox allow list` | Mod | Show the allowlist |
| `/equinox data` | Anyone | See what's stored about you and ask for it to be deleted (M9) |
| `/equinox report <user> <reason>` | Mod | Report a user to the network (M10) |

"Admin" means anyone with Manage Server. "Mod" means an admin or anyone with the mod role you picked in `/equinox setup`. Mods can use the alert buttons. Marking a link as a false positive also adds that exact host (not the whole domain) to your server's allowlist.

### Dashboard

The dashboard is each server's web tenant. It's deliberately plain for now: server-rendered pages, no JavaScript, and a redesign planned for M9.

To turn it on, open your application in the Discord developer portal, go to **OAuth2**, copy the client secret into `DISCORD_CLIENT_SECRET`, and add `http://localhost:3000/auth/callback` under **Redirects**. Click **Save Changes** afterwards, or Discord answers the login with "Invalid OAuth2 redirect_uri". `docker compose up --build` then serves it at <http://localhost:3000>. Use that address and not `127.0.0.1:3000`: login cookies belong to one host name, so a login started anywhere else is moved to `DASHBOARD_URL` first. To run it outside Docker, start the API and the dashboard: `pnpm --filter @equinox/api dev` and `pnpm --filter @equinox/dashboard dev` (with `API_URL=http://127.0.0.1:4000`).

- **Who can log in:** anyone with a Discord account, but you only see servers where you have Manage Server (or are the owner or an administrator) and where the bot is installed. That's the same "Admin" as in the commands table. People with only the mod role use the Discord alert buttons.
- **What you can do:** everything the slash commands and alert buttons do. Review detections (Restore, False positive, Confirm; the Discord alert is updated too), set the alert channel and roles, change the mode, send a test alert, see missing permissions, manage the allowlist, check links, see whether threat intel is working, and read the audit log. Changes land in the same audit log, marked `via: dashboard`.
- **How it's built:** the dashboard only renders pages. Everything else happens in the API, which it reaches through signed requests; the API reaches the bot the same way. The dashboard has no database, Redis or Discord credentials, and on Docker's network it can't reach anything but the API. See [docs/architecture.md](docs/architecture.md).
- **Sessions** last an hour and are kept by the API in Redis. Equinox asks Discord only for your identity and server list, and gives the access token back as soon as it has read them.

The full guide, including troubleshooting, is [docs/dashboard.md](docs/dashboard.md).

### Discord permissions

- **Intents:** `Guilds`, `GuildMessages` and `MessageContent` (privileged). `GuildMembers` (also privileged) comes with M7/M8.
- **Permissions:** View Channels, Send Messages, Embed Links, Manage Messages, Manage Roles and Moderate Members. Kick Members and Ban Members get added with raid handling in M8. The bot only asks for what its current features use.

## Roadmap

Each milestone has an exit check that has to pass before the next one starts.

| Phase | Milestone | Scope |
|---|---|---|
| A. Foundation | M0 ✅ | Monorepo, config, Docker Compose, CI |
| | M1 ✅ | Core pipeline, onboarding, alerts, audit log |
| B. Link protection | M2 ✅ | Link extraction, normalization, lookalike detection, blocklist |
| C. Web tenant | M3 ✅ | Dashboard, first version: Discord login, detections, audit log, settings, allowlist, and reviewing, setup and test alerts through the bot |
| D. Threat intel and network | M4 ✅ | Threat intel: redirect expansion, domain age (RDAP), feeds, VirusTotal |
| | M5 | Network propagation across servers |
| E. More detection | M6 | File scanning |
| | M7 | Hijacked account detection |
| | M8 | Raid detection |
| F. Visibility and hardening | M9 | Dashboard redesign with everything Discord can do; sharding at scale, load tests, metrics, privacy tooling |
| G. Shared reputation | M10 | Reports, trust scores, appeals |
| H. Platform depth | M11 | Per-server detection rules, written as data, versioned and testable against past detections (like Sublime's detection-as-code) |
| | M12 | Behavioral baselines: learn what's normal for each server and flag what isn't (like Abnormal) |
| | M13 | A "Report to Equinox" message action so members can send suspicious messages to their mods' triage queue |

Further out: a paid tier (which first needs a licensed intel source), a public threat-feed API, and NATS or Kafka if Redis Streams ever becomes the bottleneck.

## Privacy

- Short-lived behavior data like message fingerprints and join timing only lives in Redis. Fingerprints expire after 24 hours. A message waiting for a threat-intel answer is remembered by its IDs only, for at most an hour.
- Unconfirmed indicators expire after 30 days, and detection records after 90. A job deletes expired detections every hour.
- For the dashboard, the bot shares each server's channel and role names and its own permission gaps through Redis. Nothing about members or messages, and it expires after 15 minutes if the bot stops refreshing it.
- **We never upload anyone's files to a third party on our own.** VirusTotal is only used to look up hashes and URLs. Uploading files is a per-server opt-in, off by default.
- **What leaves Equinox for threat intel:** a link's domain goes to its registry's RDAP server (to learn its age), and a link goes to VirusTotal only if it already shows a sign of trouble or turns up in several servers. Nothing else from the message, and nothing about who posted it or where.
- **Which links the worker visits:** only shortened links and links that already look off, to see where they lead. Ordinary links people share are never visited, so one-time links like password resets aren't used up.
- Cached intel answers expire after 30 days if malicious and 24 hours otherwise, and a job deletes them every hour.
- Anyone will be able to see what's stored about them, and ask for it to be deleted, with `/equinox data`.

Every table, Redis key and outside service, with how long data is kept: [docs/privacy.md](docs/privacy.md).

## Threat intel

[docs/threat-intel.md](docs/threat-intel.md) is the full guide: what it's for, using it from Discord and the dashboard, how scores add up, setup and troubleshooting. In short:

For a link the sensor knows nothing about, the worker goes through its sources cheapest first and stops once it's confident:

1. **Redirects.** Shortened links (bit.ly and friends) and links that already look a little off are followed to where they really lead, and the destination gets the same checks as the link. This is done safely: no private or internal addresses, no cookies, at most 5 hops, 5 seconds and 1 MB. See [SECURITY.md](SECURITY.md).
2. **URLhaus.** abuse.ch's list of links serving malware, synced every 15 minutes. It's matched by exact URL, never by host, because it lists files on shared hosts like GitHub and Discord's own CDN.
3. **Domain age (RDAP).** A domain registered in the last week counts against a link, a little less so in the last month. Never enough on its own to raise an alert.
4. **VirusTotal**, last and only for links that still need it (see below).

Each server can trigger up to 30 lookups a minute, so one busy or hostile server can't crowd out the rest. Links past that are still judged on local information.

Every answer is cached. The sensor reads the cache in well under a millisecond, so the next time a link shows up, anywhere, it's judged on everything already known. If a source is down, lookups carry on without it and verdicts fall back to the local heuristics.

When an answer comes back after a message was already scanned, Equinox checks that message again through the normal pipeline. A clean link that turns out bad gets an alert (and in `protect`, gets deleted). A suspicious one that turns out malicious is escalated: a new alert shows the new verdict, and your mode's extra actions run. Detections your mods already handled are left alone.

## VirusTotal

Equinox is non-commercial for now, so it uses VirusTotal's free public API. That allows 4 requests a minute and 500 a day, for non-commercial use only. The worker stays within those limits in two ways: its queue is paced, and a shared budget in Redis refuses any call past 4 in a sliding minute or 500 in a day, however many workers are running. With `VT_TIER=public`, higher limits are refused at startup.

VirusTotal is only asked about links that show some sign of trouble or turn up in several servers, and links seen in several servers go first. Once the daily budget is gone, the worker falls back to the other sources and heuristics until the next day. It only ever looks up reports. It never submits a URL or a file, because anything submitted becomes visible to other VirusTotal users.

Equinox may go commercial later. VirusTotal sits behind the same `IntelProvider` interface as every other intel source, and `VT_TIER=public|premium` picks the tier. Before charging anyone, we switch to VirusTotal Premium or another licensed source.

## Security

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

We build against NIST SP 800-53, NIST SP 800-218 (SSDF), OWASP ASVS 5.0 and the OWASP Top 10. [docs/security-controls.md](docs/security-controls.md) lists each control, where it lives in the code, and whether it's done yet.

## Contributing

We build one milestone at a time, in roadmap order. Detection logic goes in `packages/core` and has to be testable without Discord. New detectors go through the same Signal → Verdict → Action → Audit pipeline as everything else, and every change comes with tests. [docs/development.md](docs/development.md) has the setup, the test commands, and the checklist a change must meet before it's done.
