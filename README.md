# Equinox

A security sensor for Discord servers, backed by a shared threat-intelligence network.

> **Status:** early prototype. Milestones M0–M2 are done: the core pipeline, tenant isolation, onboarding, alerts with review buttons, and link protection. Everything from M3 onward is still planned. "Equinox" is a working name; to rebrand, change `BRAND` in `packages/core/src/brand.ts`.

Think of it as [Sublime Security](https://sublime.security) or [Abnormal Security](https://abnormalsecurity.com), but for Discord instead of email. You add the Equinox bot to your server and it acts as a sensor: it watches for phishing links, and later malicious files, hijacked accounts and raids. What it sees goes through a detection engine that scores it, acts on it according to your server's settings, and gives your mods an alert they can triage with one click.

Each server is its own tenant. Your detections, settings, allowlist and audit log belong to your server alone, and the database enforces that. The one thing servers share is indicators. When a scam domain gets confirmed in one server, every other server is protected from it within seconds.

## How it fits together

- **The sensor** (`apps/bot`) is the Discord bot. It reads messages as they arrive, turns anything interesting into a `Signal`, carries out whatever actions the policy calls for, and posts alerts with triage buttons.
- **The detection engine** (`packages/core`) is plain TypeScript with no Discord in it, so it's easy to test. It holds the detectors, the verdict logic, and the policy table that decides what to do in each mode.
- **Tenant data** (`packages/db`) lives in Postgres. Each server's settings, detections, allowlist and audit log are walled off with row-level security.
- **The threat network** is the shared list of bad domains, URLs and file hashes. Today that's a Redis blocklist; M4 adds the scoring service that promotes indicators across servers. It never carries message content, and never says which server saw what.

### Tenants

One Discord server is one tenant, and the tenant ID is just the server ID. A tenant is created when Equinox joins a server. When it leaves, the tenant is deactivated, not deleted, so settings come back if it rejoins.

Isolation doesn't depend on every query remembering a `WHERE guild_id = …`. Tenant queries run as a restricted Postgres role (`equinox_tenant`) under row-level security, so a query that forgets its filter still only sees its own server. Writes into another server's data are rejected outright. The only code that runs outside that boundary is a small set of system jobs, like deleting expired data.

Every server sets its own mode, alert channel, mod role, quarantine role and allowlist. If your mods mark something as a false positive, that only affects your server.

## What it does

Done:

- **Tenant isolation.** Covered above.
- **Link protection.** Pulls links out of messages, including disguised ones (`hxxp`, `[.]`, zero-width characters, markdown links, bare domains). It normalizes them and checks them against the blocklist and a lookalike detector for Discord, Steam, Epic, Roblox and the big crypto wallets. External threat-intel lookups come with M3.

Planned:

- **Network propagation.** A link confirmed malicious in one server gets blocked in all of them within 10 seconds. A false-positive call un-blocks it just as fast.
- **File scanning.** Hash attachments as they stream in (nothing is written to disk), flag risky and disguised file types, and look up known-bad hashes.
- **Hijacked account detection.** Catch an account posting the same scam across channels or servers. Quarantine it, clean up the spam, and DM the owner how to get their account back.
- **Raid detection.** Notice when joins spike above a server's normal rate, group the suspicious accounts, and offer a temporary lockdown. Mass kicks only happen after a mod confirms.
- **Dashboard.** Log in with Discord, see incidents and detections, roll things back, and manage settings.
- **Shared reputation.** Cross-server reports about users, weighted by how trustworthy each server's past reports have been, with a real appeal process. This one ships last and carefully.

## Ground rules

1. **A false alarm is worse than a miss.** New servers start in `alert_only`, where Equinox only posts alerts and doesn't act on its own.
2. **One pipeline.** Every detector produces a `Signal`, the verdict engine judges it, the action engine acts, and all of it lands in the audit log. Nothing takes a shortcut.
3. **Keep as little as possible.** We store IDs, hashes and normalized URLs. Message content is only kept as evidence for a confirmed detection, and even then it expires.
4. **Victims are victims.** Someone whose account was hijacked gets quarantined and helped, not banned.
5. **Everything can be undone.** Any automatic action can be reversed from Discord (and later the dashboard).
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
        blocklist · allowlist · rules            │
                      │ unknown / suspicious     ▼
                      ▼                      Audit log (Postgres)
        Redis Stream: equinox:signals
                      │
                      ▼
        Scoring service (apps/api) ◄── Intel workers (apps/worker)
                      │                  redirect expansion · RDAP domain age
                      │                  free feeds (URLhaus) · VirusTotal
                      ▼
        Confirmed indicator ──► Redis Pub/Sub ──► every shard's local cache
```

Lookups try the cheap options first and stop as soon as they're confident: the local blocklist and allowlist, then local heuristics, then cached results from earlier lookups, then free threat feeds, and only then VirusTotal, which has a tight daily budget.

## Tech stack

TypeScript on Node 22 (strict mode) across the board, with:

- discord.js v14 for Discord
- PostgreSQL 16 with Drizzle ORM
- Redis 7 for the blocklist, and later queues and fan-out (BullMQ, Streams, Pub/Sub)
- zod for validating config and input
- Vitest and Testcontainers for tests, so integration tests run against real Postgres and Redis
- pino for structured logs
- pnpm workspaces and Turborepo for the monorepo
- Docker Compose for local development

Fastify (API), Next.js (dashboard) and Prometheus (metrics) come in with the milestones that need them.

## Repository layout

```
apps/
  bot/         The sensor: Discord shards, detectors, slash commands, alert buttons
packages/
  core/        Types, policy table, link detection (no Discord code)
  db/          Drizzle schema, migrations, tenant-scoped repositories
  config/      Config loading and validation
docs/          Security controls mapping
```

`api/`, `worker/` and `dashboard/` will show up when their milestones do (M3, M4 and M8).

## Getting started

You'll need Node 22, pnpm 10 and Docker.

1. Create an application in the [Discord developer portal](https://discord.com/developers/applications). On the **Bot** page, turn on the **Message Content** intent and copy the token.
2. Copy the example config:

   ```bash
   cp .env.example .env
   ```

   Fill in `DISCORD_TOKEN`, `DISCORD_CLIENT_ID` and `DEV_GUILD_ID` (the ID of your test server). Replace both passwords with long random hex strings, e.g. from `openssl rand -hex 32`. Hex matters here because the passwords end up inside connection URLs.
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
   ```

When the bot starts, it runs database migrations, loads the seed blocklist, and registers its slash commands (only in `DEV_GUILD_ID` during development). It then logs an invite link that asks for exactly the permissions it needs. Invite it, run `/equinox setup`, then `/equinox test` to push a harmless test signal all the way through.

| Variable | What it's for |
|---|---|
| `DISCORD_TOKEN`, `DISCORD_CLIENT_ID` | Your Discord application |
| `DEV_GUILD_ID` | Test server where commands register during development. Not allowed in production. |
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | Database passwords for Docker Compose |
| `DATABASE_URL`, `REDIS_URL` | Connection strings when you run the bot outside Docker |
| `NODE_ENV`, `LOG_LEVEL` | Environment and how chatty the logs are |

VirusTotal and dashboard settings will be added with M3 and M8.

### Development

```bash
pnpm build        # compile everything
pnpm test         # unit and integration tests (integration tests need Docker)
pnpm lint
pnpm typecheck
pnpm audit:deps   # check dependencies for known vulnerabilities
```

### Testing in a live server

**Don't post real scam links in Discord, not even lookalikes like the ones in the test suite.** Discord scans messages for phishing and can suspend the account that posted them, test or not.

Post this instead:

```
https://equinox-test.invalid/anything
```

It's on the seed blocklist, so Equinox treats it as malicious, but it isn't a real site. `.invalid` is a reserved domain that never resolves, so Discord's filters have no reason to flag it. It has to include `https://`, because bare domains only count if they end in a real public suffix. `/equinox check url:<link>` is also safe for trying out anything else, since the link is never posted in a channel.

A full manual pass in a real server hasn't been done yet. So far it's been checked up to posting a link in `alert_only` mode (setup, status, the test signal and the Confirm button all worked). Everything after that is covered by automated tests, but still needs a hands-on run.

### Commands

Discord hides all of these from members without **Manage Server** unless you change that in your server settings.

| Command | Who | What it does |
|---|---|---|
| `/equinox setup` | Admin | Pick the alert channel, mod role and quarantine role |
| `/equinox mode` | Admin | Switch between `alert_only`, `protect` and `strict` |
| `/equinox status` | Mod | Show settings, open detections and any missing permissions |
| `/equinox test` | Mod | Send a harmless test signal through the pipeline |
| `/equinox check <url>` | Mod | Check a link without posting it. Mods only, so attackers can't use it to test the blocklist. |
| `/equinox allow add\|remove <domain>` | Admin | Manage your server's allowlist |
| `/equinox allow list` | Mod | Show the allowlist |
| `/equinox data` | Anyone | See what's stored about you and ask for it to be deleted (M9) |
| `/equinox report <user> <reason>` | Mod | Report a user to the network (M10) |

"Admin" means anyone with Manage Server. "Mod" means an admin or anyone with the mod role you picked in `/equinox setup`. Mods can use the alert buttons. Marking a link as a false positive also adds that exact host (not the whole domain) to your server's allowlist.

### Discord permissions

- **Intents:** `Guilds`, `GuildMessages` and `MessageContent` (privileged). `GuildMembers` (also privileged) comes with M6/M7.
- **Permissions:** View Channels, Send Messages, Embed Links, Manage Messages, Manage Roles and Moderate Members. Kick Members and Ban Members get added with raid handling in M7. The bot only asks for what its current features use.

## Roadmap

Each milestone has an exit check that has to pass before the next one starts.

| Phase | Milestone | Scope |
|---|---|---|
| A. Foundation | M0 ✅ | Monorepo, config, Docker Compose, CI |
| | M1 ✅ | Core pipeline, onboarding, alerts, audit log |
| B. Link protection | M2 ✅ | Link extraction, normalization, lookalike detection, blocklist |
| | M3 | Threat intel: redirect expansion, domain age (RDAP), feeds, VirusTotal |
| | M4 | Network propagation across servers |
| C. More detection | M5 | File scanning |
| | M6 | Hijacked account detection |
| | M7 | Raid detection |
| D. Visibility and hardening | M8 | Dashboard |
| | M9 | Sharding at scale, load tests, metrics, privacy tooling |
| E. Shared reputation | M10 | Reports, trust scores, appeals |
| F. Platform depth *(proposed)* | M11 | Per-server detection rules, written as data, versioned and testable against past detections (like Sublime's detection-as-code) |
| | M12 | Behavioral baselines: learn what's normal for each server and flag what isn't (like Abnormal) |
| | M13 | A "Report to Equinox" message action so members can send suspicious messages to their mods' triage queue |

Further out: a paid tier (which first needs a licensed intel source), a public threat-feed API, and NATS or Kafka if Redis Streams ever becomes the bottleneck.

## Privacy

- Short-lived behavior data like message fingerprints and join timing only lives in Redis. Fingerprints expire after 24 hours.
- Unconfirmed indicators expire after 30 days, and detection records after 90. A job deletes expired detections every hour.
- **We never upload anyone's files to a third party on our own.** VirusTotal is only used to look up hashes and URLs. Uploading files is a per-server opt-in, off by default.
- Anyone will be able to see what's stored about them, and ask for it to be deleted, with `/equinox data`.

The full privacy policy will go in `docs/privacy.md`.

## VirusTotal

Equinox is non-commercial for now, so it uses VirusTotal's free public API. That allows 4 requests a minute and 500 a day, for non-commercial use only. The worker (M3) will stay within those limits and fall back to heuristics and network scores once the daily budget is gone.

Equinox may go commercial later. VirusTotal sits behind the same `IntelProvider` interface as every other intel source, and `VT_TIER=public|premium` picks the tier. Before charging anyone, we switch to VirusTotal Premium or another licensed source.

## Security

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

We build against NIST SP 800-53, NIST SP 800-218 (SSDF), OWASP ASVS 5.0 and the OWASP Top 10. [docs/security-controls.md](docs/security-controls.md) lists each control, where it lives in the code, and whether it's done yet.

## Contributing

We build one milestone at a time, in roadmap order. Detection logic goes in `packages/core` and has to be testable without Discord. New detectors go through the same Signal → Verdict → Action → Audit pipeline as everything else, and every change comes with tests.
