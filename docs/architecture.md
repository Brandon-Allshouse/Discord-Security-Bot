# Architecture and trust boundaries

How Equinox's parts talk to each other, what each one is trusted with, and what it can't reach. The rule: **data flows database → backend → frontend, and the frontend never talks to a database.**

- [The flow](#the-flow)
- [Who holds what](#who-holds-what)
- [Who can reach what](#who-can-reach-what)
- [How the dashboard talks to the API](#how-the-dashboard-talks-to-the-api)
- [How the API talks to the bot](#how-the-api-talks-to-the-bot)
- [If one part is compromised](#if-one-part-is-compromised)

## The flow

```
  Browser
     │  HTTPS in production; forms + cookies, no JavaScript
     ▼
  Dashboard (apps/dashboard)          frontend network only
     │  signed HTTP requests (API_SIGNING_KEY, nonce, 60 s)
     ▼
  API (apps/api)                      frontend + backend networks, not published
     │                     │                        │
     ▼                     ▼                        ▼  signed requests (INTERNAL_SIGNING_KEY, 2 min)
  Postgres              Redis                    Bot (apps/bot) ──► Discord
  (row-level security)  (sessions, caches,          ▲
                         queues)                    │ Redis queues and pub/sub
                                                 Intel worker (apps/worker) ──► URLhaus, RDAP, VirusTotal
```

- The **browser** only ever talks to the dashboard.
- The **dashboard** (frontend) renders pages. It gets every piece of data from the API and changes nothing itself.
- The **API** (backend) is the only thing the dashboard talks to. It handles login, sessions, "does this user manage this server", CSRF checks, per-user rate limits, and every read and write of tenant data, always through the database's row-level security.
- The **bot** and the **intel worker** are backend services too. They never talk to the dashboard.

## Who holds what

| Secret | Dashboard | API | Bot | Worker |
|---|:-:|:-:|:-:|:-:|
| Database credentials (`DATABASE_URL`) | ❌ | ✅ | ✅ | ✅ |
| Redis credentials (`REDIS_URL`) | ❌ | ✅ | ✅ | ✅ |
| Discord bot token (`DISCORD_TOKEN`) | ❌ | ❌ | ✅ | ❌ |
| Discord OAuth secret (`DISCORD_CLIENT_SECRET`) | ❌ | ✅ | ❌ | ❌ |
| `API_SIGNING_KEY` (dashboard → API) | ✅ | ✅ | ❌ | ❌ |
| `INTERNAL_SIGNING_KEY` (API → bot) | ❌ | ✅ | ✅ | ❌ |
| Intel keys (`VT_API_KEY`, `URLHAUS_AUTH_KEY`) | ❌ | ❌ | ❌ | ✅ |

Each container gets only its own settings, listed one by one in `docker-compose.yml`, never the whole `.env`. Each config schema in `packages/config` only accepts the settings that service needs; anything else in the environment is ignored. The dashboard's Docker image doesn't even contain a database driver or a Redis client.

`API_SIGNING_KEY` and `INTERNAL_SIGNING_KEY` must be different (the API refuses to start otherwise), so the dashboard, which holds the first, can never sign a request to the bot.

## Who can reach what

Docker Compose puts the services on two networks:

| | `frontend` network | `backend` network | Published on your machine |
|---|:-:|:-:|---|
| Dashboard | ✅ | ❌ | `127.0.0.1:3000` |
| API | ✅ | ✅ | not published |
| Bot, worker | ❌ | ✅ | not published |
| Postgres, Redis | ❌ | ✅ | `127.0.0.1` only, for local development |

So the dashboard can reach the API and nothing else: it can't open a connection to Postgres, Redis or the bot even if it tried. The API isn't reachable from outside Docker at all.

## How the dashboard talks to the API

Every request is signed (`packages/core/src/api-contract.ts`):

```
HMAC-SHA256(API_SIGNING_KEY, timestamp \n nonce \n METHOD \n path \n session \n sha256(body))
```

The API refuses a request (answering `401 {"error":"signature"}`) when:

- it isn't signed, or is signed with another key;
- its timestamp is more than 60 seconds away from the API's clock;
- its nonce has been seen before (nonces are kept in Redis for 3 minutes), so a captured request can't be replayed;
- anything that was signed changed: the method, the path, the body, or the **session**, so a request can't be moved to another user's session.

On top of that, for each user request the API checks the session, that the user manages the server in the URL (another server answers `404`), the CSRF token on every change, and per-user rate limits.

The dashboard, in turn, validates every answer against the same contract with zod. An answer that doesn't match is treated as an outage and never rendered. Errors come back as fixed codes the dashboard maps to fixed messages, so nothing from the API is echoed into a page as-is. Unexpected API failures carry only a short reference to the API's log.

The session ID in the browser's cookie is issued by the API. The dashboard passes it along but can't read what's in it.

## How the API talks to the bot

Review, setup and test alerts need Discord permissions, which only the bot has. The API sends these as requests on a Redis queue for the shard serving that server, signed with `INTERNAL_SIGNING_KEY` and valid for 2 minutes (`packages/core/src/dashboard-contract.ts`). The bot checks the signature, re-validates everything as if the user had used the Discord command, carries it out, and records it in the audit log under the user's ID with `via: dashboard`. Details: [dashboard.md](dashboard.md#how-its-kept-safe).

## If one part is compromised

| Compromised | What the attacker gets | What they still can't do |
|---|---|---|
| Dashboard | The ability to send signed requests to the API, and the session IDs of people using it at the time | Read the database or Redis; act for users who aren't logged in; mint sessions (only the API does, after a real Discord login); sign requests to the bot; use the bot token |
| API | Tenant data, sessions, the OAuth secret, the ability to ask the bot for review/setup/test | Use the bot token directly; make the bot kick or ban (it never does automatically); upload files anywhere |
| Intel worker | The database and Redis, which in principle includes writing dashboard sessions | Anything on Discord: it has no Discord credentials at all; sign requests to the bot |
| Bot | Discord in every server, the database and Redis (so, in principle, dashboard sessions) | Get the OAuth secret or the intel keys |

The remaining gaps, both planned for M9 and listed in [security-controls.md](security-controls.md):

- The API, bot and worker connect to Postgres with the same database login (the one that owns the tables). Row-level security still applies to every tenant query, but each service should have its own restricted login.
- They also share one Redis password. Each should get its own Redis user (Redis ACLs), so for example only the API can touch sessions.
