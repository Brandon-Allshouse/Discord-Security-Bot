# Development

How to work on Equinox: running the parts, testing, database changes, and what every change has to include before it's done.

- [Setup](#setup)
- [The parts](#the-parts)
- [Running locally](#running-locally)
- [Tests](#tests)
- [Database changes](#database-changes)
- [Adding a feature](#adding-a-feature)
- [Security checklist for every change](#security-checklist-for-every-change)

## Setup

You need Node 22, pnpm 10 and Docker. On Windows, also Git Bash (for `openssl` and the shell snippets in these docs); run `pnpm` from PowerShell or a terminal where Node is on the PATH.

```bash
cp .env.example .env      # then fill it in (see the README)
pnpm install
pnpm build
```

Generate each secret with `openssl rand -hex 32` in Git Bash, a different value for each.

## The parts

| Path | What it is | Talks to |
|---|---|---|
| `packages/core` | The detection engine: types, pipeline, verdicts, policy table, link detection, intel scoring, and the contracts between services (`intel/contract.ts`, `dashboard-contract.ts`, `api-contract.ts`). No Discord, no database. | nothing |
| `packages/db` | Drizzle schema, migrations, and tenant-scoped stores that run every query under row-level security | Postgres |
| `packages/config` | One zod schema per service; each accepts only the settings that service needs | nothing |
| `apps/bot` | The sensor: Discord shards, message scanning, slash commands, alert buttons, dashboard requests | Discord, Postgres, Redis |
| `apps/worker` | Threat intel: redirects, RDAP, URLhaus, VirusTotal | the internet, Postgres, Redis |
| `apps/api` | The dashboard's backend: login, sessions, access checks, all data access | Postgres, Redis, Discord OAuth |
| `apps/dashboard` | The frontend: renders pages, talks only to the API | the API |

How they connect and what each is trusted with: [architecture.md](architecture.md).

## Running locally

Everything in Docker:

```bash
docker compose up --build
```

Or the databases in Docker and the services on your machine, each in its own terminal:

```bash
docker compose up -d postgres redis
pnpm dev:bot                                  # runs migrations on start
pnpm --filter @equinox/worker dev
pnpm --filter @equinox/api dev
pnpm --filter @equinox/dashboard dev          # set API_URL=http://127.0.0.1:4000
```

Outside Docker, `DATABASE_URL` and `REDIS_URL` point at `localhost` (see `.env.example`).

## Tests

```bash
pnpm test          # every package; integration tests start Postgres and Redis with Testcontainers, so Docker must be running
pnpm lint          # type-aware ESLint
pnpm typecheck
pnpm coverage      # coverage for every package
pnpm audit:deps    # production dependencies, fails on high or critical
pnpm audit         # everything, dev tools included
```

One package: `pnpm --filter @equinox/api test`. One file: `pnpm --filter @equinox/api exec vitest run src/app.test.ts`.

How the tests are organised:

- **Unit tests** sit next to the code (`foo.ts` → `foo.test.ts`).
- **Fakes** for the pipeline are in `@equinox/core/testing`, for the API in `@equinox/api/testing`, and per app in `test-helpers.ts`.
- **Integration tests** use real Postgres and Redis through Testcontainers: tenant isolation, the audit trigger, intel queues, VirusTotal budgets, the dashboard → bot request path.
- **End-to-end web tests**: the dashboard's tests run the real API in the same process, so each request goes browser → dashboard → signed request → API, exactly as in production.
- **Security properties have their own tests**: tenant isolation, forged or replayed requests, CSRF, SSRF, rate limits, escaping, secrets never in errors or logs. [security-controls.md](security-controls.md) names the test behind each control.

The only files without unit tests are the startup files (`index.ts`, `shard.ts`) and the migration command, which only wire the tested parts together. Running the stack in Docker exercises them.

## Database changes

1. Change `packages/db/src/schema.ts`.
2. `pnpm --filter @equinox/db exec drizzle-kit generate --name <what_changed>` writes a migration in `packages/db/drizzle/`.
3. Add anything Drizzle doesn't generate by hand in the same file: row-level security policies, grants for the `equinox_tenant` role, triggers. Every table with tenant data needs RLS and a policy; tables without it (like `provider_results`) get RLS enabled and no grants.
4. Add tests to `packages/db/src/repositories.test.ts`, including that another tenant can't see or change the rows.

The bot applies migrations when it starts.

## Adding a feature

A feature is done only when all of this is true:

1. **Complete**: everything the milestone promises, working in Docker.
2. **In the dashboard**: usable from the web as well as Discord. Dashboard features go through the API: add the route in `apps/api`, the response schema in `packages/core/src/api-contract.ts`, and the page in `apps/dashboard`. The dashboard never gets data access of its own.
3. **Tested**: unit tests for every new module (check with `pnpm coverage`), plus the milestone's exit checks.
4. **Documented**: a guide in `docs/` for users and operators (what it's for, how to use it, settings, troubleshooting), plus README, [privacy.md](privacy.md) if it stores or sends anything new, and [architecture.md](architecture.md) if it changes how the parts talk.
5. **Secure**: reviewed against NIST SP 800-53 / SSDF and OWASP ASVS / Top 10, with a row per control in [security-controls.md](security-controls.md).

Detection code goes in `packages/core` and must be testable without Discord. Every detector produces a `Signal` and goes through `processSignal`, which is the one pipeline (verdict → actions → audit log). User-facing names come from `BRAND` in `packages/core/src/brand.ts`.

## Security checklist for every change

- **Input:** validated with zod (or a strict parser) at every boundary: Discord, forms, the API, Redis, outside APIs.
- **Tenant data:** only through the stores in `packages/db`, which run under row-level security. Never query tenant tables outside `asTenant`.
- **Output:** pages through the `html` template, Discord text through the alert helpers (escaped, defanged, no pings), errors as fixed messages or codes.
- **Secrets:** only in environment variables, only in the services that need them (named one by one in `docker-compose.yml`), added to `logRedactPaths`, never in URLs, errors or logs.
- **Service-to-service:** signed (see the two contracts), validated on both ends, short-lived.
- **Outside requests:** through the SSRF-safe fetcher for anything from users, with timeouts and size caps for everything else.
- **Limits:** anything that costs money, outside requests or Discord API calls has a rate limit.
- **Audit:** anything a person changes, and anything the bot does, goes in the audit log.
- **Dependencies:** exact versions, and `pnpm audit` stays clean.
