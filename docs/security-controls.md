# Security controls

This is where we keep track of which security controls Equinox has, which standard each one comes from, and where to find it in the code. If a row says ✅, it's built and there's a test for it. 🟡 means partly done, and ⏳ means planned for the milestone listed.

The standards:

- **NIST SP 800-53 Rev. 5** for security and privacy controls (AC-3, AU-9 and so on)
- **NIST SP 800-218 (SSDF)** for how we build and ship software (PO, PS, PW, RV)
- **OWASP ASVS 5.0** for application security requirements (chapters V1–V17)
- **OWASP Top 10 (2025)**, cited by category name

If something marked ✅ turns out not to hold, that's a vulnerability. Please report it the way [SECURITY.md](../SECURITY.md) describes.

## Tenant isolation

Each Discord server is a tenant. One server's data should never show up in another's. The only thing shared across the network is indicators (bad domains, URLs, file hashes).

| Control | Standard | Where | Status |
|---|---|---|---|
| Row-level security on every tenant table (`guilds`, `detections`, `guild_allowlist`, `audit_log`) | 800-53 AC-4, SC-4 · ASVS V8 · Top 10: Broken Access Control | `packages/db/drizzle/0002_tenant_isolation.sql` | ✅ |
| Tenant queries run as the restricted `equinox_tenant` role (no BYPASSRLS), with the tenant ID set per transaction | 800-53 AC-6 | `asTenant()` in `packages/db/src/tenant.ts` | ✅ |
| If no tenant is set, queries return nothing | 800-53 AC-3 | RLS policy uses `current_setting(..., true)`; test `sees nothing when no tenant is set` | ✅ |
| A query with no tenant filter still only sees its own tenant; cross-tenant writes are rejected | 800-53 AC-4 | tests in `repositories.test.ts` → `tenant isolation` | ✅ |
| The tenant setting and role end with the transaction, so they can't carry over on a pooled connection | 800-53 SC-4 | `set_config(..., true)`, `SET LOCAL`; test `does not leak the tenant or role` | ✅ |
| Tenant IDs validated before use | ASVS V2 | `assertTenantId` | ✅ |
| The tenant role can't delete detections or change the audit log, on top of the trigger that also blocks it | 800-53 AU-9, AC-6 | grants in migration 0002 | ✅ |
| Jobs that span tenants live in one small class that never hands tenant data back | 800-53 AC-6 | `SystemStore` | ✅ |
| Each tenant has its own mode, roles and allowlist; a false-positive call only affects the server that made it | Keeps false alarms local | `guilds`, `guild_allowlist`, button handler | ✅ |
| Only indicators cross tenants, never content or server identities | 800-53 PT-2, AC-21 | Redis blocklist holds domains only; `provider_results` has no server column and no tenant grants | ✅ · ⏳ network scoring in M5 |
| The network-wide intel cache is out of reach of tenant queries | 800-53 AC-3, AC-6 | migration 0003 (no grants, RLS on), test `is invisible to tenants` | ✅ |
| Late intel results only act in the server that posted the link, through the normal pipeline | 800-53 AC-4 | `handleResolved`, `reevaluateSignal`, tests in `intel.test.ts` | ✅ |
| Escalations are audited (`detection.escalated`, with the old and new verdict) and announced in a clearly marked alert, never silently | 800-53 AU-2, AU-3 | `reevaluateSignal`, `buildAlertEmbed`, tests `escalates an open detection`, `marks an escalation clearly` | ✅ |
| Separate login role for the app, distinct from the migration owner | 800-53 AC-6 | — | ⏳ M9 |

## Access control

| Control | Standard | Where | Status |
|---|---|---|---|
| Every command and button is denied unless the user clearly qualifies | 800-53 AC-3 · ASVS V8 · Top 10: Broken Access Control | `packages/core/src/review.ts` (`canModerate`), `apps/bot/src/handlers/interactions.ts` | ✅ |
| Two levels: admins (Manage Server) change settings, mods act on alerts. Unknown commands need admin. | 800-53 AC-5, AC-6 | `apps/bot/src/authz.ts`, `authz.test.ts` | ✅ |
| Detections are always looked up by server and ID, so an ID from another server finds nothing (IDOR) | ASVS V8 · Top 10: Broken Access Control | `DetectionStore.get`, test `cannot reach a detection through another guild` | ✅ |
| Button IDs are parsed strictly and tampered ones are ignored | ASVS V2 | `parseReviewCustomId`, tests in `bot.test.ts` | ✅ |
| Denied attempts go in the audit log | 800-53 AC-7, AU-2 | `authz.denied` audit entries | ✅ |
| The bot asks Discord only for the intents and permissions it uses (never Administrator, Kick or Ban yet) | 800-53 AC-6 | `apps/bot/src/shard.ts`, `permissions.ts`, `permissions.test.ts` | ✅ |
| `/equinox setup` and the dashboard's setup refuse a quarantine role above the bot's own, and @everyone or bot-managed roles as the mod role (one shared rule) | 800-53 AC-6 | `setupProblem` in `moderation.ts`, tests in `setup-status.test.ts`, `moderation.test.ts` | ✅ |
| Slash commands are hidden from non-admins and don't work in DMs | 800-53 AC-6 | `commands.ts` | ✅ |
| `/equinox check` is mods-only so attackers can't use it to test the blocklist | 800-53 SI-4 | `interactions.ts` | ✅ |

## Dashboard

The web dashboard (`apps/dashboard`) is a separate process from the bot. It reads and writes tenant data through the same row-level-security stores.

| Control | Standard | Where | Status |
|---|---|---|---|
| Login is Discord OAuth2 (authorization code) with a random `state` bound to the browser by an HttpOnly cookie and compared in constant time | 800-53 IA-2, IA-8 · ASVS V10 | `app.ts` (`/auth/login`, `/auth/callback`), tests `rejects a callback with…` | ✅ |
| A login always starts on the public address (`DASHBOARD_URL`), so the state and session cookies belong to one host name | ASVS V3 | `/auth/login`, test `moves a login started under another host name…` | ✅ |
| Only `identify` and `guilds` are requested, and the access token is revoked right after login (even if the login fails) instead of being stored. The client secret only travels in POST bodies. | 800-53 AC-6, IA-5 · ASVS V14 | `DiscordOAuthClient.login`, tests in `auth.test.ts` | ✅ |
| A tenant page needs Manage Server (or owner/Administrator) in that server, checked on every request. Other tenants and unknown IDs both answer 404. | 800-53 AC-3 · ASVS V8 · Top 10: Broken Access Control | `tenantFor`, `canManage`, tests in `app.test.ts` → `tenant access` | ✅ |
| Sessions are random 256-bit IDs in Redis, stored under their SHA-256 hash, expire after an hour, and are replaced at every login | 800-53 SC-23, AC-12 · ASVS V7 | `sessions.ts`, tests in `auth.test.ts` | ✅ |
| Session and state cookies are HttpOnly and SameSite=Lax, and Secure whenever the dashboard is served over https; production refuses to start on plain http | ASVS V3 · 800-53 SC-8 | `cookieOptions`, `loadDashboardConfig` | ✅ |
| Over https, cookies use the `__Host-` prefix (Secure, whole site, this host only), so a subdomain or plain-http page can't plant or overwrite them | ASVS V3 | `cookieNames` in `app.ts`, test `served over https` | ✅ |
| The dashboard never holds the bot token. Review, setup and test alerts are sent to the bot as requests signed with HMAC-SHA256 over a shared key, refused if unsigned, tampered or more than 2 minutes old | 800-53 IA-9, SC-8, AC-6 · ASVS V13 (service authentication) | `signAction` / `verifyAction` in `packages/core/src/dashboard-contract.ts`, tests in `dashboard-contract.test.ts` | ✅ |
| Without a signing key, those dashboard buttons are off and the bot ignores requests, rather than falling back to unsigned requests | 800-53 AC-3 (fail closed) | `RedisBotLink.enabled`, `startDashboardWorker`, test `is off without a signing key` | ✅ |
| The bot re-validates every dashboard request as if it came from the Discord command (channel postable, roles usable, detection in that server) and audits it under the user's ID with `via: dashboard` | 800-53 AC-3, AU-2, AU-3 | `handleDashboardAction`, `setupProblem`, tests in `moderation.test.ts` → `handleDashboardAction` | ✅ |
| Requests to the bot are POSTs with the CSRF token, only for servers the user manages, limited to 30 a minute per user, with IDs and decisions validated before anything is sent | ASVS V3, V8, V2 · Top 10: Broken Access Control | `actionTenant` in `app.ts`, tests in `actions.test.ts` | ✅ |
| The bot's answers are fixed result codes mapped to fixed messages; nothing the bot or Discord returns is echoed into pages | ASVS V1 · Top 10: Injection | `OUTCOME_REDIRECT`, test `maps every bot answer to a fixed message` | ✅ |
| A request the bot didn't pick up in time is withdrawn, so it can't run after the user was told nothing changed | Top 10: Mishandling of Exceptional Conditions | `RedisBotLink.send`, test `times out when no bot picks the request up` | ✅ |
| The server snapshot the dashboard reads holds channel and role names and permission flags only, is size-capped, validated on read, and expires | 800-53 AC-21, SI-10 · ASVS V14 | `buildSnapshot`, `guildSnapshotSchema` | ✅ |
| Resolving a detection anywhere updates its alerts in Discord and removes their buttons, so nobody acts on a stale alert | 800-53 AU-2 | `resolveAlertMessages`, tests in `moderation.test.ts` | ✅ |
| Every form carries a per-session CSRF token, compared in constant time | ASVS V3 · 800-53 SC-23 | `csrfOk`, test `rejects forms without the CSRF token` | ✅ |
| All page output goes through an auto-escaping template | ASVS V1 (output encoding) · Top 10: Injection | `html.ts`, test `escapes names and subjects that contain markup` | ✅ |
| Strict Content-Security-Policy (no scripts at all), no framing, no sniffing, no referrer, no caching; HSTS over https | ASVS V3 · Top 10: Security Misconfiguration | `onSend` hook in `app.ts` | ✅ |
| Query strings are never echoed; page messages come from a fixed table | ASVS V1 | `NOTICES`, `ERRORS`, test `never reflects the query string` | ✅ |
| Requests are rate-limited per address (120 a minute, 10 a minute for login) | ASVS V2 (anti-automation) · 800-53 SC-5 | `limits` in `app.ts` | ✅ in memory · ⏳ shared limiter and proxy-aware addresses in M9 |
| Request logs record the route pattern, never the URL, so login codes and IDs stay out of the logs. A rejected login logs which check failed, never the values. | 800-53 AU-3 · ASVS V16 | `onResponse` hook, `/auth/callback` | ✅ |
| Settings and allowlist changes made on the web land in the tenant's audit log, marked `via: dashboard` | 800-53 AU-2, AU-12 | `app.ts`, tests in `settings changes` | ✅ |
| Permissions are re-checked against Discord during a session, not only at login | 800-53 AC-2 | — | 🟡 bounded by the one-hour session · ⏳ M9 |
| "Check a link" is a POST with the CSRF token, only for servers the user manages (others answer 404), and limited to 10 a minute per user, so another site can't make an admin's browser trigger lookups | ASVS V3, V8 · 800-53 AC-3, SC-5 · Top 10: Broken Access Control | `/servers/:guildId/check` in `app.ts`, tests in `intel.test.ts` → `check a link` | ✅ |
| What was typed into "Check a link" is normalized, length-capped and shown escaped and defanged | ASVS V1, V2 · Top 10: Injection | `parseLinkInput`, `checkResultPage`, test `escapes what was typed` | ✅ |
| The threat-intel status shown to tenants has no budget numbers, so nobody can tell when VirusTotal is used up | 800-53 SC-7, SI-4 | `intelStatusSchema` (no budget fields), test `shows which sources are working` (asserts no budget figures on the page) | ✅ |
| If Redis or the intel worker is down, pages still load and say so, instead of failing | Top 10: Mishandling of Exceptional Conditions | `intel.status().catch`, tests `still loads when Redis is down`, `still answers when intel is unavailable` | ✅ |

## Input validation and injection

| Control | Standard | Where | Status |
|---|---|---|---|
| Every signal is validated with zod before the pipeline does anything with it | 800-53 SI-10 · ASVS V2 · Top 10: Injection | `signalSchema` in `packages/core/src/types.ts` | ✅ |
| All SQL goes through Drizzle, so values are always parameterized | ASVS V1 · Top 10: Injection | `packages/db/src/repositories.ts` | ✅ |
| Only `http:` and `https:` links are processed; `javascript:`, `file:` and friends are dropped | ASVS V1 | `normalizeUrl` | ✅ |
| Text from users is markdown-escaped, has backticks neutralized and is length-capped in alerts | ASVS V1 (output encoding) | `apps/bot/src/alerts.ts` | ✅ |
| Nothing the bot posts can ping anyone (`allowedMentions: { parse: [] }` everywhere) | ASVS V1 | `shard.ts`, `alerts.ts` | ✅ |
| Bad links are defanged in alerts so nobody clicks them by accident | Alerts shouldn't spread the threat | `defang` in `display.ts` | ✅ |
| Work per message is capped (10 links, 8,000 characters) | 800-53 SC-5 | `extract.ts` | ✅ |
| Commands and buttons are rate-limited to 10 a minute per user | ASVS V2 (anti-automation) | `RateLimiter`, `context.ts` | ✅ |
| Threat-intel lookups are limited to 30 a minute per server, so one server can't flood the worker or the registries it asks | 800-53 SC-5 · ASVS V2 (anti-automation) | `IntelRequests` in `apps/bot/src/intel.ts`, test `per-server lookup limit` | ✅ |
| Domains typed into `/equinox allow` or the dashboard are validated first | ASVS V2 | `parseDomainInput` in `packages/core` | ✅ |
| Following redirects can't reach private, loopback, link-local, CGNAT, multicast or cloud-metadata addresses, including IPv4 wrapped in IPv6 | ASVS V1 · Top 10: Server-Side Request Forgery · 800-53 SC-7 | `apps/worker/src/net/address-policy.ts`, tests in `net.test.ts` | ✅ |
| Addresses are checked after DNS, at connect time, on every hop, and refused if any answer is private (no DNS-rebinding gap between check and connect) | Top 10: Server-Side Request Forgery | `guardedLookup` in `safe-fetch.ts`, test `refuses a host that resolves to any private address` | ✅ |
| Redirect following: http(s) on ports 80/443 only, at most 5 hops, 5 seconds, 1 MB; no cookies, no credentials, no connection reuse, nothing executed | Top 10: Server-Side Request Forgery · 800-53 SC-7 | `expandRedirects`, tests in `net.test.ts` | ✅ |
| Only shortener links and links that already look off are followed, so ordinary links (and one-time links like password resets) are never visited | 800-53 PT-2 | `shouldExpand` in `apps/worker/src/chain.ts` | ✅ |
| Messages between the bot and the intel worker are validated with zod on both ends | 800-53 SI-10 · ASVS V2 | `packages/core/src/intel/contract.ts` | ✅ |
| Requests to the intel APIs themselves (IANA, RDAP, URLhaus, VirusTotal) refuse redirects and have a timeout and a size cap | Top 10: Server-Side Request Forgery · 800-53 SC-5 | `apps/worker/src/net/http.ts`, `http.test.ts` | ✅ |
| Hosts that come from attacker links (like a redirect's destination) are defanged before they appear in alerts | ASVS V1 (output encoding) | `resolveUrl` in `chain.ts`, test `defanging the host` | ✅ |

## Audit and logging

| Control | Standard | Where | Status |
|---|---|---|---|
| Every detection, action, review, settings change and denial is logged with who did it and to whom | 800-53 AU-2, AU-3, AU-12 · ASVS V16 | pipeline, review, interactions | ✅ |
| The audit log is append-only; a trigger rejects UPDATE, DELETE and TRUNCATE | 800-53 AU-9 | `packages/db/drizzle/0001_audit_log_append_only.sql`, test `is append-only` | ✅ |
| Every Discord action includes a reason, so it also shows up in Discord's own audit log | 800-53 AU-3 | `executor.ts` | ✅ |
| Structured logs (pino), with secrets blanked out | 800-53 AU-9 · ASVS V16 | `logRedactPaths`, `logger.ts` | ✅ |
| Users get a short reference ID when something breaks, never a stack trace or error text | ASVS V16 · Top 10: Mishandling of Exceptional Conditions | `safeErrorMessage`, `handleInteraction`, test `gives the user a reference ID, never the error` | ✅ |
| If one action fails, the rest still run, and the alert always goes out | Top 10: Mishandling of Exceptional Conditions | `processSignal`, test `keeps going when an action fails` | ✅ |
| If an intel source (or the intel cache) is down, lookups carry on without it and verdicts fall back to local heuristics | Top 10: Mishandling of Exceptional Conditions · 800-53 SC-5 | `ask()` in `chain.ts`, `cachedIntel` in `pipeline.ts`; tests `a provider outage degrades gracefully` | ✅ |
| Metrics and alerting | 800-53 SI-4 · Top 10: Logging and Alerting Failures | — | ⏳ M9 |
| A separate database role that can't drop the audit trigger | 800-53 AU-9, AC-6 | — | ⏳ M9 |

## Configuration and secrets

| Control | Standard | Where | Status |
|---|---|---|---|
| Secrets only live in environment variables; `.env` is kept out of git and Docker builds | 800-53 IA-5 · ASVS V13 | `.gitignore`, `.dockerignore` | ✅ |
| Config is checked at startup; the bot won't start with bad config, and errors never print secret values | 800-53 CM-6 · ASVS V13 | `packages/config`, tests | ✅ |
| `DEV_GUILD_ID` isn't allowed in production | 800-53 CM-6 | `loadConfig` | ✅ |
| Postgres and Redis need passwords and only listen on 127.0.0.1 | 800-53 CM-7, SC-7 · Top 10: Security Misconfiguration | `docker-compose.yml` | ✅ |
| Containers run as a non-root user on a read-only filesystem, with all capabilities dropped and no privilege escalation | 800-53 CM-7, AC-6 | `apps/*/Dockerfile`, `docker-compose.yml` | ✅ |
| The dashboard container gets the OAuth client secret but never the bot token | 800-53 AC-6 | `dashboardConfigSchema`, `docker-compose.yml` | ✅ |
| The intel worker, which visits links strangers post, gets no Discord credentials at all | 800-53 AC-6, SC-7 | `workerConfigSchema`, `docker-compose.yml` | ✅ |
| Intel API keys are only sent as headers, never in URLs, and are blanked out of logs | 800-53 IA-5 · ASVS V13 | `virustotal.ts`, `logRedactPaths` | ✅ |
| TLS to Postgres/Redis in production (`sslmode`, `rediss://`) | 800-53 SC-8 · ASVS V12 | `rediss:` accepted by config | 🟡 supported, not required yet |

## Supply chain and how we build

| Control | Standard | Where | Status |
|---|---|---|---|
| The lockfile is committed and CI installs with `--frozen-lockfile` | SSDF PS.3 · Top 10: Software Supply Chain Failures | `ci.yml` | ✅ |
| Dependencies are saved at exact versions (`save-exact`) | SSDF PW.4 | `.npmrc` | ✅ |
| Install scripts are blocked unless a package is explicitly allowed | SSDF PW.4 · Top 10: Software Supply Chain Failures | `onlyBuiltDependencies` / `ignoredBuiltDependencies` in `pnpm-workspace.yaml` | ✅ |
| Package versions less than 3 days old aren't installed | SSDF PW.4 | `minimumReleaseAge` | ✅ |
| CI runs `pnpm audit` and fails on high or critical issues | SSDF RV.1 · 800-53 RA-5 | `ci.yml` | ✅ |
| Dependabot updates npm packages, Actions, the Docker base image and Compose images, waiting 3 days on new releases to match pnpm | SSDF RV.1 · 800-53 SI-2 | `.github/dependabot.yml` | ✅ |
| The CI token is read-only and checkout doesn't keep credentials around | SSDF PO.5 | `ci.yml` | ✅ |
| Strict TypeScript, type-aware linting, and no `eval` or anything like it | SSDF PW.5 | `tsconfig.base.json`, `eslint.config.js` | ✅ |
| Security behavior has tests, and they run in CI against real Postgres and Redis | SSDF PW.8 | Vitest + Testcontainers | ✅ |
| CodeQL (`security-extended` queries) scans every push and pull request, plus once a week | SSDF PW.7 · 800-53 SA-11, RA-5 · OWASP Top 10 | `.github/workflows/codeql.yml` | ✅ |
| A private way to report vulnerabilities | SSDF RV.1 | `SECURITY.md` | ✅ |
| GitHub Actions are pinned to commit SHAs | SSDF PS.2 | `ci.yml`, `codeql.yml` | ✅ |
| Docker base images pinned by digest | SSDF PS.2 | — | ⏳ before the first release |
| SBOM and signed images | SSDF PS.3 | — | ⏳ M9 |

## Privacy and keeping data to a minimum

| Control | Standard | Where | Status |
|---|---|---|---|
| We store IDs, normalized URLs and verdicts, not message content | 800-53 PT-2, SI-12 · ASVS V14 | `detections` schema | ✅ |
| discord.js doesn't cache messages | ASVS V14 | `makeCache` in `shard.ts` | ✅ |
| Detections expire after 90 days and an hourly job deletes them | 800-53 SI-12, AU-11 | `SystemStore.deleteExpiredDetections`, `startRetentionJob` | ✅ |
| User files are never uploaded anywhere automatically | ASVS V14 | No upload code exists | ✅ |
| VirusTotal is only asked about links (never sent files, never sent URLs to scan), only for links that already show a sign of trouble or turn up in several servers, and only within its free-tier limits | 800-53 PT-2, SA-9 | `processLookup` in `jobs.ts`, `VirusTotalProvider` | ✅ |
| VirusTotal's free-tier limits (4 a minute, 500 a day) can't be configured higher, and are enforced atomically across workers with a sliding window | 800-53 SA-9 | `loadWorkerConfig`, `ApiBudget`; load tests in `jobs.test.ts` | ✅ |
| Cached intel answers expire (malicious after 30 days, everything else after 24 hours) and an hourly job deletes them | 800-53 SI-12 | `cacheTtlSeconds`, `ProviderResultStore.deleteExpired` | ✅ |
| `/equinox data` so people can see and delete their data | 800-53 PT-5 | — | ⏳ M9 |

## Ground rules, and what enforces them

| Rule | Enforced by | Status |
|---|---|---|
| A false alarm is worse than a miss; new servers start in `alert_only` | The database default and `register()`; heuristics tuned so no single weak signal counts as suspicious; a 122-case test suite of real scams and real sites | ✅ |
| Kicks and bans are never automatic | Tests over every row of the policy table | ✅ |
| Everything can be undone | `reviewDetection` reverses quarantine, timeout and ban, from Discord or the dashboard; a false positive allowlists the exact host | ✅, except deleted messages, which Discord can't bring back |
| Victims are victims | Hijacked accounts get quarantined, not banned | ✅ policy · ⏳ detector in M7 |
