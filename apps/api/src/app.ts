import { randomUUID, timingSafeEqual } from 'node:crypto';
import { fastify, LogController, type FastifyBaseLogger, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  API_HEADERS,
  checkLink,
  domainCandidates,
  GUILD_MODES,
  parseDomainInput,
  parseLinkInput,
  RateLimiter,
  REVIEW_DECISIONS,
  snowflakeSchema,
  verifyApiRequest,
  type ApiErrorCode,
  type BotOutcome,
  type DashboardAction,
  type GuildSettings,
} from '@equinox/core';
import type { AllowlistStore, AuditStore, DetectionStore, GuildStore } from '@equinox/db';
import type { BotLink } from './bot-link.js';
import type { DiscordOAuth } from './discord-oauth.js';
import type { DashboardIntel } from './intel.js';
import { newToken, type Session, type SessionStore } from './sessions.js';

/** The tenant-scoped stores the API uses. Everything goes through row-level security. */
export interface ApiStores {
  guilds: Pick<GuildStore, 'get' | 'setMode'>;
  detections: Pick<DetectionStore, 'recent' | 'countOpen'>;
  audit: Pick<AuditStore, 'write' | 'recent'>;
  allowlist: Pick<AllowlistStore, 'list' | 'add' | 'remove' | 'hasAny'>;
}

/** Remembers request nonces so a signed request can't be replayed. */
export interface NonceStore {
  /** True the first time a nonce is seen, false after that. */
  claim(nonce: string): Promise<boolean>;
}

export interface ApiDeps {
  stores: ApiStores;
  sessions: SessionStore;
  oauth: DiscordOAuth;
  intel: DashboardIntel;
  /** Requests to the bot for things that need Discord permissions (review, setup, test alert). */
  bot: BotLink;
  nonces: NonceStore;
  /** API_SIGNING_KEY: every request must be signed with it (see packages/core/src/api-contract.ts). */
  signingKey: string;
  logger?: FastifyBaseLogger;
  now?: () => number;
}

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const csrfField = z.string().max(100);

function sameToken(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function fail(reply: FastifyReply, status: number, error: ApiErrorCode): FastifyReply {
  return reply.code(status).send({ error });
}

/**
 * The backend for the dashboard. The only service the dashboard talks to, and the only one
 * that reads and writes tenant data for it. Every request must be signed by the dashboard;
 * login, sessions, which servers a user may manage, CSRF and per-user rate limits all live here.
 */
export async function buildApi(deps: ApiDeps) {
  const { stores, sessions, oauth, intel, bot, nonces } = deps;
  const now = deps.now ?? Date.now;
  const app = fastify({
    ...(deps.logger ? { loggerInstance: deps.logger } : { logger: false }),
    // Request URLs can carry IDs; the onResponse hook logs route patterns instead.
    logController: new LogController({ disableRequestLogging: true }),
    bodyLimit: 10_000,
  });

  // Keep the raw body: the signature covers the exact bytes that were sent.
  const rawBodies = new WeakMap<FastifyRequest, string>();
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (request, body, done) => {
    rawBodies.set(request, body as string);
    try {
      done(null, body === '' ? {} : (JSON.parse(body as string) as unknown));
    } catch {
      done(Object.assign(new Error('invalid JSON'), { statusCode: 400 }), undefined);
    }
  });

  const limits = {
    /** Per user. Each check of an unknown link can mean outside lookups by the intel worker. */
    checks: new RateLimiter(10, 60_000),
    /** Per user: review, setup and test requests to the bot. */
    actions: new RateLimiter(30, 60_000),
  };

  // Every request except the health check must carry a valid, fresh, never-seen signature.
  app.addHook('preHandler', async (request, reply) => {
    if (request.routeOptions.url === '/healthz') return;
    const check = verifyApiRequest(
      deps.signingKey,
      { method: request.method, path: request.url, body: rawBodies.get(request) ?? '' },
      request.headers,
      now(),
    );
    if (!check.ok) {
      request.log.warn({ problem: check.problem, route: request.routeOptions.url ?? 'unmatched' }, 'unsigned or invalid API request');
      return fail(reply, 401, 'signature');
    }
    if (!(await nonces.claim(check.nonce))) {
      request.log.warn({ route: request.routeOptions.url ?? 'unmatched' }, 'replayed API request');
      return fail(reply, 401, 'signature');
    }
  });

  app.addHook('onSend', async (_request, reply) => {
    reply.headers({ 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  });

  app.addHook('onResponse', async (request, reply) => {
    // The route pattern, not the URL, so IDs stay out of the logs.
    request.log.info(
      { method: request.method, route: request.routeOptions.url ?? 'unmatched', status: reply.statusCode, ms: Math.round(reply.elapsedTime) },
      'request',
    );
  });

  app.setNotFoundHandler((_request, reply) => fail(reply, 404, 'not_found'));

  app.setErrorHandler((error, request, reply) => {
    const status = (error as { statusCode?: number }).statusCode;
    if (status && status >= 400 && status < 500) return fail(reply, status, 'bad_request');
    // Full details go to the log; the dashboard only gets a reference to find them.
    const ref = randomUUID().slice(0, 8);
    request.log.error({ err: error, ref }, 'request failed');
    return reply.code(500).send({ error: 'unavailable', ref });
  });

  async function sessionOf(request: FastifyRequest): Promise<{ id: string; session: Session } | null> {
    const id = request.headers[API_HEADERS.session];
    if (typeof id !== 'string' || !TOKEN.test(id)) return null;
    const session = await sessions.get(id);
    return session ? { id, session } : null;
  }

  /** The logged-in user, or answers 401 itself. */
  async function requireSession(request: FastifyRequest, reply: FastifyReply) {
    const found = await sessionOf(request);
    if (!found) void fail(reply, 401, 'unauthenticated');
    return found;
  }

  /**
   * The server in the URL, for a user who manages it, or answers the request itself.
   * A server the user can't manage and one that doesn't exist look the same: 404.
   */
  async function tenantFor(request: FastifyRequest, reply: FastifyReply) {
    const found = await requireSession(request, reply);
    if (!found) return null;
    const guildId = (request.params as { guildId?: string }).guildId ?? '';
    const entry = snowflakeSchema.safeParse(guildId).success ? found.session.guilds.find((g) => g.id === guildId) : undefined;
    const guild = entry ? await stores.guilds.get(entry.id) : null;
    if (!entry || !guild) {
      if (!entry) request.log.warn({ userId: found.session.userId }, 'tenant access denied');
      void fail(reply, 404, 'not_found');
      return null;
    }
    return { ...found, guild, name: entry.name };
  }

  /** Parses the body with `schema` and checks its CSRF token against the session. */
  function formFor<T extends z.ZodRawShape>(
    request: FastifyRequest,
    reply: FastifyReply,
    session: Session,
    shape: T,
  ): z.infer<z.ZodObject<T>> | null {
    const csrf = z.object({ csrf: csrfField }).safeParse(request.body);
    const parsed = z.object(shape).safeParse(request.body);
    if (!csrf.success || !parsed.success) {
      void fail(reply, 400, 'bad_request');
      return null;
    }
    if (!sameToken(csrf.data.csrf, session.csrf)) {
      void fail(reply, 403, 'csrf');
      return null;
    }
    return parsed.data;
  }

  const viewer = (session: Session) => ({ username: session.username, csrf: session.csrf });

  app.get('/healthz', (_request, reply) => reply.send({ ok: true }));

  app.get('/v1/auth/authorize-url', async (request, reply) => {
    const state = (request.query as { state?: unknown }).state;
    if (typeof state !== 'string' || !TOKEN.test(state)) return fail(reply, 400, 'bad_request');
    return { url: oauth.authorizeUrl(state) };
  });

  /** Finishes a Discord login: exchanges the code, and starts a fresh session. */
  app.post('/v1/auth/session', async (request, reply) => {
    const parsed = z.object({ code: z.string().min(1).max(200), replaces: z.string().optional() }).safeParse(request.body);
    if (!parsed.success) return fail(reply, 400, 'bad_request');
    let login;
    try {
      login = await oauth.login(parsed.data.code);
    } catch (error) {
      request.log.warn({ err: { message: error instanceof Error ? error.message : 'unknown' } }, 'discord login failed');
      return fail(reply, 502, 'discord');
    }
    // Always a fresh session ID at login, and the old one stops working.
    if (parsed.data.replaces && TOKEN.test(parsed.data.replaces)) await sessions.destroy(parsed.data.replaces);
    const sessionId = await sessions.create({
      userId: login.user.id,
      username: login.user.username,
      csrf: newToken(),
      guilds: login.manageableGuilds,
    });
    request.log.info({ userId: login.user.id }, 'login');
    return reply.code(201).send({ sessionId });
  });

  app.post('/v1/auth/logout', async (request, reply) => {
    const found = await requireSession(request, reply);
    if (!found || !formFor(request, reply, found.session, {})) return reply;
    await sessions.destroy(found.id);
    return reply.code(204).send();
  });

  app.get('/v1/me', async (request, reply) => {
    const found = await requireSession(request, reply);
    if (!found) return reply;
    const { session } = found;
    // Only servers that are active tenants, i.e. the bot is installed.
    const active = await Promise.all(session.guilds.map(async (g) => ((await stores.guilds.get(g.id)) ? g : null)));
    return {
      user: { id: session.userId, username: session.username },
      csrf: session.csrf,
      guilds: active.filter((g) => g !== null),
    };
  });

  app.get('/v1/guilds/:guildId', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant) return reply;
    const { session, guild, name } = tenant;
    const [openCount, detections, allowlist, audit, intelStatus, snapshot] = await Promise.all([
      stores.detections.countOpen(guild.id),
      stores.detections.recent(guild.id, 50),
      stores.allowlist.list(guild.id),
      stores.audit.recent(guild.id, 50),
      // Intel and the bot's snapshot are extras: if Redis can't answer, the page still loads and says so.
      intel.status().catch(() => null),
      bot.snapshot(guild.id).catch(() => null),
    ]);
    return {
      viewer: viewer(session),
      name,
      guild: settingsView(guild),
      openCount,
      detections,
      allowlist: allowlist.map((a) => ({ value: a.value, addedBy: a.addedBy, createdAt: a.createdAt })),
      audit: audit.map((a) => ({ actor: a.actor, action: a.action, target: a.target, createdAt: a.createdAt })),
      intelStatus,
      snapshot,
      botEnabled: bot.enabled,
    };
  });

  app.post('/v1/guilds/:guildId/mode', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant) return reply;
    const body = formFor(request, reply, tenant.session, { mode: z.string().max(20) });
    if (!body) return reply;
    const mode = GUILD_MODES.find((m) => m === body.mode);
    if (!mode) return fail(reply, 400, 'mode');
    await stores.guilds.setMode(tenant.guild.id, mode);
    await stores.audit.write({
      guildId: tenant.guild.id,
      actor: tenant.session.userId,
      action: 'settings.mode',
      target: null,
      details: { from: tenant.guild.mode, to: mode, via: 'dashboard' },
    });
    return { ok: true };
  });

  app.post('/v1/guilds/:guildId/allowlist', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant) return reply;
    const body = formFor(request, reply, tenant.session, { domain: z.string().max(300) });
    if (!body) return reply;
    const domain = parseDomainInput(body.domain);
    if (!domain) return fail(reply, 400, 'domain');
    await stores.allowlist.add({ guildId: tenant.guild.id, type: 'domain', value: domain, addedBy: tenant.session.userId });
    await stores.audit.write({
      guildId: tenant.guild.id,
      actor: tenant.session.userId,
      action: 'allowlist.add',
      target: domain,
      details: { via: 'dashboard' },
    });
    return { ok: true };
  });

  app.post('/v1/guilds/:guildId/allowlist/remove', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant) return reply;
    const body = formFor(request, reply, tenant.session, { domain: z.string().max(300) });
    if (!body) return reply;
    const domain = parseDomainInput(body.domain);
    if (!domain || !(await stores.allowlist.remove(tenant.guild.id, 'domain', domain))) return fail(reply, 404, 'missing');
    await stores.audit.write({
      guildId: tenant.guild.id,
      actor: tenant.session.userId,
      action: 'allowlist.remove',
      target: domain,
      details: { via: 'dashboard' },
    });
    return { ok: true };
  });

  /**
   * "Check a link", like /equinox check in Discord: local heuristics, this server's allowlist,
   * the network blocklist and cached intel. Unknown links are queued for the intel worker.
   */
  app.post('/v1/guilds/:guildId/check', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant) return reply;
    const body = formFor(request, reply, tenant.session, { url: z.string().max(4096) });
    if (!body) return reply;
    if (!limits.checks.take(tenant.session.userId)) return fail(reply, 429, 'rate_limited');
    const finding = parseLinkInput(body.url);
    if (!finding) return fail(reply, 400, 'url');

    const candidates = domainCandidates(finding.normalized);
    const [allowlisted, blocklisted, cached] = await Promise.all([
      stores.allowlist.hasAny(tenant.guild.id, 'domain', candidates),
      intel.isBlocklisted(candidates).catch(() => false),
      intel.cached(finding.normalized.url).catch(() => null),
    ]);
    const result = checkLink(finding, { allowlisted, blocklisted, intel: cached });
    let queued = false;
    if (result.intelState === 'pending') {
      queued = await intel
        .requestLookup(result.url, finding.score)
        .then(() => true)
        .catch((err: unknown) => {
          request.log.warn({ err: { message: err instanceof Error ? err.message : 'unknown' } }, 'could not queue intel lookup');
          return false;
        });
    }
    return { viewer: viewer(tenant.session), name: tenant.name, result, queued };
  });

  /** Common checks for requests to the bot: logged in, manages this server, CSRF, rate limit. */
  async function actionTenant<T extends z.ZodRawShape>(request: FastifyRequest, reply: FastifyReply, shape: T) {
    const tenant = await tenantFor(request, reply);
    if (!tenant) return null;
    const body = formFor(request, reply, tenant.session, shape);
    if (!body) return null;
    if (!limits.actions.take(tenant.session.userId)) {
      void fail(reply, 429, 'rate_limited');
      return null;
    }
    return { ...tenant, body };
  }

  async function sendToBot(action: DashboardAction): Promise<{ outcome: BotOutcome }> {
    return { outcome: await bot.send(action).catch(() => 'bot_unavailable' as const) };
  }

  /** Restore, false positive or confirm, like the buttons on the alert in Discord. */
  app.post('/v1/guilds/:guildId/detections/:detectionId/review', async (request, reply) => {
    const tenant = await actionTenant(request, reply, { decision: z.string().max(30) });
    if (!tenant) return reply;
    const detectionId = z.uuid().safeParse((request.params as { detectionId?: string }).detectionId);
    const decision = REVIEW_DECISIONS.find((d) => d === tenant.body.decision);
    if (!detectionId.success || !decision) return { outcome: 'not_found' satisfies BotOutcome };
    return sendToBot({ type: 'review', guildId: tenant.guild.id, actorId: tenant.session.userId, detectionId: detectionId.data, decision });
  });

  /** Alert channel, mod role and quarantine role, like /equinox setup. The bot re-checks all of it. */
  app.post('/v1/guilds/:guildId/setup', async (request, reply) => {
    const id = z.string().max(30);
    const tenant = await actionTenant(request, reply, { alertChannelId: id, modRoleId: id.nullable(), quarantineRoleId: id.nullable() });
    if (!tenant) return reply;
    const { alertChannelId, modRoleId, quarantineRoleId } = tenant.body;
    const valid = (value: string | null) => value === null || snowflakeSchema.safeParse(value).success;
    if (!snowflakeSchema.safeParse(alertChannelId).success) return { outcome: 'setup_bad_channel' satisfies BotOutcome };
    if (!valid(modRoleId)) return { outcome: 'setup_bad_mod_role' satisfies BotOutcome };
    if (!valid(quarantineRoleId)) return { outcome: 'setup_bad_quarantine_role' satisfies BotOutcome };
    return sendToBot({ type: 'setup', guildId: tenant.guild.id, actorId: tenant.session.userId, alertChannelId, modRoleId, quarantineRoleId });
  });

  /** A harmless test alert, like /equinox test. */
  app.post('/v1/guilds/:guildId/test', async (request, reply) => {
    const tenant = await actionTenant(request, reply, {});
    if (!tenant) return reply;
    return sendToBot({ type: 'test', guildId: tenant.guild.id, actorId: tenant.session.userId });
  });

  return app;
}

/** Only the settings the dashboard shows, nothing else from the row. */
function settingsView(guild: GuildSettings) {
  return {
    id: guild.id,
    mode: guild.mode,
    alertChannelId: guild.alertChannelId,
    quarantineRoleId: guild.quarantineRoleId,
    modRoleIds: guild.modRoleIds,
  };
}
