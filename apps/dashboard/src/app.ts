import { randomUUID, timingSafeEqual } from 'node:crypto';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { fastify, LogController, type FastifyBaseLogger, type FastifyReply, type FastifyRequest } from 'fastify';
import {
  checkLink,
  domainCandidates,
  GUILD_MODES,
  parseDomainInput,
  parseLinkInput,
  RateLimiter,
  REVIEW_DECISIONS,
  type DashboardAction,
  type GuildMode,
  type GuildSettings,
} from '@equinox/core';
import type { AllowlistStore, AuditStore, DetectionStore, GuildStore } from '@equinox/db';
import type { BotLink, SendOutcome } from './bot-link.js';
import type { DiscordOAuth } from './discord-oauth.js';
import type { Html } from './html.js';
import type { DashboardIntel } from './intel.js';
import { newToken, SESSION_TTL_SECONDS, type Session, type SessionStore } from './sessions.js';
import { checkResultPage, ERRORS, landingPage, messagePage, NOTICES, serversPage, STYLESHEET, tenantPage } from './views.js';

/** The tenant-scoped stores the dashboard uses. Everything goes through row-level security. */
export interface DashboardStores {
  guilds: Pick<GuildStore, 'get' | 'setMode'>;
  detections: Pick<DetectionStore, 'recent' | 'countOpen'>;
  audit: Pick<AuditStore, 'write' | 'recent'>;
  allowlist: Pick<AllowlistStore, 'list' | 'add' | 'remove' | 'hasAny'>;
}

export interface DashboardDeps {
  stores: DashboardStores;
  sessions: SessionStore;
  oauth: DiscordOAuth;
  intel: DashboardIntel;
  /** Requests to the bot for things that need Discord permissions (review, setup, test alert). */
  bot: BotLink;
  /** Public address of the dashboard. Over https, cookies are marked Secure and HSTS is sent. */
  publicUrl: string;
  logger?: FastifyBaseLogger;
}

/**
 * Over https the cookies get the __Host- prefix: the browser then only accepts them if they're
 * Secure, for the whole site and set by this exact host, so a subdomain or a plain-http page
 * can't plant or overwrite them (ASVS V3). Browsers refuse the prefix over plain http.
 */
export function cookieNames(secure: boolean) {
  const prefix = secure ? '__Host-' : '';
  return { session: `${prefix}eq_session`, state: `${prefix}eq_oauth_state` };
}
const STATE_TTL_SECONDS = 10 * 60;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const SNOWFLAKE = /^\d{17,20}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Where to send the user after a request to the bot: a fixed notice or error key, never the bot's text. */
const OUTCOME_REDIRECT: Record<SendOutcome, { notice: keyof typeof NOTICES } | { error: keyof typeof ERRORS }> = {
  reviewed: { notice: 'reviewed' },
  setup_saved: { notice: 'setup' },
  test_sent: { notice: 'test' },
  already_resolved: { error: 'already_resolved' },
  not_found: { error: 'detection_missing' },
  setup_bad_channel: { error: 'setup_channel' },
  setup_bad_mod_role: { error: 'setup_mod_role' },
  setup_bad_quarantine_role: { error: 'setup_quarantine_role' },
  test_not_detected: { error: 'test_failed' },
  guild_unavailable: { error: 'bot_unavailable' },
  bot_unavailable: { error: 'bot_unavailable' },
  timeout: { error: 'bot_timeout' },
  rejected: { error: 'bot_rejected' },
  off: { error: 'bot_off' },
};

// No scripts at all, styles and forms only from this site, and no framing.
const CSP = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

function sameToken(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** A single string field from a form or query string, or '' for anything else. */
function field(source: unknown, name: string): string {
  if (typeof source !== 'object' || source === null) return '';
  const value = (source as Record<string, unknown>)[name];
  return typeof value === 'string' ? value : '';
}

function send(reply: FastifyReply, page: Html, status = 200): FastifyReply {
  return reply.code(status).type('text/html; charset=utf-8').send(page.value);
}

export async function buildApp(deps: DashboardDeps) {
  const { stores, sessions, oauth, intel, bot } = deps;
  const publicUrl = new URL(deps.publicUrl);
  const secure = publicUrl.protocol === 'https:';
  const app = fastify({
    ...(deps.logger ? { loggerInstance: deps.logger } : { logger: false }),
    // The default request log prints full URLs, and the OAuth callback URL carries the login code.
    logController: new LogController({ disableRequestLogging: true }),
    bodyLimit: 10_000,
  });
  await app.register(cookie);
  await app.register(formbody);

  const cookieOptions = { path: '/', httpOnly: true, sameSite: 'lax', secure } as const;
  const { session: SESSION_COOKIE, state: STATE_COOKIE } = cookieNames(secure);
  const limits = {
    requests: new RateLimiter(120, 60_000),
    logins: new RateLimiter(10, 60_000),
    /** Per user. Each check of an unknown link can mean outside lookups by the intel worker. */
    checks: new RateLimiter(10, 60_000),
    /** Per user: review, setup and test requests to the bot. */
    actions: new RateLimiter(30, 60_000),
  };

  app.addHook('onRequest', async (request, reply) => {
    if (!limits.requests.take(request.ip)) {
      return send(reply, messagePage('Slow down', 'Too many requests. Try again in a minute.'), 429);
    }
  });

  app.addHook('onSend', async (_request, reply) => {
    reply.headers({
      'content-security-policy': CSP,
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store',
      ...(secure ? { 'strict-transport-security': 'max-age=31536000; includeSubDomains' } : {}),
    });
  });

  app.addHook('onResponse', async (request, reply) => {
    // The route pattern, not the URL, so IDs and query strings stay out of the logs.
    request.log.info(
      { method: request.method, route: request.routeOptions.url ?? 'unmatched', status: reply.statusCode, ms: Math.round(reply.elapsedTime) },
      'request',
    );
  });

  app.setNotFoundHandler((_request, reply) => send(reply, messagePage('Not found', 'There’s nothing here.'), 404));

  app.setErrorHandler((error, request, reply) => {
    // Full details go to the log. The user just gets a short ref they can pass to us.
    const ref = randomUUID().slice(0, 8);
    request.log.error({ err: error, ref }, 'request failed');
    return send(reply, messagePage('Something went wrong', `Reference: ${ref}`), 500);
  });

  async function currentSession(request: FastifyRequest): Promise<Session | null> {
    const id = request.cookies[SESSION_COOKIE];
    return id ? sessions.get(id) : null;
  }

  /**
   * Resolves the tenant in the URL for the logged-in user, or answers the request itself.
   * A server the user can't manage and a server that doesn't exist look the same: 404.
   */
  async function tenantFor(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<{ session: Session; guild: GuildSettings; name: string } | null> {
    const session = await currentSession(request);
    if (!session) {
      void reply.redirect('/');
      return null;
    }
    const guildId = field(request.params, 'guildId');
    const entry = SNOWFLAKE.test(guildId) ? session.guilds.find((g) => g.id === guildId) : undefined;
    const guild = entry ? await stores.guilds.get(entry.id) : null;
    if (!entry || !guild) {
      if (!entry) request.log.warn({ userId: session.userId }, 'tenant access denied');
      void send(reply, messagePage('Not found', 'There’s nothing here.', session), 404);
      return null;
    }
    return { session, guild, name: entry.name };
  }

  /** Every form carries the session's CSRF token. Answers 403 itself when it doesn't match. */
  function csrfOk(request: FastifyRequest, reply: FastifyReply, session: Session): boolean {
    if (sameToken(field(request.body, '_csrf'), session.csrf)) return true;
    void send(reply, messagePage('Expired', 'That form is out of date. Go back, reload and try again.', session), 403);
    return false;
  }

  app.get('/healthz', (_request, reply) => reply.send({ ok: true }));

  app.get('/static/style.css', (_request, reply) => reply.type('text/css; charset=utf-8').send(STYLESHEET));

  app.get('/', async (request, reply) => {
    if (await currentSession(request)) return reply.redirect('/servers');
    return send(reply, landingPage());
  });

  app.get('/auth/login', async (request, reply) => {
    if (!limits.logins.take(request.ip)) {
      return send(reply, messagePage('Slow down', 'Too many login attempts. Try again in a minute.'), 429);
    }
    // Cookies belong to one host name, and Discord always sends people back to the public address.
    // Someone who opened the site under another name (127.0.0.1 instead of localhost) would come
    // back without the state cookie, so move them to the public address first. Once only, so a
    // proxy that rewrites the Host header can't cause a redirect loop.
    if (request.host !== publicUrl.host && field(request.query, 'moved') === '') {
      return reply.redirect(new URL('/auth/login?moved=1', publicUrl).toString());
    }
    // The state ties the callback to this browser, so a login can't be started for someone else.
    const state = newToken();
    return reply.setCookie(STATE_COOKIE, state, { ...cookieOptions, maxAge: STATE_TTL_SECONDS }).redirect(oauth.authorizeUrl(state));
  });

  app.get('/auth/callback', async (request, reply) => {
    if (!limits.logins.take(request.ip)) {
      return send(reply, messagePage('Slow down', 'Too many login attempts. Try again in a minute.'), 429);
    }
    const expected = request.cookies[STATE_COOKIE] ?? '';
    const state = field(request.query, 'state');
    const code = field(request.query, 'code');
    void reply.clearCookie(STATE_COOKIE, cookieOptions);

    const problem = !TOKEN.test(expected)
      ? 'no state cookie'
      : !sameToken(state, expected)
        ? 'state mismatch'
        : code.length === 0 || code.length > 200
          ? 'no usable code'
          : null;
    if (problem) {
      // Which check failed, but none of the values.
      request.log.warn({ problem, deniedByUser: field(request.query, 'error') === 'access_denied' }, 'login callback rejected');
      return send(
        reply,
        messagePage('Login failed', `The login didn’t complete. Open ${publicUrl.origin} and try again.`),
        400,
      );
    }

    let login;
    try {
      login = await oauth.login(code);
    } catch (error) {
      request.log.warn({ err: { message: error instanceof Error ? error.message : 'unknown' } }, 'discord login failed');
      return send(reply, messagePage('Login failed', 'Discord didn’t confirm the login. Please try again.'), 502);
    }

    // Always a fresh session ID at login, and the old one stops working.
    const previous = request.cookies[SESSION_COOKIE];
    if (previous) await sessions.destroy(previous);
    const id = await sessions.create({
      userId: login.user.id,
      username: login.user.username,
      csrf: newToken(),
      guilds: login.manageableGuilds,
    });
    request.log.info({ userId: login.user.id }, 'login');
    return reply.setCookie(SESSION_COOKIE, id, { ...cookieOptions, maxAge: SESSION_TTL_SECONDS }).redirect('/servers');
  });

  app.post('/auth/logout', async (request, reply) => {
    const session = await currentSession(request);
    if (!session) return reply.redirect('/', 303);
    if (!csrfOk(request, reply, session)) return reply;
    await sessions.destroy(request.cookies[SESSION_COOKIE] ?? '');
    return reply.clearCookie(SESSION_COOKIE, cookieOptions).redirect('/', 303);
  });

  app.get('/servers', async (request, reply) => {
    const session = await currentSession(request);
    if (!session) return reply.redirect('/');
    // Only servers that are active tenants, i.e. the bot is installed.
    const found = await Promise.all(session.guilds.map(async (g) => ((await stores.guilds.get(g.id)) ? g : null)));
    return send(reply, serversPage(session, found.filter((g) => g !== null)));
  });

  app.get('/servers/:guildId', async (request, reply) => {
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
    // Messages come from a fixed table, so nothing from the query string is ever shown.
    const notice = field(request.query, 'notice');
    const error = field(request.query, 'error');
    return send(
      reply,
      tenantPage({
        session,
        name,
        guild,
        openCount,
        detections,
        allowlist,
        audit,
        intelStatus,
        snapshot,
        botEnabled: bot.enabled,
        notice: Object.hasOwn(NOTICES, notice) ? (notice as keyof typeof NOTICES) : undefined,
        error: Object.hasOwn(ERRORS, error) ? (error as keyof typeof ERRORS) : undefined,
      }),
    );
  });

  app.post('/servers/:guildId/mode', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant || !csrfOk(request, reply, tenant.session)) return reply;
    const { session, guild } = tenant;
    const mode = field(request.body, 'mode') as GuildMode;
    if (!GUILD_MODES.includes(mode)) return reply.redirect(`/servers/${guild.id}?error=mode`, 303);

    await stores.guilds.setMode(guild.id, mode);
    await stores.audit.write({
      guildId: guild.id,
      actor: session.userId,
      action: 'settings.mode',
      target: null,
      details: { from: guild.mode, to: mode, via: 'dashboard' },
    });
    return reply.redirect(`/servers/${guild.id}?notice=mode`, 303);
  });

  /** Sends a request to the bot and redirects back with a fixed notice or error. */
  async function sendToBot(reply: FastifyReply, guildId: string, action: DashboardAction): Promise<FastifyReply> {
    const outcome = await bot.send(action).catch(() => 'bot_unavailable' as const);
    const target = OUTCOME_REDIRECT[outcome];
    const query = 'notice' in target ? `notice=${target.notice}` : `error=${target.error}`;
    return reply.redirect(`/servers/${guildId}?${query}`, 303);
  }

  /** Common checks for requests to the bot: logged in, manages this server, CSRF, rate limit. */
  async function actionTenant(request: FastifyRequest, reply: FastifyReply) {
    const tenant = await tenantFor(request, reply);
    if (!tenant || !csrfOk(request, reply, tenant.session)) return null;
    if (!limits.actions.take(tenant.session.userId)) {
      void send(reply, messagePage('Slow down', 'Too many changes in a minute. Try again shortly.', tenant.session), 429);
      return null;
    }
    return tenant;
  }

  /** Restore, false positive or confirm, like the buttons on the alert in Discord. */
  app.post('/servers/:guildId/detections/:detectionId/review', async (request, reply) => {
    const tenant = await actionTenant(request, reply);
    if (!tenant) return reply;
    const detectionId = field(request.params, 'detectionId');
    const decision = field(request.body, 'decision') as (typeof REVIEW_DECISIONS)[number];
    if (!UUID.test(detectionId) || !REVIEW_DECISIONS.includes(decision)) {
      return reply.redirect(`/servers/${tenant.guild.id}?error=detection_missing`, 303);
    }
    return sendToBot(reply, tenant.guild.id, {
      type: 'review',
      guildId: tenant.guild.id,
      actorId: tenant.session.userId,
      detectionId,
      decision,
    });
  });

  /** Alert channel, mod role and quarantine role, like /equinox setup. The bot re-checks all of it. */
  app.post('/servers/:guildId/setup', async (request, reply) => {
    const tenant = await actionTenant(request, reply);
    if (!tenant) return reply;
    const channel = field(request.body, 'alert_channel');
    const modRole = field(request.body, 'mod_role');
    const quarantineRole = field(request.body, 'quarantine_role');
    if (!SNOWFLAKE.test(channel)) return reply.redirect(`/servers/${tenant.guild.id}?error=setup_channel`, 303);
    if (modRole && !SNOWFLAKE.test(modRole)) return reply.redirect(`/servers/${tenant.guild.id}?error=setup_mod_role`, 303);
    if (quarantineRole && !SNOWFLAKE.test(quarantineRole)) {
      return reply.redirect(`/servers/${tenant.guild.id}?error=setup_quarantine_role`, 303);
    }
    return sendToBot(reply, tenant.guild.id, {
      type: 'setup',
      guildId: tenant.guild.id,
      actorId: tenant.session.userId,
      alertChannelId: channel,
      modRoleId: modRole || null,
      quarantineRoleId: quarantineRole || null,
    });
  });

  /** A harmless test alert, like /equinox test. */
  app.post('/servers/:guildId/test', async (request, reply) => {
    const tenant = await actionTenant(request, reply);
    if (!tenant) return reply;
    return sendToBot(reply, tenant.guild.id, { type: 'test', guildId: tenant.guild.id, actorId: tenant.session.userId });
  });

  /**
   * "Check a link", like /equinox check in Discord: local heuristics, this server's allowlist,
   * the network blocklist and cached intel. Unknown links are queued for the intel worker.
   * A POST with the CSRF token, so another site can't make an admin's browser trigger lookups.
   */
  app.post('/servers/:guildId/check', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant || !csrfOk(request, reply, tenant.session)) return reply;
    const { session, guild, name } = tenant;
    if (!limits.checks.take(session.userId)) {
      return send(reply, messagePage('Slow down', 'You can check 10 links a minute. Try again shortly.', session), 429);
    }
    const input = field(request.body, 'url');
    const finding = parseLinkInput(input);
    if (!finding) return reply.redirect(`/servers/${guild.id}?error=url`, 303);

    const candidates = domainCandidates(finding.normalized);
    const [allowlisted, blocklisted, cached] = await Promise.all([
      stores.allowlist.hasAny(guild.id, 'domain', candidates),
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
    return send(reply, checkResultPage({ session, guildId: guild.id, name, result, queued }));
  });

  app.post('/servers/:guildId/allowlist', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant || !csrfOk(request, reply, tenant.session)) return reply;
    const { session, guild } = tenant;
    const domain = parseDomainInput(field(request.body, 'domain'));
    if (!domain) return reply.redirect(`/servers/${guild.id}?error=domain`, 303);

    await stores.allowlist.add({ guildId: guild.id, type: 'domain', value: domain, addedBy: session.userId });
    await stores.audit.write({
      guildId: guild.id,
      actor: session.userId,
      action: 'allowlist.add',
      target: domain,
      details: { via: 'dashboard' },
    });
    return reply.redirect(`/servers/${guild.id}?notice=added`, 303);
  });

  app.post('/servers/:guildId/allowlist/remove', async (request, reply) => {
    const tenant = await tenantFor(request, reply);
    if (!tenant || !csrfOk(request, reply, tenant.session)) return reply;
    const { session, guild } = tenant;
    const domain = parseDomainInput(field(request.body, 'domain'));
    if (!domain || !(await stores.allowlist.remove(guild.id, 'domain', domain))) {
      return reply.redirect(`/servers/${guild.id}?error=missing`, 303);
    }

    await stores.audit.write({
      guildId: guild.id,
      actor: session.userId,
      action: 'allowlist.remove',
      target: domain,
      details: { via: 'dashboard' },
    });
    return reply.redirect(`/servers/${guild.id}?notice=removed`, 303);
  });

  return app;
}
