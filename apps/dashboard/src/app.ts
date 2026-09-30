import { randomUUID, timingSafeEqual } from 'node:crypto';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { fastify, LogController, type FastifyBaseLogger, type FastifyReply, type FastifyRequest } from 'fastify';
import { GUILD_MODES, parseDomainInput, RateLimiter, type GuildMode, type GuildSettings } from '@equinox/core';
import type { AllowlistStore, AuditStore, DetectionStore, GuildStore } from '@equinox/db';
import type { DiscordOAuth } from './discord-oauth.js';
import type { Html } from './html.js';
import { newToken, SESSION_TTL_SECONDS, type Session, type SessionStore } from './sessions.js';
import { ERRORS, landingPage, messagePage, NOTICES, serversPage, STYLESHEET, tenantPage } from './views.js';

/** The tenant-scoped stores the dashboard uses. Everything goes through row-level security. */
export interface DashboardStores {
  guilds: Pick<GuildStore, 'get' | 'setMode'>;
  detections: Pick<DetectionStore, 'recent' | 'countOpen'>;
  audit: Pick<AuditStore, 'write' | 'recent'>;
  allowlist: Pick<AllowlistStore, 'list' | 'add' | 'remove'>;
}

export interface DashboardDeps {
  stores: DashboardStores;
  sessions: SessionStore;
  oauth: DiscordOAuth;
  /** Public address of the dashboard. Over https, cookies are marked Secure and HSTS is sent. */
  publicUrl: string;
  logger?: FastifyBaseLogger;
}

const SESSION_COOKIE = 'eq_session';
const STATE_COOKIE = 'eq_oauth_state';
const STATE_TTL_SECONDS = 10 * 60;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const SNOWFLAKE = /^\d{17,20}$/;

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
  const { stores, sessions, oauth } = deps;
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
  const limits = {
    requests: new RateLimiter(120, 60_000),
    logins: new RateLimiter(10, 60_000),
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
    const [openCount, detections, allowlist, audit] = await Promise.all([
      stores.detections.countOpen(guild.id),
      stores.detections.recent(guild.id, 50),
      stores.allowlist.list(guild.id),
      stores.audit.recent(guild.id, 50),
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
