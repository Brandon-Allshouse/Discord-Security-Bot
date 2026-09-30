import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { fastify, LogController, type FastifyBaseLogger, type FastifyReply, type FastifyRequest } from 'fastify';
import { RateLimiter, type BotOutcome } from '@equinox/core';
import { ApiError, type ApiClient } from './api-client.js';
import type { Html } from './html.js';
import { checkResultPage, ERRORS, landingPage, messagePage, NOTICES, serversPage, STYLESHEET, tenantPage } from './views.js';

/**
 * The dashboard is the frontend. It renders pages and handles the browser side of login
 * (cookies, the OAuth state), and gets every piece of data from the API. It has no database,
 * Redis or Discord credentials: see api-client.ts.
 */
export interface DashboardDeps {
  api: ApiClient;
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
/** Must match the API's session lifetime; the API is the one that actually expires sessions. */
const SESSION_TTL_SECONDS = 60 * 60;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const SNOWFLAKE = /^\d{17,20}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Where to send the user after a request to the bot: a fixed notice or error key, never the bot's text. */
const OUTCOME_REDIRECT: Record<BotOutcome, { notice: keyof typeof NOTICES } | { error: keyof typeof ERRORS }> = {
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
  const { api } = deps;
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
  // Per address: the dashboard is the only part that sees who's connecting. Per-user limits live in the API.
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
    if (error instanceof ApiError) return apiFailure(request, reply, error);
    // Full details go to the log. The user just gets a short ref they can pass to us.
    const ref = randomUUID().slice(0, 8);
    request.log.error({ err: error, ref }, 'request failed');
    return send(reply, messagePage('Something went wrong', `Reference: ${ref}`), 500);
  });

  /** What the user sees when the API says no. Only fixed messages, never the API's own text. */
  function apiFailure(request: FastifyRequest, reply: FastifyReply, error: ApiError): FastifyReply {
    const guildId = field(request.params, 'guildId');
    const back = SNOWFLAKE.test(guildId) ? `/servers/${guildId}` : '/servers';
    switch (error.code) {
      case 'unauthenticated':
        // Session expired or logged out elsewhere: forget the cookie and start over.
        return reply.clearCookie(SESSION_COOKIE, cookieOptions).redirect('/', 303);
      case 'csrf':
        return send(reply, messagePage('Expired', 'That form is out of date. Go back, reload and try again.'), 403);
      case 'not_found':
        return send(reply, messagePage('Not found', 'There’s nothing here.'), 404);
      case 'rate_limited':
        return send(reply, messagePage('Slow down', 'Too many requests in a minute. Try again shortly.'), 429);
      case 'mode':
      case 'domain':
      case 'missing':
      case 'url':
        return reply.redirect(`${back}?error=${error.code}`, 303);
      case 'signature':
        // The dashboard and the API disagree about the signing key: an operator problem, not the user's.
        request.log.error('the API rejected the dashboard’s signature: check API_SIGNING_KEY on both');
        return send(reply, messagePage('Temporarily unavailable', 'Try again in a minute.'), 503);
      case 'bad_request':
        return send(reply, messagePage('Bad request', 'That request didn’t look right.'), 400);
      default:
        if (error.ref) {
          // The API failed unexpectedly and logged the details under this reference.
          request.log.error({ apiRef: error.ref }, 'API request failed');
          return send(reply, messagePage('Something went wrong', `Reference: ${error.ref}`), 500);
        }
        request.log.warn({ status: error.status, code: error.code }, 'API unavailable');
        return send(reply, messagePage('Temporarily unavailable', 'Try again in a minute.'), 503);
    }
  }

  /** The session cookie's value, if it has the right shape. The API decides whether it's valid. */
  function sessionCookie(request: FastifyRequest): string | null {
    const id = request.cookies[SESSION_COOKIE];
    return id && TOKEN.test(id) ? id : null;
  }

  /** The session and the server in the URL, or answers the request itself (log in, or 404). */
  function tenantRequest(request: FastifyRequest, reply: FastifyReply): { session: string; guildId: string } | null {
    const session = sessionCookie(request);
    if (!session) {
      void reply.redirect('/');
      return null;
    }
    const guildId = field(request.params, 'guildId');
    if (!SNOWFLAKE.test(guildId)) {
      void send(reply, messagePage('Not found', 'There’s nothing here.'), 404);
      return null;
    }
    return { session, guildId };
  }

  async function botResult(reply: FastifyReply, guildId: string, outcome: Promise<BotOutcome>): Promise<FastifyReply> {
    const target = OUTCOME_REDIRECT[await outcome];
    const query = 'notice' in target ? `notice=${target.notice}` : `error=${target.error}`;
    return reply.redirect(`/servers/${guildId}?${query}`, 303);
  }

  app.get('/healthz', (_request, reply) => reply.send({ ok: true }));

  app.get('/static/style.css', (_request, reply) => reply.type('text/css; charset=utf-8').send(STYLESHEET));

  app.get('/', async (request, reply) => {
    if (sessionCookie(request)) return reply.redirect('/servers');
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
    const state = randomBytes(32).toString('base64url');
    const url = await api.authorizeUrl(state);
    return reply.setCookie(STATE_COOKIE, state, { ...cookieOptions, maxAge: STATE_TTL_SECONDS }).redirect(url);
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
      return send(reply, messagePage('Login failed', `The login didn’t complete. Open ${publicUrl.origin} and try again.`), 400);
    }

    let sessionId: string;
    try {
      // The API exchanges the code with Discord and starts a fresh session; the old one stops working.
      sessionId = await api.createSession(code, sessionCookie(request) ?? undefined);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'discord') {
        return send(reply, messagePage('Login failed', 'Discord didn’t confirm the login. Please try again.'), 502);
      }
      throw error;
    }
    return reply.setCookie(SESSION_COOKIE, sessionId, { ...cookieOptions, maxAge: SESSION_TTL_SECONDS }).redirect('/servers');
  });

  app.post('/auth/logout', async (request, reply) => {
    const session = sessionCookie(request);
    if (!session) return reply.redirect('/', 303);
    await api.logout(session, field(request.body, '_csrf'));
    return reply.clearCookie(SESSION_COOKIE, cookieOptions).redirect('/', 303);
  });

  app.get('/servers', async (request, reply) => {
    const session = sessionCookie(request);
    if (!session) return reply.redirect('/');
    const me = await api.me(session);
    return send(reply, serversPage({ username: me.user.username, csrf: me.csrf }, me.guilds));
  });

  app.get('/servers/:guildId', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    const page = await api.guild(target.session, target.guildId);
    // Messages come from a fixed table, so nothing from the query string is ever shown.
    const notice = field(request.query, 'notice');
    const error = field(request.query, 'error');
    return send(
      reply,
      tenantPage({
        ...page,
        notice: Object.hasOwn(NOTICES, notice) ? (notice as keyof typeof NOTICES) : undefined,
        error: Object.hasOwn(ERRORS, error) ? (error as keyof typeof ERRORS) : undefined,
      }),
    );
  });

  app.post('/servers/:guildId/mode', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    await api.setMode(target.session, target.guildId, field(request.body, '_csrf'), field(request.body, 'mode'));
    return reply.redirect(`/servers/${target.guildId}?notice=mode`, 303);
  });

  app.post('/servers/:guildId/allowlist', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    await api.allowlistAdd(target.session, target.guildId, field(request.body, '_csrf'), field(request.body, 'domain'));
    return reply.redirect(`/servers/${target.guildId}?notice=added`, 303);
  });

  app.post('/servers/:guildId/allowlist/remove', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    await api.allowlistRemove(target.session, target.guildId, field(request.body, '_csrf'), field(request.body, 'domain'));
    return reply.redirect(`/servers/${target.guildId}?notice=removed`, 303);
  });

  /** "Check a link", like /equinox check in Discord. The API does the checking. */
  app.post('/servers/:guildId/check', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    const { viewer, name, result, queued } = await api.checkLink(
      target.session,
      target.guildId,
      field(request.body, '_csrf'),
      field(request.body, 'url'),
    );
    return send(reply, checkResultPage({ viewer, guildId: target.guildId, name, result, queued }));
  });

  /** Restore, false positive or confirm, like the buttons on the alert in Discord. */
  app.post('/servers/:guildId/detections/:detectionId/review', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    const detectionId = field(request.params, 'detectionId');
    if (!UUID.test(detectionId)) return reply.redirect(`/servers/${target.guildId}?error=detection_missing`, 303);
    const csrf = field(request.body, '_csrf');
    return botResult(reply, target.guildId, api.review(target.session, target.guildId, csrf, detectionId, field(request.body, 'decision')));
  });

  /** Alert channel, mod role and quarantine role, like /equinox setup. The API and the bot check it all. */
  app.post('/servers/:guildId/setup', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    const modRole = field(request.body, 'mod_role');
    const quarantineRole = field(request.body, 'quarantine_role');
    return botResult(
      reply,
      target.guildId,
      api.setup(target.session, target.guildId, field(request.body, '_csrf'), {
        alertChannelId: field(request.body, 'alert_channel'),
        modRoleId: modRole || null,
        quarantineRoleId: quarantineRole || null,
      }),
    );
  });

  /** A harmless test alert, like /equinox test. */
  app.post('/servers/:guildId/test', async (request, reply) => {
    const target = tenantRequest(request, reply);
    if (!target) return reply;
    return botResult(reply, target.guildId, api.test(target.session, target.guildId, field(request.body, '_csrf')));
  });

  return app;
}
