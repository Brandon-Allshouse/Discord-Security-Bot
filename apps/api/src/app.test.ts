import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { API_REQUEST_MAX_AGE_MS, signApiRequest } from '@equinox/core';
import { ADMIN, createTestApi, OTHER_TENANT, TENANT, TEST_API_KEY } from './testing.js';

type Api = Awaited<ReturnType<typeof createTestApi>>;

/** Sends a request signed the way the dashboard signs it. `sign` can be overridden to test forgeries. */
async function call(
  t: Api,
  method: 'GET' | 'POST',
  path: string,
  options: { session?: string; body?: unknown; key?: string; now?: number; headers?: Record<string, string> } = {},
) {
  const body = options.body === undefined ? undefined : JSON.stringify(options.body);
  const headers = {
    ...signApiRequest(options.key ?? TEST_API_KEY, { method, path, body: body ?? '', session: options.session ?? '' }, options.now),
    ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    ...options.headers,
  };
  return t.api.inject({ method, url: path, headers, ...(body !== undefined ? { payload: body } : {}) });
}

/** Logs ADMIN in through the API and returns the session ID and CSRF token. */
async function login(t: Api) {
  const res = await call(t, 'POST', '/v1/auth/session', { body: { code: 'abc' } });
  const sessionId = (res.json<{ sessionId: string }>()).sessionId;
  return { session: sessionId, csrf: t.sessions.sessions.get(sessionId)!.csrf };
}

describe('only the dashboard can talk to the API', () => {
  it('answers the health check without a signature, and nothing else', async () => {
    const t = await createTestApi();
    expect((await t.api.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200);
    const unsigned = await t.api.inject({ method: 'GET', url: '/v1/me' });
    expect(unsigned.statusCode).toBe(401);
    expect(unsigned.json()).toEqual({ error: 'signature' });
  });

  it('refuses requests signed with another key', async () => {
    const t = await createTestApi();
    expect((await call(t, 'GET', '/v1/me', { key: 'ab'.repeat(32) })).json()).toEqual({ error: 'signature' });
  });

  it('refuses stale requests and ones from the future', async () => {
    const t = await createTestApi();
    expect((await call(t, 'GET', '/v1/me', { now: Date.now() - API_REQUEST_MAX_AGE_MS - 1000 })).json()).toEqual({ error: 'signature' });
    expect((await call(t, 'GET', '/v1/me', { now: Date.now() + API_REQUEST_MAX_AGE_MS + 1000 })).json()).toEqual({ error: 'signature' });
  });

  it('refuses a replayed request, even while it is still fresh', async () => {
    const t = await createTestApi();
    const { session } = await login(t);
    const headers = signApiRequest(TEST_API_KEY, { method: 'GET', path: '/v1/me', body: '', session });
    expect((await t.api.inject({ method: 'GET', url: '/v1/me', headers })).statusCode).toBe(200);
    const replay = await t.api.inject({ method: 'GET', url: '/v1/me', headers });
    expect(replay.statusCode).toBe(401);
    expect(replay.json()).toEqual({ error: 'signature' });
  });

  it('refuses a request whose body, path or session was changed after signing', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    const other = await login(t);
    const path = `/v1/guilds/${TENANT}/mode`;
    const body = JSON.stringify({ csrf, mode: 'alert_only' });
    const headers = { ...signApiRequest(TEST_API_KEY, { method: 'POST', path, body, session }), 'content-type': 'application/json' };

    const tamperedBody = await t.api.inject({ method: 'POST', url: path, headers, payload: JSON.stringify({ csrf, mode: 'strict' }) });
    expect(tamperedBody.json()).toEqual({ error: 'signature' });
    const tamperedPath = await t.api.inject({ method: 'POST', url: `/v1/guilds/${OTHER_TENANT}/mode`, headers, payload: body });
    expect(tamperedPath.json()).toEqual({ error: 'signature' });
    const swappedSession = await t.api.inject({ method: 'POST', url: path, headers: { ...headers, 'x-equinox-session': other.session }, payload: body });
    expect(swappedSession.json()).toEqual({ error: 'signature' });
    expect(t.guilds.get(TENANT)?.mode).toBe('alert_only');
  });

  it('only accepts JSON bodies', async () => {
    const t = await createTestApi();
    const res = await call(t, 'POST', '/v1/auth/session', { body: { code: 'x' }, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    expect(res.statusCode).toBe(415);
    expect(res.json()).toEqual({ error: 'bad_request' });
  });
});

describe('login and sessions', () => {
  it('builds the Discord login URL only for a well-formed state', async () => {
    const t = await createTestApi();
    const state = 'a'.repeat(43);
    expect((await call(t, 'GET', `/v1/auth/authorize-url?state=${state}`)).json()).toEqual({ url: `https://discord.com/oauth2/authorize?state=${state}` });
    expect((await call(t, 'GET', '/v1/auth/authorize-url?state=short')).statusCode).toBe(400);
  });

  it('starts a fresh session at login and ends the one it replaces', async () => {
    const t = await createTestApi();
    const first = await login(t);
    const res = await call(t, 'POST', '/v1/auth/session', { body: { code: 'abc', replaces: first.session } });
    expect(res.statusCode).toBe(201);
    expect(t.sessions.sessions.has(first.session)).toBe(false);
    expect(t.sessions.sessions.size).toBe(1);
  });

  it('says so when Discord refuses the login, without details', async () => {
    const t = await createTestApi();
    t.discord.login = new Error('invalid_grant: code=abc client_secret=hunter2');
    const res = await call(t, 'POST', '/v1/auth/session', { body: { code: 'abc' } });
    expect(res.statusCode).toBe(502);
    expect(res.body).toBe('{"error":"discord"}');
  });

  it('needs a valid session for everything a user sees', async () => {
    const t = await createTestApi();
    for (const session of [undefined, 'not-a-session', 'a'.repeat(43)]) {
      const res = await call(t, 'GET', '/v1/me', session ? { session } : {});
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual({ error: 'unauthenticated' });
    }
  });

  it('logs out only with the CSRF token', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    expect((await call(t, 'POST', '/v1/auth/logout', { session, body: { csrf: 'wrong-token-value-wrong' } })).statusCode).toBe(403);
    expect(t.sessions.sessions.has(session)).toBe(true);
    expect((await call(t, 'POST', '/v1/auth/logout', { session, body: { csrf } })).statusCode).toBe(204);
    expect(t.sessions.sessions.has(session)).toBe(false);
  });

  it('lists only servers the user manages that have the bot', async () => {
    const t = await createTestApi();
    t.discord.login = {
      user: { id: ADMIN, username: 'admin' },
      manageableGuilds: [
        { id: TENANT, name: 'Test server' },
        { id: '100000000000000777', name: 'No bot here' },
      ],
    };
    const { session } = await login(t);
    expect((await call(t, 'GET', '/v1/me', { session })).json()).toMatchObject({ guilds: [{ id: TENANT, name: 'Test server' }] });
  });
});

describe('tenant access', () => {
  it('answers 404 for a server the user doesn’t manage, one that doesn’t exist, and a malformed ID', async () => {
    const t = await createTestApi();
    const { session } = await login(t);
    for (const id of [OTHER_TENANT, '100000000000000999', 'nope', '../admin']) {
      const res = await call(t, 'GET', `/v1/guilds/${encodeURIComponent(id)}`, { session });
      expect(res.statusCode, id).toBe(404);
    }
  });

  it('returns only the settings the dashboard shows', async () => {
    const t = await createTestApi();
    const { session } = await login(t);
    const page = (await call(t, 'GET', `/v1/guilds/${TENANT}`, { session })).json<{ guild: object; viewer: { username: string; csrf: string } }>();
    expect(Object.keys(page.guild).sort()).toEqual(['alertChannelId', 'id', 'modRoleIds', 'mode', 'quarantineRoleId']);
    expect(Object.keys(page.viewer).sort()).toEqual(['csrf', 'username']);
    expect(page.viewer.username).toBe('admin');
  });

  it('never caches answers', async () => {
    const t = await createTestApi();
    const { session } = await login(t);
    expect((await call(t, 'GET', `/v1/guilds/${TENANT}`, { session })).headers['cache-control']).toBe('no-store');
  });
});

describe('changes', () => {
  it('need the CSRF token, and reject malformed bodies', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    const path = `/v1/guilds/${TENANT}/mode`;
    expect((await call(t, 'POST', path, { session, body: { csrf: 'x'.repeat(43), mode: 'strict' } })).statusCode).toBe(403);
    expect((await call(t, 'POST', path, { session, body: { mode: 'strict' } })).statusCode).toBe(400);
    expect((await call(t, 'POST', path, { session, body: { csrf, mode: ['strict'] } })).statusCode).toBe(400);
    expect(t.guilds.get(TENANT)?.mode).toBe('alert_only');
  });

  it('change the mode and audit it as the user, from the dashboard', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    expect((await call(t, 'POST', `/v1/guilds/${TENANT}/mode`, { session, body: { csrf, mode: 'yolo' } })).json()).toEqual({ error: 'mode' });
    expect((await call(t, 'POST', `/v1/guilds/${TENANT}/mode`, { session, body: { csrf, mode: 'protect' } })).json()).toEqual({ ok: true });
    expect(t.audit.at(-1)).toMatchObject({ actor: ADMIN, action: 'settings.mode', details: { from: 'alert_only', to: 'protect', via: 'dashboard' } });
  });

  it('manage the allowlist with validated domains', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    const path = `/v1/guilds/${TENANT}/allowlist`;
    expect((await call(t, 'POST', path, { session, body: { csrf, domain: 'https://x.com/path' } })).json()).toEqual({ error: 'domain' });
    expect((await call(t, 'POST', path, { session, body: { csrf, domain: 'Example.com' } })).json()).toEqual({ ok: true });
    expect(t.allowlist.map((a) => a.value)).toEqual(['example.com']);
    expect((await call(t, 'POST', `${path}/remove`, { session, body: { csrf, domain: 'other.com' } })).json()).toEqual({ error: 'missing' });
    expect((await call(t, 'POST', `${path}/remove`, { session, body: { csrf, domain: 'example.com' } })).json()).toEqual({ ok: true });
  });

  it('can’t touch another server', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    expect((await call(t, 'POST', `/v1/guilds/${OTHER_TENANT}/mode`, { session, body: { csrf, mode: 'strict' } })).statusCode).toBe(404);
    expect(t.guilds.get(OTHER_TENANT)?.mode).toBe('alert_only');
  });
});

describe('requests to the bot', () => {
  it('check IDs and decisions before anything is sent', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    const setup = (body: object) => call(t, 'POST', `/v1/guilds/${TENANT}/setup`, { session, body: { csrf, modRoleId: null, quarantineRoleId: null, ...body } });
    expect((await setup({ alertChannelId: 'general' })).json()).toEqual({ outcome: 'setup_bad_channel' });
    expect((await setup({ alertChannelId: '300000000000000001', modRoleId: 'x' })).json()).toEqual({ outcome: 'setup_bad_mod_role' });
    expect((await setup({ alertChannelId: '300000000000000001', quarantineRoleId: '1;drop' })).json()).toEqual({ outcome: 'setup_bad_quarantine_role' });
    const review = (id: string, decision: string) => call(t, 'POST', `/v1/guilds/${TENANT}/detections/${id}/review`, { session, body: { csrf, decision } });
    expect((await review('not-a-uuid', 'confirm')).json()).toEqual({ outcome: 'not_found' });
    expect((await review(randomUUID(), 'ban')).json()).toEqual({ outcome: 'not_found' });
    expect(t.bot.sent).toHaveLength(0);
  });

  it('send valid requests with the logged-in user as the actor', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    t.bot.answer = 'setup_saved';
    const res = await call(t, 'POST', `/v1/guilds/${TENANT}/setup`, {
      session,
      body: { csrf, alertChannelId: '300000000000000001', modRoleId: '600000000000000001', quarantineRoleId: null },
    });
    expect(res.json()).toEqual({ outcome: 'setup_saved' });
    expect(t.bot.sent).toEqual([
      { type: 'setup', guildId: TENANT, actorId: ADMIN, alertChannelId: '300000000000000001', modRoleId: '600000000000000001', quarantineRoleId: null },
    ]);
  });

  it('are limited to 30 a minute per user', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    t.bot.answer = 'test_sent';
    for (let i = 0; i < 30; i++) expect((await call(t, 'POST', `/v1/guilds/${TENANT}/test`, { session, body: { csrf } })).statusCode).toBe(200);
    expect((await call(t, 'POST', `/v1/guilds/${TENANT}/test`, { session, body: { csrf } })).json()).toEqual({ error: 'rate_limited' });
  });
});

describe('check a link', () => {
  it('rejects input that isn’t a link, and is limited to 10 a minute per user', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    const check = (url: string) => call(t, 'POST', `/v1/guilds/${TENANT}/check`, { session, body: { csrf, url } });
    expect((await check('!!!')).json()).toEqual({ error: 'url' });
    for (let i = 1; i < 10; i++) expect((await check(`https://n${i}.test/`)).statusCode).toBe(200);
    expect((await check('https://n10.test/')).json()).toEqual({ error: 'rate_limited' });
  });
});

describe('failures', () => {
  it('give the dashboard a log reference, never the error', async () => {
    const t = await createTestApi();
    const { session } = await login(t);
    t.sessions.get = () => Promise.reject(new Error('connect ECONNREFUSED password=hunter2'));
    const res = await call(t, 'GET', '/v1/me', { session });
    expect(res.statusCode).toBe(500);
    const body = res.json<{ error: string; ref: string }>();
    expect(Object.keys(body).sort()).toEqual(['error', 'ref']);
    expect(body.error).toBe('unavailable');
    expect(body.ref).toMatch(/^[0-9a-f]{8}$/);
    expect(res.body).not.toContain('hunter2');
  });

  it('answer unknown routes with 404', async () => {
    const t = await createTestApi();
    expect((await call(t, 'GET', '/v1/admin')).statusCode).toBe(404);
  });
});

describe('edge cases', () => {
  it('rejects a signed body that isn’t valid JSON, and a login without a code', async () => {
    const t = await createTestApi();
    const body = 'not json';
    const headers = { ...signApiRequest(TEST_API_KEY, { method: 'POST', path: '/v1/auth/session', body, session: '' }), 'content-type': 'application/json' };
    expect((await t.api.inject({ method: 'POST', url: '/v1/auth/session', headers, payload: body })).statusCode).toBe(400);
    expect((await call(t, 'POST', '/v1/auth/session', { body: { nope: 1 } })).json()).toEqual({ error: 'bad_request' });
  });

  it('still serves the page when intel and the bot snapshot can’t be read', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    await call(t, 'POST', `/v1/guilds/${TENANT}/allowlist`, { session, body: { csrf, domain: 'example.com' } });
    t.intel.down = true;
    t.bot.down = true;
    const page = await call(t, 'GET', `/v1/guilds/${TENANT}`, { session });
    expect(page.statusCode).toBe(200);
    expect(page.json()).toMatchObject({ intelStatus: null, snapshot: null, allowlist: [{ value: 'example.com', addedBy: ADMIN }] });
  });

  it('refuses every change for a server the user doesn’t manage', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    const base = `/v1/guilds/${OTHER_TENANT}`;
    for (const [path, body] of [
      ['/allowlist', { domain: 'x.com' }],
      ['/allowlist/remove', { domain: 'x.com' }],
      ['/check', { url: 'https://x.test/' }],
      ['/test', {}],
      ['/setup', { alertChannelId: '300000000000000001', modRoleId: null, quarantineRoleId: null }],
      [`/detections/${randomUUID()}/review`, { decision: 'confirm' }],
    ] as const) {
      const res = await call(t, 'POST', `${base}${path}`, { session, body: { csrf, ...body } });
      expect(res.statusCode, path).toBe(404);
    }
    expect(t.bot.sent).toHaveLength(0);
    expect(t.intel.lookups).toHaveLength(0);
  });

  it('still answers a link check when intel is down, and says the lookup wasn’t queued', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    t.intel.down = true;
    const res = await call(t, 'POST', `/v1/guilds/${TENANT}/check`, { session, body: { csrf, url: 'https://unknown.test/' } });
    expect(res.json()).toMatchObject({ queued: false, result: { intelState: 'pending', blocklisted: false } });
  });

  it('sends a review, and reports the bot as unavailable if the request fails', async () => {
    const t = await createTestApi();
    const { session, csrf } = await login(t);
    const id = randomUUID();
    const review = () => call(t, 'POST', `/v1/guilds/${TENANT}/detections/${id}/review`, { session, body: { csrf, decision: 'restore' } });
    expect((await review()).json()).toEqual({ outcome: 'reviewed' });
    expect(t.bot.sent).toEqual([{ type: 'review', guildId: TENANT, actorId: ADMIN, detectionId: id, decision: 'restore' }]);
    t.bot.down = true;
    expect((await review()).json()).toEqual({ outcome: 'bot_unavailable' });
  });
});
