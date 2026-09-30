import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Detection } from '@equinox/core';
import { ADMIN, createTestApp, HOST, OTHER_TENANT, TENANT } from './test-helpers.js';

const form = (fields: Record<string, string>) => ({
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  payload: new URLSearchParams(fields).toString(),
});

function detection(overrides: Partial<Detection> = {}): Detection {
  return {
    id: randomUUID(),
    guildId: TENANT,
    userId: '200000000000000001',
    channelId: null,
    messageId: null,
    signalKind: 'url',
    subject: 'https://dlscord.gift/abc',
    verdict: { level: 'malicious', score: 0.95, sources: ['heuristic'], reasons: [] },
    actionsTaken: [{ action: 'alert', ok: true }],
    status: 'open',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}

describe('login', () => {
  it('shows the landing page with security headers and no scripts allowed', async () => {
    const t = await createTestApp();
    const res = await t.app.inject({ method: 'GET', url: '/' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Log in with Discord');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('sends the user to Discord with a state kept in an HttpOnly cookie', async () => {
    const t = await createTestApp();
    const res = await t.app.inject({ method: 'GET', url: '/auth/login', headers: HOST });
    const cookie = res.cookies.find((c) => c.name === 'eq_oauth_state');
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe(`https://discord.com/oauth2/authorize?state=${cookie?.value}`);
    expect(cookie).toMatchObject({ httpOnly: true, sameSite: 'Lax', path: '/' });
  });

  it('moves a login started under another host name to the public address, once', async () => {
    const t = await createTestApp();
    const other = { host: '127.0.0.1:3000' };
    const res = await t.app.inject({ method: 'GET', url: '/auth/login', headers: other });
    expect(res.headers.location).toBe('http://localhost:3000/auth/login?moved=1');
    expect(res.cookies).toHaveLength(0);

    const again = await t.app.inject({ method: 'GET', url: '/auth/login?moved=1', headers: other });
    expect(again.headers.location).toMatch(/^https:\/\/discord\.com\/oauth2\/authorize\?/);
  });

  it('creates a session and sets an HttpOnly cookie', async () => {
    const t = await createTestApp();
    const { callback, cookies } = await t.logIn();
    expect(callback.statusCode).toBe(302);
    expect(callback.headers.location).toBe('/servers');
    expect(callback.cookies.find((c) => c.name === 'eq_session')).toMatchObject({ httpOnly: true, sameSite: 'Lax' });
    expect(t.sessions.sessions.get(cookies.eq_session)).toMatchObject({ userId: ADMIN, guilds: [{ id: TENANT }] });
  });

  it.each([
    ['a missing state cookie', {}, 'x'.repeat(43)],
    ['a state that doesn’t match', { eq_oauth_state: 'a'.repeat(43) }, 'b'.repeat(43)],
    ['a malformed state', { eq_oauth_state: 'short' }, 'short'],
  ])('rejects a callback with %s', async (_name, cookies, state) => {
    const t = await createTestApp();
    const res = await t.app.inject({ method: 'GET', url: `/auth/callback?code=abc&state=${state}`, cookies });
    expect(res.statusCode).toBe(400);
    expect(t.sessions.sessions.size).toBe(0);
  });

  it('does not log in when Discord rejects the code, and shows no details', async () => {
    const t = await createTestApp();
    t.discord.login = new Error('invalid_grant client_secret=hunter2');
    const start = await t.app.inject({ method: 'GET', url: '/auth/login', headers: HOST });
    const state = t.discord.states.at(-1)!;
    const res = await t.app.inject({
      method: 'GET',
      url: `/auth/callback?code=abc&state=${state}`,
      cookies: { eq_oauth_state: start.cookies[0]!.value },
    });
    expect(res.statusCode).toBe(502);
    expect(res.body).not.toContain('hunter2');
    expect(t.sessions.sessions.size).toBe(0);
  });

  it('logging in again replaces the old session', async () => {
    const t = await createTestApp();
    const first = await t.logIn();
    const start = await t.app.inject({ method: 'GET', url: '/auth/login', headers: HOST });
    await t.app.inject({
      method: 'GET',
      url: `/auth/callback?code=abc&state=${t.discord.states.at(-1)!}`,
      cookies: { ...first.cookies, eq_oauth_state: start.cookies[0]!.value },
    });
    expect(t.sessions.sessions.has(first.cookies.eq_session)).toBe(false);
    expect(t.sessions.sessions.size).toBe(1);
  });

  it('logout needs the CSRF token and ends the session', async () => {
    const t = await createTestApp();
    const { cookies, csrf } = await t.logIn();
    const forged = await t.app.inject({ method: 'POST', url: '/auth/logout', cookies, ...form({ _csrf: 'nope' }) });
    expect(forged.statusCode).toBe(403);
    expect(t.sessions.sessions.size).toBe(1);

    const res = await t.app.inject({ method: 'POST', url: '/auth/logout', cookies, ...form({ _csrf: csrf }) });
    expect(res.statusCode).toBe(303);
    expect(t.sessions.sessions.size).toBe(0);
    expect((await t.app.inject({ method: 'GET', url: '/servers', cookies })).headers.location).toBe('/');
  });
});

describe('tenant access', () => {
  it('sends anonymous visitors back to the landing page', async () => {
    const t = await createTestApp();
    for (const url of ['/servers', `/servers/${TENANT}`]) {
      const res = await t.app.inject({ method: 'GET', url });
      expect(res.statusCode).toBe(302);
      expect(res.headers.location).toBe('/');
    }
    const post = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/mode`, ...form({ mode: 'strict' }) });
    expect(post.statusCode).toBe(302);
    expect(t.guilds.get(TENANT)?.mode).toBe('alert_only');
  });

  it('lists only servers the user manages that are active tenants', async () => {
    const t = await createTestApp();
    t.discord.login = {
      user: { id: ADMIN, username: 'admin' },
      manageableGuilds: [
        { id: TENANT, name: 'Test server' },
        { id: '100000000000000009', name: 'No bot here' },
      ],
    };
    const { cookies } = await t.logIn();
    const res = await t.app.inject({ method: 'GET', url: '/servers', cookies });
    expect(res.body).toContain('Test server');
    expect(res.body).not.toContain('No bot here');
    expect(res.body).not.toContain(OTHER_TENANT);
  });

  it('shows a tenant to its manager', async () => {
    const t = await createTestApp();
    t.detections.push(detection(), detection({ guildId: OTHER_TENANT, subject: 'https://other-tenant.example/' }));
    const { cookies } = await t.logIn();
    const res = await t.app.inject({ method: 'GET', url: `/servers/${TENANT}`, cookies });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('hxxps://dlscord[.]gift/abc');
    expect(res.body).not.toContain('https://dlscord.gift');
    expect(res.body).not.toContain('other-tenant');
  });

  it.each([
    ['another tenant', OTHER_TENANT],
    ['a server that isn’t a tenant', '100000000000000009'],
    ['a malformed ID', 'abc'],
  ])('answers 404 for %s, on every route', async (_name, id) => {
    const t = await createTestApp();
    const { cookies, csrf } = await t.logIn();
    expect((await t.app.inject({ method: 'GET', url: `/servers/${id}`, cookies })).statusCode).toBe(404);
    for (const [path, fields] of [
      ['mode', { mode: 'strict' }],
      ['allowlist', { domain: 'example.com' }],
      ['allowlist/remove', { domain: 'example.com' }],
    ] as const) {
      const res = await t.app.inject({ method: 'POST', url: `/servers/${id}/${path}`, cookies, ...form({ _csrf: csrf, ...fields }) });
      expect(res.statusCode).toBe(404);
    }
    expect(t.guilds.get(OTHER_TENANT)?.mode).toBe('alert_only');
    expect(t.allowlist).toHaveLength(0);
    expect(t.audit).toHaveLength(0);
  });

  it('treats a server the bot has left as gone', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    t.guilds.delete(TENANT);
    expect((await t.app.inject({ method: 'GET', url: `/servers/${TENANT}`, cookies })).statusCode).toBe(404);
  });
});

describe('settings changes', () => {
  it('rejects forms without the CSRF token', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    for (const fields of [{ mode: 'strict' }, { mode: 'strict', _csrf: 'a'.repeat(43) }]) {
      const res = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/mode`, cookies, ...form(fields) });
      expect(res.statusCode).toBe(403);
    }
    expect(t.guilds.get(TENANT)?.mode).toBe('alert_only');
    expect(t.audit).toHaveLength(0);
  });

  it('changes the mode and audits who did it', async () => {
    const t = await createTestApp();
    const { cookies, csrf } = await t.logIn();
    const res = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/mode`, cookies, ...form({ _csrf: csrf, mode: 'protect' }) });
    expect(res.statusCode).toBe(303);
    expect(t.guilds.get(TENANT)?.mode).toBe('protect');
    expect(t.audit.at(-1)).toMatchObject({
      guildId: TENANT,
      actor: ADMIN,
      action: 'settings.mode',
      details: { from: 'alert_only', to: 'protect', via: 'dashboard' },
    });
  });

  it('rejects a mode that isn’t one of the three', async () => {
    const t = await createTestApp();
    const { cookies, csrf } = await t.logIn();
    const res = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/mode`, cookies, ...form({ _csrf: csrf, mode: 'yolo' }) });
    expect(res.headers.location).toBe(`/servers/${TENANT}?error=mode`);
    expect(t.guilds.get(TENANT)?.mode).toBe('alert_only');
  });

  it('validates, stores and audits allowlist changes', async () => {
    const t = await createTestApp();
    const { cookies, csrf } = await t.logIn();
    const post = (path: string, domain: string) =>
      t.app.inject({ method: 'POST', url: `/servers/${TENANT}/${path}`, cookies, ...form({ _csrf: csrf, domain }) });

    expect((await post('allowlist', 'https://x.com/path')).headers.location).toBe(`/servers/${TENANT}?error=domain`);
    expect(t.allowlist).toHaveLength(0);

    await post('allowlist', 'Example.com');
    expect(t.allowlist).toMatchObject([{ guildId: TENANT, type: 'domain', value: 'example.com', addedBy: ADMIN }]);
    expect(t.audit.at(-1)).toMatchObject({ action: 'allowlist.add', target: 'example.com', actor: ADMIN });

    expect((await post('allowlist/remove', 'nope.com')).headers.location).toBe(`/servers/${TENANT}?error=missing`);
    await post('allowlist/remove', 'example.com');
    expect(t.allowlist).toHaveLength(0);
    expect(t.audit.at(-1)).toMatchObject({ action: 'allowlist.remove', target: 'example.com' });
  });
});

describe('output and failure handling', () => {
  it('escapes names and subjects that contain markup', async () => {
    const t = await createTestApp();
    t.discord.login = {
      user: { id: ADMIN, username: '<img src=x onerror=alert(1)>' },
      manageableGuilds: [{ id: TENANT, name: '<script>alert(1)</script>' }],
    };
    t.detections.push(detection({ signalKind: 'report', subject: '"><script>alert(2)</script>' }));
    const { cookies } = await t.logIn();
    for (const url of ['/servers', `/servers/${TENANT}`]) {
      const res = await t.app.inject({ method: 'GET', url, cookies });
      expect(res.body).not.toContain('<script>');
      expect(res.body).not.toContain('<img');
      expect(res.body).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    }
  });

  it('never reflects the query string', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    const res = await t.app.inject({
      method: 'GET',
      url: `/servers/${TENANT}?notice=${encodeURIComponent('<script>x</script>')}&error=toString`,
      cookies,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain('script');
    expect(res.body).not.toContain('class="notice');
  });

  it('shows only a reference when something breaks', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    t.sessions.get = () => Promise.reject(new Error('connect ECONNREFUSED password=hunter2'));
    const res = await t.app.inject({ method: 'GET', url: '/servers', cookies });
    expect(res.statusCode).toBe(500);
    expect(res.body).toMatch(/Reference: [0-9a-f]{8}/);
    expect(res.body).not.toContain('hunter2');
  });

  it('rate-limits an address after 120 requests a minute', async () => {
    const t = await createTestApp();
    let last = 0;
    for (let i = 0; i < 121; i++) last = (await t.app.inject({ method: 'GET', url: '/healthz' })).statusCode;
    expect(last).toBe(429);
  });

  it('rate-limits login attempts more tightly', async () => {
    const t = await createTestApp();
    let last = 0;
    for (let i = 0; i < 11; i++) last = (await t.app.inject({ method: 'GET', url: '/auth/login', headers: HOST })).statusCode;
    expect(last).toBe(429);
  });
});
