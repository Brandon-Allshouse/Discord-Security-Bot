import { describe, expect, it } from 'vitest';
import { ApiClient, type Transport } from './api-client.js';
import { buildApp } from './app.js';
import { createTestApp, HOST, TENANT } from './test-helpers.js';

const form = (fields: Record<string, string>) => ({
  headers: { ...HOST, 'content-type': 'application/x-www-form-urlencoded' },
  payload: new URLSearchParams(fields).toString(),
});
const SESSION = { eq_session: 'a'.repeat(43) };

/** A dashboard whose API always answers the same way (or can't be reached). */
async function dashboardWith(transport: Transport, key = 'cd'.repeat(32)) {
  return buildApp({ api: new ApiClient(transport, key), publicUrl: 'http://localhost:3000' });
}

describe('when the API can’t help', () => {
  it('says the service is temporarily unavailable when the API is down', async () => {
    const app = await dashboardWith(() => Promise.reject(new Error('ECONNREFUSED')));
    const res = await app.inject({ method: 'GET', url: '/servers', cookies: SESSION });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('Temporarily unavailable');
    expect(res.body).not.toContain('ECONNREFUSED');
  });

  it('treats a signing key mismatch as an outage, not the user’s fault', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    // A second dashboard that signs with the wrong key, talking to the same API.
    const wrong = await dashboardWith(async ({ method, path, headers, body }) => {
      const res = await t.api.inject({
        method,
        url: path,
        headers: { ...headers, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
        ...(body !== undefined ? { payload: body } : {}),
      });
      return { status: res.statusCode, body: res.body };
    }, 'ab'.repeat(32));
    const res = await wrong.inject({ method: 'GET', url: '/servers', cookies });
    expect(res.statusCode).toBe(503);
  });

  it('shows a plain "bad request" page for input the API refuses outright', async () => {
    const t = await createTestApp();
    const { cookies, csrf } = await t.logIn();
    const res = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/allowlist`, cookies, ...form({ _csrf: csrf, domain: 'x'.repeat(400) }) });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('Bad request');
  });

  it('shows an expired-form page for a form without its token', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    const res = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/test`, cookies, headers: HOST });
    expect(res.statusCode).toBe(403);
    expect(res.body).toContain('out of date');
  });

  it('forgets an expired session and starts over', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    t.sessions.sessions.clear();
    const res = await t.app.inject({ method: 'GET', url: `/servers/${TENANT}`, cookies });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/');
    expect(res.cookies.find((c) => c.name === 'eq_session')?.value).toBe('');
  });

  it('shows a reference for an unexpected dashboard error, never the error itself', async () => {
    const api = { me: () => Promise.reject(new Error('internal detail: password=hunter2')) } as unknown as ApiClient;
    const app = await buildApp({ api, publicUrl: 'http://localhost:3000' });
    const res = await app.inject({ method: 'GET', url: '/servers', cookies: SESSION });
    expect(res.statusCode).toBe(500);
    expect(res.body).toMatch(/Reference: [0-9a-f]{8}/);
    expect(res.body).not.toContain('hunter2');
  });

  it('fails a login cleanly when the API is unreachable at the callback', async () => {
    const t = await createTestApp();
    const start = await t.app.inject({ method: 'GET', url: '/auth/login', headers: HOST });
    const state = t.discord.states.at(-1)!;
    t.sessions.create = () => Promise.reject(new Error('redis down'));
    const res = await t.app.inject({
      method: 'GET',
      url: `/auth/callback?code=abc&state=${state}`,
      cookies: { eq_oauth_state: start.cookies.find((c) => c.name === 'eq_oauth_state')!.value },
    });
    expect(res.statusCode).toBe(500);
    expect(res.body).toMatch(/Reference: [0-9a-f]{8}/);
    expect(res.cookies.some((c) => c.name === 'eq_session' && c.value !== '')).toBe(false);
  });
});

describe('small routes', () => {
  it('serves the stylesheet, answers unknown pages with 404, and sends logged-in visitors to their servers', async () => {
    const t = await createTestApp();
    const css = await t.app.inject({ method: 'GET', url: '/static/style.css' });
    expect(css.headers['content-type']).toContain('text/css');
    expect((await t.app.inject({ method: 'GET', url: '/nope' })).statusCode).toBe(404);
    const home = await t.app.inject({ method: 'GET', url: '/', cookies: SESSION });
    expect(home.headers.location).toBe('/servers');
  });

  it('sends logged-out visitors home from forms and logout', async () => {
    const t = await createTestApp();
    for (const path of [`/servers/${TENANT}/allowlist/remove`, `/servers/${TENANT}/check`, '/auth/logout']) {
      const res = await t.app.inject({ method: 'POST', url: path, ...form({}) });
      expect([302, 303], path).toContain(res.statusCode);
      expect(res.headers.location).toBe('/');
    }
    expect(t.requests).toHaveLength(0);
  });

  it('limits login callbacks per address', async () => {
    const t = await createTestApp();
    let last = 0;
    for (let i = 0; i < 11; i++) last = (await t.app.inject({ method: 'GET', url: '/auth/callback?code=x&state=y' })).statusCode;
    expect(last).toBe(429);
  });

  it('never calls the API with an ID that isn’t a Discord ID', async () => {
    const t = await createTestApp();
    const { cookies } = await t.logIn();
    const before = t.requests.length;
    const res = await t.app.inject({ method: 'GET', url: '/servers/..%2F..%2Fv1%2Fme', cookies });
    expect(res.statusCode).toBe(404);
    expect(t.requests.length).toBe(before);
  });
});
