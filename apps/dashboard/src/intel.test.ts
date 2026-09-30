import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { URLHAUS_HIT, type Detection, type IntelStatus } from '@equinox/core';
import { createTestApp, HOST, OTHER_TENANT, TENANT } from './test-helpers.js';

/** A form POST from the public host name. */
const form = (fields: Record<string, string>) => ({
  headers: { ...HOST, 'content-type': 'application/x-www-form-urlencoded' },
  payload: new URLSearchParams(fields).toString(),
});

const STATUS: IntelStatus = {
  virustotal: true,
  urlhaus: { count: 13329, syncedAt: '2026-09-30T12:00:00.000Z' },
  heartbeatAt: '2026-09-30T12:05:00.000Z',
};

async function loggedIn() {
  const t = await createTestApp();
  const login = await t.logIn();
  const check = (url: string, csrf = login.csrf, guild = TENANT) =>
    t.app.inject({ method: 'POST', url: `/servers/${guild}/check`, cookies: login.cookies, ...form({ _csrf: csrf, url }) });
  const page = () => t.app.inject({ method: 'GET', url: `/servers/${TENANT}`, cookies: login.cookies, headers: HOST });
  return { t, login, check, page };
}

describe('threat intel on the server page', () => {
  it('shows which sources are working', async () => {
    const { t, page } = await loggedIn();
    t.intel.status = STATUS;
    const body = (await page()).body;
    expect(body).toContain('Threat intel');
    expect(body).toContain('Running');
    expect(body).toContain('13,329 links, updated 2026-09-30 12:00 UTC');
    expect(body).toContain('On, for links that look off');
    // Budget numbers are never shown to tenants.
    expect(body).not.toMatch(/budget|remaining|500/i);
  });

  it('says when the list is loaded but its update time is not known yet', async () => {
    const { t, page } = await loggedIn();
    t.intel.status = { ...STATUS, urlhaus: { count: 42, syncedAt: null } };
    expect((await page()).body).toContain('42 links, last update time not known yet');
  });

  it('says when VirusTotal is off or the list has not been downloaded', async () => {
    const { t, page } = await loggedIn();
    t.intel.status = { ...STATUS, virustotal: false, urlhaus: null };
    const body = (await page()).body;
    expect(body).toContain('Off (no API key configured)');
    expect(body).toContain('Not downloaded yet');
  });

  it('says plainly when the worker is not running, and still loads when Redis is down', async () => {
    const { t, page } = await loggedIn();
    expect((await page()).body).toContain('isn’t running right now');
    t.intel.down = true;
    const res = await page();
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('isn’t running right now');
  });

  it('explains each detection, including which intel sources flagged it, escaped', async () => {
    const { t, page } = await loggedIn();
    const d: Detection = {
      id: randomUUID(),
      guildId: TENANT,
      userId: '200000000000000001',
      channelId: null,
      messageId: null,
      signalKind: 'url',
      subject: 'https://late.test/',
      verdict: { level: 'malicious', score: 0.95, sources: ['heuristic', 'urlhaus'], reasons: ['<b>Listed</b> by URLhaus'] },
      actionsTaken: [],
      status: 'open',
      createdAt: new Date(),
    };
    t.detections.push(d);
    const body = (await page()).body;
    expect(body).toContain('<th>Why</th>');
    expect(body).toContain('&lt;b&gt;Listed&lt;/b&gt; by URLhaus');
    expect(body).toContain('Threat intel: urlhaus');
  });
});

describe('check a link', () => {
  it('queues a lookup for an unknown link and says so', async () => {
    const { t, check } = await loggedIn();
    const res = await check('unknown-site.test/page?utm_source=x');
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('hxxp://unknown-site[.]test/page');
    expect(res.body).toContain('No known issues');
    expect(res.body).toContain('A lookup is queued now');
    expect(t.intel.lookups).toEqual([{ url: 'http://unknown-site.test/page', heuristicScore: 0 }]);
  });

  it('shows cached intel and does not queue again', async () => {
    const { t, check } = await loggedIn();
    t.intel.cached.set('https://bad.test/x', URLHAUS_HIT);
    const res = await check('https://bad.test/x');
    expect(res.body).toContain('Malicious');
    expect(res.body).toContain('Listed by URLhaus as a malware link');
    expect(res.body).toContain('Threat intel: urlhaus');
    expect(t.intel.lookups).toHaveLength(0);
  });

  it('honors this server’s allowlist and the network blocklist', async () => {
    const { t, check } = await loggedIn();
    t.allowlist.push({ guildId: TENANT, type: 'domain', value: 'dlscord.com', addedBy: 'x', createdAt: new Date(), id: 'x' });
    expect((await check('https://dlscord.com/')).body).toContain('allowlisted in this server');
    t.intel.blocklist.add('blocked.test');
    expect((await check('https://www.blocked.test/')).body).toContain('blocklist');
    expect(t.intel.lookups).toHaveLength(0);
  });

  it('never sends well-known sites for lookups', async () => {
    const { t, check } = await loggedIn();
    expect((await check('https://github.com/org/repo')).body).toContain('well-known site');
    expect(t.intel.lookups).toHaveLength(0);
  });

  it('still answers when intel is unavailable, and says the lookup could not be queued', async () => {
    const { t, check } = await loggedIn();
    t.intel.down = true;
    const res = await check('https://unknown.test/');
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('couldn’t be queued');
  });

  it('rejects input that is not a link', async () => {
    const { t, check } = await loggedIn();
    const res = await check('!!!');
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`/servers/${TENANT}?error=url`);
    expect(t.intel.lookups).toHaveLength(0);
  });

  it('needs the CSRF token and a server the user manages', async () => {
    const { t, check } = await loggedIn();
    expect((await check('https://unknown.test/', 'wrong')).statusCode).toBe(403);
    expect((await check('https://unknown.test/', undefined, OTHER_TENANT)).statusCode).toBe(404);
    const anonymous = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/check`, ...form({ url: 'x.test' }) });
    expect(anonymous.statusCode).toBe(302);
    expect(t.intel.lookups).toHaveLength(0);
  });

  it('limits each user to 10 checks a minute', async () => {
    const { check } = await loggedIn();
    for (let i = 0; i < 10; i++) expect((await check(`https://n${i}.test/`)).statusCode).toBe(200);
    expect((await check('https://n10.test/')).statusCode).toBe(429);
  });

  it('escapes what was typed, and offers to check again with the same link', async () => {
    const { check } = await loggedIn();
    const res = await check('https://x.test/"><script>alert(1)</script>');
    expect(res.body).not.toContain('<script>alert(1)');
    expect(res.body).toContain('Check again');
  });
});
