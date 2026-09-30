import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Detection, GuildSnapshot } from '@equinox/core';
import { createTestApp, HOST, OTHER_TENANT, TENANT } from './test-helpers.js';

/** A form POST from the public host name. */
const form = (fields: Record<string, string>) => ({
  headers: { ...HOST, 'content-type': 'application/x-www-form-urlencoded' },
  payload: new URLSearchParams(fields).toString(),
});

const SNAPSHOT: GuildSnapshot = {
  channels: [
    { id: '300000000000000001', name: 'mod-alerts', canPostAlerts: true },
    { id: '300000000000000002', name: 'announcements', canPostAlerts: false },
  ],
  roles: [
    { id: '600000000000000001', name: 'Moderators', canBeModRole: true, canBeQuarantineRole: true },
    { id: '600000000000000002', name: 'SomeBot', canBeModRole: false, canBeQuarantineRole: false },
    { id: '600000000000000003', name: '<b>Admins</b>', canBeModRole: true, canBeQuarantineRole: false },
  ],
  missingPermissions: [],
  updatedAt: new Date().toISOString(),
};

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
    actionsTaken: [],
    status: 'open',
    createdAt: new Date(),
    ...overrides,
  };
}

async function loggedIn() {
  const t = await createTestApp();
  const login = await t.logIn();
  const post = (path: string, fields: Record<string, string> = {}, csrf = login.csrf) =>
    t.app.inject({ method: 'POST', url: path, cookies: login.cookies, ...form({ _csrf: csrf, ...fields }) });
  const page = async () => (await t.app.inject({ method: 'GET', url: `/servers/${TENANT}`, cookies: login.cookies, headers: HOST })).body;
  return { t, login, post, page };
}

describe('settings from the dashboard', () => {
  it('shows channel and role names, and only offers what the bot can actually use', async () => {
    const { t, page } = await loggedIn();
    t.bot.snapshots.set(TENANT, SNAPSHOT);
    t.guilds.set(TENANT, { ...t.guilds.get(TENANT)!, alertChannelId: '300000000000000001', modRoleIds: ['600000000000000001'] });
    const body = await page();
    expect(body).toContain('#mod-alerts');
    expect(body).toContain('@Moderators');
    expect(body).toMatch(/<option value="300000000000000002" disabled>#announcements \(bot can’t post here\)/);
    // Not a mod-role option, and not a quarantine option.
    expect(body).not.toContain('@SomeBot');
    // Role names are escaped.
    expect(body).toContain('@&lt;b&gt;Admins&lt;/b&gt;');
    expect(body).toContain('Send a test alert');
  });

  it('sends setup to the bot with the user as the actor', async () => {
    const { t, post } = await loggedIn();
    t.bot.answer = 'setup_saved';
    const res = await post(`/servers/${TENANT}/setup`, { alert_channel: '300000000000000001', mod_role: '600000000000000001', quarantine_role: '' });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`/servers/${TENANT}?notice=setup`);
    expect(t.bot.sent).toEqual([
      { type: 'setup', guildId: TENANT, actorId: '500000000000000001', alertChannelId: '300000000000000001', modRoleId: '600000000000000001', quarantineRoleId: null },
    ]);
  });

  it('shows the bot’s refusal as a fixed message', async () => {
    const { t, post } = await loggedIn();
    t.bot.answer = 'setup_bad_channel';
    const res = await post(`/servers/${TENANT}/setup`, { alert_channel: '300000000000000002' });
    expect(res.headers.location).toBe(`/servers/${TENANT}?error=setup_channel`);
    const shown = await t.app.inject({ method: 'GET', url: res.headers.location as string, cookies: (await t.logIn()).cookies, headers: HOST });
    expect(shown.body).toContain('The bot can’t post in that channel');
  });

  it('rejects IDs that aren’t Discord IDs before asking the bot', async () => {
    const { t, post } = await loggedIn();
    expect((await post(`/servers/${TENANT}/setup`, { alert_channel: 'general' })).headers.location).toContain('error=setup_channel');
    expect((await post(`/servers/${TENANT}/setup`, { alert_channel: '300000000000000001', mod_role: 'x' })).headers.location).toContain(
      'error=setup_mod_role',
    );
    expect(
      (await post(`/servers/${TENANT}/setup`, { alert_channel: '300000000000000001', quarantine_role: '1; drop' })).headers.location,
    ).toContain('error=setup_quarantine_role');
    expect(t.bot.sent).toHaveLength(0);
  });

  it('warns about missing permissions, an alert channel it can’t post in, or none at all', async () => {
    const { t, page } = await loggedIn();
    t.guilds.set(TENANT, { ...t.guilds.get(TENANT)!, alertChannelId: null });
    expect(await page()).toContain('No alert channel is set');

    t.bot.snapshots.set(TENANT, { ...SNAPSHOT, missingPermissions: ['ManageMessages', 'ManageRoles'] });
    t.guilds.set(TENANT, { ...t.guilds.get(TENANT)!, alertChannelId: '300000000000000002' });
    const body = await page();
    expect(body).toContain('ManageMessages, ManageRoles');
    expect(body).toContain('can’t post in the alert channel');
  });

  it('explains what’s needed when the bot link is off or the bot hasn’t reported the server', async () => {
    const { t, page, post } = await loggedIn();
    expect(await page()).toContain('hasn’t reported this server');
    t.bot.enabled = false;
    const body = await page();
    expect(body).toContain('INTERNAL_SIGNING_KEY');
    expect(body).not.toContain('Send a test alert');
    expect((await post(`/servers/${TENANT}/test`)).headers.location).toContain('error=bot_off');
  });
});

describe('reviewing detections from the dashboard', () => {
  it('shows review buttons for detections that are still open or confirmed', async () => {
    const { t, page } = await loggedIn();
    const open = detection();
    const confirmed = detection({ status: 'confirmed' });
    const restored = detection({ status: 'restored' });
    t.detections.push(open, confirmed, restored);
    const body = await page();
    expect(body).toContain(`/detections/${open.id}/review`);
    expect(body).toContain(`/detections/${confirmed.id}/review`);
    expect(body).not.toContain(`/detections/${restored.id}/review`);
  });

  it('sends the decision to the bot and reports back', async () => {
    const { t, post } = await loggedIn();
    const id = randomUUID();
    const res = await post(`/servers/${TENANT}/detections/${id}/review`, { decision: 'false_positive' });
    expect(res.headers.location).toBe(`/servers/${TENANT}?notice=reviewed`);
    expect(t.bot.sent).toEqual([{ type: 'review', guildId: TENANT, actorId: '500000000000000001', detectionId: id, decision: 'false_positive' }]);
  });

  it('maps every bot answer to a fixed message', async () => {
    const { t, post } = await loggedIn();
    const cases = {
      already_resolved: 'error=already_resolved',
      not_found: 'error=detection_missing',
      timeout: 'error=bot_timeout',
      bot_unavailable: 'error=bot_unavailable',
      guild_unavailable: 'error=bot_unavailable',
      rejected: 'error=bot_rejected',
    } as const;
    for (const [answer, expected] of Object.entries(cases)) {
      t.bot.answer = answer as keyof typeof cases;
      expect((await post(`/servers/${TENANT}/detections/${randomUUID()}/review`, { decision: 'confirm' })).headers.location).toContain(expected);
    }
  });

  it('rejects unknown decisions and malformed IDs without asking the bot', async () => {
    const { t, post } = await loggedIn();
    expect((await post(`/servers/${TENANT}/detections/${randomUUID()}/review`, { decision: 'ban' })).headers.location).toContain(
      'error=detection_missing',
    );
    expect((await post(`/servers/${TENANT}/detections/not-a-uuid/review`, { decision: 'confirm' })).headers.location).toContain(
      'error=detection_missing',
    );
    expect(t.bot.sent).toHaveLength(0);
  });
});

describe('requests to the bot are protected', () => {
  it('need the CSRF token and a server the user manages', async () => {
    const { t, post } = await loggedIn();
    for (const path of [`/servers/${TENANT}/test`, `/servers/${TENANT}/setup`, `/servers/${TENANT}/detections/${randomUUID()}/review`]) {
      expect((await post(path, { decision: 'confirm', alert_channel: '300000000000000001' }, 'wrong')).statusCode).toBe(403);
    }
    expect((await post(`/servers/${OTHER_TENANT}/test`)).statusCode).toBe(404);
    const anonymous = await t.app.inject({ method: 'POST', url: `/servers/${TENANT}/test`, ...form({}) });
    expect(anonymous.statusCode).toBe(302);
    expect(t.bot.sent).toHaveLength(0);
  });

  it('are limited to 30 a minute per user', async () => {
    const { t, post } = await loggedIn();
    t.bot.answer = 'test_sent';
    for (let i = 0; i < 30; i++) expect((await post(`/servers/${TENANT}/test`)).statusCode).toBe(303);
    expect((await post(`/servers/${TENANT}/test`)).statusCode).toBe(429);
  });

  it('send the test alert', async () => {
    const { t, post } = await loggedIn();
    t.bot.answer = 'test_sent';
    expect((await post(`/servers/${TENANT}/test`)).headers.location).toBe(`/servers/${TENANT}?notice=test`);
    expect(t.bot.sent).toEqual([{ type: 'test', guildId: TENANT, actorId: '500000000000000001' }]);
  });
});

describe('served over https', () => {
  it('uses Secure, __Host- cookies and sends HSTS, and logging in still works', async () => {
    const t = await createTestApp('https://dash.example');
    const host = { host: 'dash.example' };
    const start = await t.app.inject({ method: 'GET', url: '/auth/login', headers: host });
    const state = start.cookies.find((c) => c.name === '__Host-eq_oauth_state');
    expect(state).toMatchObject({ secure: true, httpOnly: true, path: '/' });
    expect(state).not.toHaveProperty('domain');
    expect(start.cookies.some((c) => c.name === 'eq_oauth_state')).toBe(false);
    expect(start.headers['strict-transport-security']).toContain('max-age=31536000');

    const callback = await t.app.inject({
      method: 'GET',
      url: `/auth/callback?code=abc&state=${t.discord.states.at(-1)}`,
      headers: host,
      cookies: { '__Host-eq_oauth_state': state!.value },
    });
    const session = callback.cookies.find((c) => c.name === '__Host-eq_session');
    expect(session).toMatchObject({ secure: true, httpOnly: true, sameSite: 'Lax', path: '/' });

    const page = await t.app.inject({ method: 'GET', url: '/servers', headers: host, cookies: { '__Host-eq_session': session!.value } });
    expect(page.statusCode).toBe(200);
    // The unprefixed name is ignored over https, so a cookie planted without the prefix does nothing.
    const planted = await t.app.inject({ method: 'GET', url: '/servers', headers: host, cookies: { eq_session: session!.value } });
    expect(planted.statusCode).toBe(302);
  });
});
