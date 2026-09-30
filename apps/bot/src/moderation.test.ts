import { ChannelType, PermissionFlagsBits, PermissionsBitField, type Client, type Guild } from 'discord.js';
import { describe, expect, it, vi } from 'vitest';
import { processSignal, signAction, type DashboardAction, type Detection } from '@equinox/core';
import { makeGuild, makeSignal } from '@equinox/core/testing';
import { handleDashboardAction } from './handlers/dashboard-actions.js';
import { alertRefs, resolveAlertMessages, reviewWithFollowUps, saveSetup, sendTestSignal, setupProblem } from './moderation.js';
import { buildSnapshot, SnapshotPublisher } from './snapshot.js';
import { createFakeContext, silentLogger, TENANT } from './test-helpers.js';

const KEY = 'ab'.repeat(32);
const ACTOR = '500000000000000001';
const alertPerms = new PermissionsBitField([PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.EmbedLinks]);

/** Enough of a text channel for the setup checks. */
const textChannel = (id: string, perms = alertPerms) => ({
  id,
  name: `chan-${id.slice(-2)}`,
  type: ChannelType.GuildText,
  rawPosition: Number(id.slice(-2)),
  isTextBased: () => true,
  guild: { members: { me: {} } },
  permissionsFor: () => perms,
});

const role = (id: string, overrides: { editable?: boolean; managed?: boolean; position?: number } = {}) => ({
  id,
  name: `role-${id.slice(-2)}`,
  editable: true,
  managed: false,
  position: 1,
  ...overrides,
});

/** A Discord guild with a few channels and roles, as the bot's cache would hold it. */
function fakeGuild() {
  const channels = [
    textChannel('300000000000000001'),
    textChannel('300000000000000002', new PermissionsBitField([PermissionFlagsBits.ViewChannel])),
    { id: '300000000000000003', name: 'voice', type: ChannelType.GuildVoice, rawPosition: 3 },
  ];
  const roles = [
    role(TENANT, { position: 0 }), // @everyone
    role('600000000000000001', { position: 5 }),
    role('600000000000000002', { managed: true, editable: false, position: 9 }), // another bot's role
    role('600000000000000003', { editable: false, position: 20 }), // above the bot
  ];
  return {
    id: TENANT,
    channels: { cache: new Map(channels.map((c) => [c.id, c])) },
    roles: { cache: new Map(roles.map((r) => [r.id, r])) },
    members: { me: { permissions: new PermissionsBitField([PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages]) } },
  } as unknown as Guild;
}

/** A Discord client whose alert messages can be fetched and edited. */
function fakeAlertClient() {
  const edits: { messageId: string; payload: unknown }[] = [];
  const client = {
    channels: {
      fetch: vi.fn((id: string) =>
        Promise.resolve(
          id === 'gone'
            ? null
            : {
                isTextBased: () => true,
                messages: {
                  fetch: (messageId: string) =>
                    messageId === 'deleted'
                      ? Promise.reject(new Error('Unknown Message'))
                      : Promise.resolve({
                          embeds: [{ data: { title: 'Alert' } }],
                          edit: (payload: unknown) => {
                            edits.push({ messageId, payload });
                            return Promise.resolve();
                          },
                        }),
                },
              },
        ),
      ),
    },
    guilds: { cache: new Map<string, Guild>() },
  };
  return { client: client as unknown as Client, edits, raw: client };
}

describe('reviewWithFollowUps', () => {
  it('allowlists the exact host on a false positive and records where it came from', async () => {
    const t = createFakeContext();
    const result = await processSignal(makeSignal({ guildId: TENANT, subject: 'https://sub.odd-site.test/x' }), t.ctx.deps);
    if (result.status !== 'detected') throw new Error('expected detection');
    const { notes } = await reviewWithFollowUps(
      { guildId: TENANT, detectionId: result.detection.id, decision: 'false_positive', actorId: ACTOR, via: 'dashboard' },
      t.ctx,
    );
    expect(t.allowlist.has(`${TENANT}:sub.odd-site.test`)).toBe(true);
    expect(t.allowlist.has(`${TENANT}:odd-site.test`)).toBe(false);
    expect(notes).toContain('Allowlisted `sub.odd-site.test` in this server');
    expect(t.fake.audit.map((a) => a.action)).toEqual(expect.arrayContaining(['review.false_positive', 'allowlist.add']));
    expect(t.fake.audit.find((a) => a.action === 'review.false_positive')?.details).toMatchObject({ via: 'dashboard' });
  });

  it('says a deleted message can’t come back, and does nothing more for unknown detections', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT, mode: 'protect' }));
    const result = await processSignal(makeSignal({ guildId: TENANT }), t.ctx.deps);
    if (result.status !== 'detected') throw new Error('expected detection');
    const { notes } = await reviewWithFollowUps(
      { guildId: TENANT, detectionId: result.detection.id, decision: 'restore', actorId: ACTOR, via: 'discord' },
      t.ctx,
    );
    expect(notes.join('\n')).toMatch(/can’t be brought back/);

    const missing = await reviewWithFollowUps(
      { guildId: TENANT, detectionId: '0b7f5c8e-1d2a-4c3b-9e8f-7a6b5c4d3e2f', decision: 'confirm', actorId: ACTOR, via: 'discord' },
      t.ctx,
    );
    expect(missing).toEqual({ result: { status: 'not_found' }, notes: [] });
  });
});

describe('resolveAlertMessages', () => {
  const detection = (refs: { channelId: string; messageId: string }[]): Detection => ({
    id: 'd',
    guildId: TENANT,
    userId: '200000000000000001',
    channelId: null,
    messageId: null,
    signalKind: 'url',
    subject: 'https://x.test/',
    verdict: { level: 'malicious', score: 0.9, sources: ['heuristic'], reasons: [] },
    actionsTaken: [
      { action: 'delete', ok: true },
      ...refs.map((ref) => ({ action: 'alert' as const, ok: true, ref })),
      { action: 'alert', ok: false },
    ],
    status: 'restored',
    createdAt: new Date(),
  });

  it('finds every alert posted for a detection', () => {
    expect(alertRefs(detection([{ channelId: 'c', messageId: 'm1' }, { channelId: 'c', messageId: 'm2' }]).actionsTaken)).toHaveLength(2);
  });

  it('resolves each alert and removes its buttons, skipping the one already handled and any that are gone', async () => {
    const { client, edits } = fakeAlertClient();
    const d = detection([
      { channelId: 'c', messageId: 'm1' },
      { channelId: 'c', messageId: 'm2' },
      { channelId: 'c', messageId: 'deleted' },
      { channelId: 'gone', messageId: 'm3' },
    ]);
    expect(await resolveAlertMessages(client, d, 'restored', ACTOR, 'note', 'm1')).toBe(1);
    expect(edits).toHaveLength(1);
    expect(edits[0]).toMatchObject({ messageId: 'm2', payload: { components: [], allowedMentions: { parse: [] } } });
    expect(JSON.stringify(edits[0]?.payload)).toContain(`<@${ACTOR}>`);
  });
});

describe('setup rules', () => {
  const guild = fakeGuild();
  const ch = (id: string) => guild.channels.cache.get(id) as never;
  const r = (id: string) => guild.roles.cache.get(id) as never;

  it('accepts a channel the bot can post in and usable roles', () => {
    expect(setupProblem(TENANT, ch('300000000000000001'), r('600000000000000001'), r('600000000000000001'))).toBeNull();
    expect(setupProblem(TENANT, ch('300000000000000001'), null, null)).toBeNull();
  });

  it('refuses a channel it can’t post in, a role above it, and @everyone or bot roles as the mod role', () => {
    expect(setupProblem(TENANT, ch('300000000000000002'), null, null)).toBe('setup_bad_channel');
    expect(setupProblem(TENANT, null, null, null)).toBe('setup_bad_channel');
    expect(setupProblem(TENANT, ch('300000000000000001'), null, r('600000000000000003'))).toBe('setup_bad_quarantine_role');
    expect(setupProblem(TENANT, ch('300000000000000001'), r(TENANT), null)).toBe('setup_bad_mod_role');
    expect(setupProblem(TENANT, ch('300000000000000001'), r('600000000000000002'), null)).toBe('setup_bad_mod_role');
  });

  it('saves, refreshes the cache and audits where the change came from', async () => {
    const t = createFakeContext();
    await saveSetup(t.ctx, {
      guildId: TENANT,
      actorId: ACTOR,
      alertChannelId: '300000000000000001',
      modRoleId: null,
      quarantineRoleId: '600000000000000001',
      via: 'dashboard',
    });
    expect(t.stores.guilds.configure).toHaveBeenCalledWith(TENANT, { alertChannelId: '300000000000000001', quarantineRoleId: '600000000000000001' });
    expect(t.guildCache.invalidate).toHaveBeenCalledWith(TENANT);
    expect(t.fake.audit.at(-1)).toMatchObject({ actor: ACTOR, action: 'settings.setup', details: { via: 'dashboard' } });
  });
});

describe('sendTestSignal', () => {
  it('says where the test came from', async () => {
    const t = createFakeContext();
    const result = await sendTestSignal(t.ctx, { guildId: TENANT, actorId: ACTOR, via: 'dashboard' });
    expect(result.status).toBe('detected');
    expect(result.status === 'detected' && result.verdict.reasons[0]).toMatch(/dashboard/);
  });
});

describe('buildSnapshot', () => {
  it('lists text channels with whether alerts can go there, and roles with what they can be used for', () => {
    const snapshot = buildSnapshot(fakeGuild(), new Date('2026-09-30T00:00:00Z'));
    expect(snapshot.channels).toEqual([
      { id: '300000000000000001', name: 'chan-01', canPostAlerts: true },
      { id: '300000000000000002', name: 'chan-02', canPostAlerts: false },
    ]);
    // @everyone is left out; highest role first.
    expect(snapshot.roles).toEqual([
      { id: '600000000000000003', name: 'role-03', canBeModRole: true, canBeQuarantineRole: false },
      { id: '600000000000000002', name: 'role-02', canBeModRole: false, canBeQuarantineRole: false },
      { id: '600000000000000001', name: 'role-01', canBeModRole: true, canBeQuarantineRole: true },
    ]);
    expect(snapshot.missingPermissions).toEqual(['EmbedLinks', 'ManageMessages', 'ManageRoles', 'ModerateMembers']);
    expect(snapshot.updatedAt).toBe('2026-09-30T00:00:00.000Z');
  });
});

describe('SnapshotPublisher', () => {
  it('publishes with an expiry, and batches bursts of changes into one publish', async () => {
    vi.useFakeTimers();
    try {
      const set = vi.fn(() => Promise.resolve('OK' as const));
      const publisher = new SnapshotPublisher({ set }, silentLogger(), 1000);
      const guild = fakeGuild();
      for (let i = 0; i < 20; i++) publisher.schedule(guild);
      expect(set).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1000);
      expect(set).toHaveBeenCalledOnce();
      expect(set).toHaveBeenCalledWith(`equinox:guild:${TENANT}:snapshot`, expect.any(String), 'EX', 900);
    } finally {
      vi.useRealTimers();
    }
  });

  it('logs instead of throwing when Redis is down', async () => {
    const logger = silentLogger();
    const publisher = new SnapshotPublisher({ set: () => Promise.reject(new Error('down')) }, logger);
    await publisher.publish(fakeGuild());
    expect(logger.warn).toHaveBeenCalledOnce();
  });
});

describe('handleDashboardAction', () => {
  function setup() {
    const t = createFakeContext();
    const discord = fakeAlertClient();
    discord.raw.guilds.cache.set(TENANT, fakeGuild());
    const ctx = { ...t.ctx, client: discord.client };
    const run = (action: DashboardAction, key = KEY, now = Date.now()) => handleDashboardAction(signAction(key, action, now), ctx, KEY, now);
    return { t, ctx, run, edits: discord.edits };
  }

  it('refuses requests that aren’t signed with the shared key, or are too old', async () => {
    const { run, t } = setup();
    const test: DashboardAction = { type: 'test', guildId: TENANT, actorId: ACTOR };
    expect(await run(test, 'cd'.repeat(32))).toEqual({ code: 'rejected' });
    expect(await handleDashboardAction(signAction(KEY, test, Date.now() - 10 * 60_000), setup().ctx, KEY)).toEqual({ code: 'rejected' });
    expect(await handleDashboardAction({ action: test }, setup().ctx, KEY)).toEqual({ code: 'rejected' });
    expect(t.fake.detections.size).toBe(0);
    expect(t.logger.warn).toHaveBeenCalled();
  });

  it('answers guild_unavailable for servers this shard doesn’t serve', async () => {
    const { run } = setup();
    expect(await run({ type: 'test', guildId: '100000000000000555', actorId: ACTOR })).toEqual({ code: 'guild_unavailable' });
  });

  it('reviews a detection, audits it as the user from the dashboard, and resolves its Discord alerts', async () => {
    const { run, t, edits } = setup();
    const result = await processSignal(makeSignal({ guildId: TENANT }), t.ctx.deps);
    if (result.status !== 'detected') throw new Error('expected detection');
    t.fake.detections.get(result.detection.id)!.actionsTaken = [{ action: 'alert', ok: true, ref: { channelId: 'c', messageId: 'm1' } }];

    expect(await run({ type: 'review', guildId: TENANT, actorId: ACTOR, detectionId: result.detection.id, decision: 'confirm' })).toEqual({
      code: 'reviewed',
    });
    expect(t.fake.audit.at(-1)).toMatchObject({ actor: ACTOR, action: 'review.confirm', details: { via: 'dashboard' } });
    expect(edits.map((e) => e.messageId)).toEqual(['m1']);
    expect(JSON.stringify(edits[0]?.payload)).toContain('Resolved from the dashboard');

    await run({ type: 'review', guildId: TENANT, actorId: ACTOR, detectionId: result.detection.id, decision: 'restore' });
    expect(await run({ type: 'review', guildId: TENANT, actorId: ACTOR, detectionId: result.detection.id, decision: 'restore' })).toEqual({
      code: 'already_resolved',
    });
    expect(
      await run({ type: 'review', guildId: TENANT, actorId: ACTOR, detectionId: '0b7f5c8e-1d2a-4c3b-9e8f-7a6b5c4d3e2f', decision: 'restore' }),
    ).toEqual({ code: 'not_found' });
  });

  it('applies setup only after checking it the same way /equinox setup does', async () => {
    const { run, t } = setup();
    const base = { type: 'setup' as const, guildId: TENANT, actorId: ACTOR, modRoleId: null, quarantineRoleId: null };
    expect(await run({ ...base, alertChannelId: '300000000000000002' })).toEqual({ code: 'setup_bad_channel' });
    expect(await run({ ...base, alertChannelId: '399999999999999999' })).toEqual({ code: 'setup_bad_channel' });
    expect(await run({ ...base, alertChannelId: '300000000000000001', modRoleId: '699999999999999999' })).toEqual({ code: 'setup_bad_mod_role' });
    expect(await run({ ...base, alertChannelId: '300000000000000001', quarantineRoleId: '699999999999999999' })).toEqual({
      code: 'setup_bad_quarantine_role',
    });
    expect(await run({ ...base, alertChannelId: '300000000000000001', quarantineRoleId: '600000000000000003' })).toEqual({
      code: 'setup_bad_quarantine_role',
    });
    expect(t.stores.guilds.configure).not.toHaveBeenCalled();

    expect(await run({ ...base, alertChannelId: '300000000000000001', modRoleId: '600000000000000001' })).toEqual({ code: 'setup_saved' });
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'settings.setup', details: { via: 'dashboard', modRoleIds: ['600000000000000001'] } });
  });

  it('sends a test alert', async () => {
    const { run, t } = setup();
    expect(await run({ type: 'test', guildId: TENANT, actorId: ACTOR })).toEqual({ code: 'test_sent' });
    expect(t.fake.executed.map((e) => e.action)).toEqual(['alert']);
  });
});
