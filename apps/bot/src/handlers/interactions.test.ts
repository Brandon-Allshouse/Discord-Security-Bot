import { describe, expect, it } from 'vitest';
import { processSignal } from '@equinox/core';
import { makeGuild, makeSignal } from '@equinox/core/testing';
import { reviewCustomId } from '../alerts.js';
import { createFakeContext, fakeButton, fakeCommand, MOD_ROLE, OTHER_TENANT, replyText, TENANT } from '../test-helpers.js';
import { handleInteraction } from './interactions.js';

const ADMIN = { manageGuild: true };
const MOD = { roleIds: [MOD_ROLE] };
const MEMBER = { roleIds: ['600000000000000099'] };

async function detect(ctx: ReturnType<typeof createFakeContext>, overrides = {}) {
  const result = await processSignal(makeSignal({ guildId: TENANT, ...overrides }), ctx.ctx.deps);
  if (result.status !== 'detected') throw new Error('expected detection');
  return result.detection;
}

describe('slash command authorization', () => {
  it('denies admin-only commands to mods and audits the attempt', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'mode' }, { mode: 'strict' }, MOD);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/don’t have permission/);
    expect(t.stores.guilds.setMode).not.toHaveBeenCalled();
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'authz.denied', details: { command: 'mode' } });
  });

  it('denies mod commands to ordinary members', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'test' }, {}, MEMBER);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/don’t have permission/);
    expect(t.fake.executed).toHaveLength(0);
  });

  it('lets admins change the mode, audits it and refreshes the cache', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'mode' }, { mode: 'protect' }, ADMIN);
    await handleInteraction(interaction, t.ctx);
    expect(t.stores.guilds.setMode).toHaveBeenCalledWith(TENANT, 'protect');
    expect(t.guildCache.invalidate).toHaveBeenCalledWith(TENANT);
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'settings.mode', details: { from: 'alert_only', to: 'protect' } });
    expect(replyText(replies)).toMatch(/protect/);
  });

  it('rejects a mode value that bypassed Discord’s choices', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'mode' }, { mode: 'yolo' }, ADMIN);
    await handleInteraction(interaction, t.ctx);
    expect(t.stores.guilds.setMode).not.toHaveBeenCalled();
    expect(replyText(replies)).toMatch(/Unknown mode/);
  });

  it('registers an unknown tenant on first use instead of failing', async () => {
    const t = createFakeContext(makeGuild({ id: OTHER_TENANT }));
    const { interaction } = fakeCommand({ sub: 'status' }, {}, ADMIN);
    await handleInteraction(interaction, t.ctx);
    expect(t.stores.guilds.register).toHaveBeenCalledWith({ id: TENANT, name: 'Test server' });
  });
});

describe('slash commands', () => {
  it('/equinox test sends a signal through the whole pipeline', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'test' }, {}, MOD);
    await handleInteraction(interaction, t.ctx);
    expect(t.fake.executed.map((e) => e.action)).toEqual(['alert']);
    expect(replyText(replies)).toMatch(/Test signal processed/);
  });

  it('/equinox check reports lookalikes, defanged', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'check' }, { url: 'https://dlscord.com/gift' }, MOD);
    await handleInteraction(interaction, t.ctx);
    const text = replyText(replies);
    expect(text).toMatch(/Malicious/);
    expect(text).toContain('hxxps://dlscord[.]com');
    expect(text).not.toContain('https://dlscord.com');
  });

  it('/equinox check honors the tenant allowlist', async () => {
    const t = createFakeContext();
    t.allowlist.add(`${TENANT}:dlscord.com`);
    const { interaction, replies } = fakeCommand({ sub: 'check' }, { url: 'dlscord.com' }, MOD);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/allowlisted here/);
  });

  it('/equinox allow add validates input, stores and audits', async () => {
    const t = createFakeContext();
    const bad = fakeCommand({ sub: 'add', group: 'allow' }, { domain: 'https://x.com/path' }, ADMIN);
    await handleInteraction(bad.interaction, t.ctx);
    expect(replyText(bad.replies)).toMatch(/Enter a domain/);
    expect(t.stores.allowlist.add).not.toHaveBeenCalled();

    const good = fakeCommand({ sub: 'add', group: 'allow' }, { domain: 'Example.com' }, ADMIN);
    await handleInteraction(good.interaction, t.ctx);
    expect(t.stores.allowlist.add).toHaveBeenCalledWith(expect.objectContaining({ guildId: TENANT, value: 'example.com' }));
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'allowlist.add', target: 'example.com' });
  });

  it('/equinox allow remove reports missing entries', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'remove', group: 'allow' }, { domain: 'nope.com' }, ADMIN);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/isn’t on the allowlist/);
  });

  it('/equinox setup refuses a channel the sensor cannot post in', async () => {
    const t = createFakeContext();
    const channel = { isTextBased: () => true, guild: { members: { me: null } }, toString: () => '<#1>' };
    const { interaction, replies } = fakeCommand({ sub: 'setup' }, { alert_channel: channel }, ADMIN);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/can’t post/);
    expect(t.stores.guilds.configure).not.toHaveBeenCalled();
  });
});

describe('alert buttons', () => {
  it('ignores tampered button IDs', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeButton('eq:ban:not-a-uuid', ADMIN);
    await handleInteraction(interaction, t.ctx);
    expect(replies).toHaveLength(0);
  });

  it('denies non-moderators and audits the attempt', async () => {
    const t = createFakeContext();
    const detection = await detect(t);
    const { interaction, replies } = fakeButton(reviewCustomId('restore', detection.id), MEMBER);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/Only moderators/);
    expect(t.fake.detections.get(detection.id)?.status).toBe('open');
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'authz.denied' });
  });

  it('restore undoes reversible actions and resolves the alert', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT, mode: 'strict', modRoleIds: [MOD_ROLE] }));
    const detection = await detect(t, { kind: 'member_join', heuristicScore: 0.95 });
    const { interaction, raw, replies } = fakeButton(reviewCustomId('restore', detection.id), MOD);
    await handleInteraction(interaction, t.ctx);
    expect(raw.deferUpdate).toHaveBeenCalled();
    expect(t.fake.reverted.map((r) => r.action)).toEqual(['quarantine']);
    expect(t.fake.detections.get(detection.id)?.status).toBe('restored');
    expect(replyText(replies)).toMatch(/"components":\[\]/);
    expect(replyText(replies)).toMatch(/Restored by/);
  });

  it('restore after a delete says the message can’t be brought back', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT, mode: 'protect', modRoleIds: [MOD_ROLE] }));
    const detection = await detect(t, { heuristicScore: 0.95 });
    expect(detection.actionsTaken.map((a) => a.action)).toContain('delete');
    const { interaction, replies } = fakeButton(reviewCustomId('restore', detection.id), MOD);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/can’t be brought back/);
  });

  it('confirm after a delete has no restore warning', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT, mode: 'protect', modRoleIds: [MOD_ROLE] }));
    const detection = await detect(t, { heuristicScore: 0.95 });
    const { interaction, replies } = fakeButton(reviewCustomId('confirm', detection.id), MOD);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).not.toMatch(/can’t be brought back/);
  });

  it('false positive on a link allowlists the exact host in this tenant only', async () => {
    const t = createFakeContext();
    const detection = await detect(t, { subject: 'https://cdn.partner.example/x' });
    const { interaction } = fakeButton(reviewCustomId('false_positive', detection.id), MOD);
    await handleInteraction(interaction, t.ctx);
    expect(t.allowlist.has(`${TENANT}:cdn.partner.example`)).toBe(true);
    expect(t.allowlist.has(`${TENANT}:partner.example`)).toBe(false);
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'allowlist.add', details: { via: 'false_positive' } });
  });

  it('cannot act on a detection that belongs to another tenant', async () => {
    const t = createFakeContext();
    const detection = await detect(t);
    const { interaction, replies } = fakeButton(reviewCustomId('restore', detection.id), {
      ...ADMIN,
      guildId: OTHER_TENANT,
    });
    t.fake.guildMap.set(OTHER_TENANT, makeGuild({ id: OTHER_TENANT }));
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/no longer exists/);
    expect(t.fake.detections.get(detection.id)?.status).toBe('open');
  });

  it('reports an already-resolved alert', async () => {
    const t = createFakeContext();
    const detection = await detect(t);
    for (let i = 0; i < 2; i++) {
      const { interaction, replies } = fakeButton(reviewCustomId('false_positive', detection.id), MOD);
      await handleInteraction(interaction, t.ctx);
      if (i === 1) expect(replyText(replies)).toMatch(/already resolved/);
    }
  });
});

describe('abuse and failure handling', () => {
  it('rate-limits a user after 10 interactions a minute', async () => {
    const t = createFakeContext();
    let last: unknown[] = [];
    for (let i = 0; i < 11; i++) {
      const { interaction, replies } = fakeCommand({ sub: 'status' }, {}, MOD);
      await handleInteraction(interaction, t.ctx);
      last = replies;
    }
    expect(replyText(last)).toMatch(/too fast/);
  });

  it('shows only a reference ID when something breaks, and logs the details', async () => {
    const t = createFakeContext();
    t.ctx.guildCache.get = () => Promise.reject(new Error('connect ECONNREFUSED password=hunter2'));
    const { interaction, replies } = fakeCommand({ sub: 'status' }, {}, MOD);
    await handleInteraction(interaction, t.ctx);
    const text = replyText(replies);
    expect(text).toMatch(/Something went wrong \(ref/);
    expect(text).not.toContain('hunter2');
    expect(t.logger.error).toHaveBeenCalled();
  });
});
