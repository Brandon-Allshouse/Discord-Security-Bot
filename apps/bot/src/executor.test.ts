import type { Client } from 'discord.js';
import { describe, expect, it, vi } from 'vitest';
import type { Detection } from '@equinox/core';
import { makeGuild } from '@equinox/core/testing';
import { DiscordActionExecutor } from './executor.js';

function fakeDiscord({ sendable = true } = {}) {
  const member = { roles: { add: vi.fn(), remove: vi.fn() }, timeout: vi.fn() };
  const channel = {
    isSendable: () => sendable,
    isTextBased: () => true,
    send: vi.fn(),
    messages: { delete: vi.fn() },
  };
  const guild = {
    channels: { fetch: vi.fn(() => Promise.resolve(channel)) },
    members: { fetch: vi.fn(() => Promise.resolve(member)) },
    bans: { remove: vi.fn() },
  };
  const client = { guilds: { fetch: vi.fn(() => Promise.resolve(guild)) } } as unknown as Client;
  return { client, guild, channel, member };
}

const detection: Detection = {
  id: '0b7f5c8e-1d2a-4c3b-9e8f-7a6b5c4d3e2f',
  guildId: '100000000000000001',
  userId: '200000000000000001',
  channelId: '300000000000000001',
  messageId: '400000000000000001',
  signalKind: 'url',
  subject: 'https://evil.example/',
  verdict: { level: 'malicious', score: 0.9, sources: ['heuristic'], reasons: [] },
  actionsTaken: [],
  status: 'open',
  createdAt: new Date(),
};

describe('DiscordActionExecutor.execute', () => {
  it('posts alerts that cannot ping anyone', async () => {
    const d = fakeDiscord();
    const outcome = await new DiscordActionExecutor(d.client).execute('alert', {
      guild: makeGuild(),
      detection,
      previous: [],
    });
    expect(outcome).toEqual({ action: 'alert', ok: true });
    expect(d.channel.send).toHaveBeenCalledWith(expect.objectContaining({ allowedMentions: { parse: [] } }));
  });

  it('reports a missing or unusable alert channel', async () => {
    const d = fakeDiscord();
    const executor = new DiscordActionExecutor(d.client);
    const missing = await executor.execute('alert', { guild: makeGuild({ alertChannelId: null }), detection, previous: [] });
    expect(missing.ok).toBe(false);
    expect(missing.detail).toMatch(/setup/);
    const blocked = fakeDiscord({ sendable: false });
    expect(await new DiscordActionExecutor(blocked.client).execute('alert', { guild: makeGuild(), detection, previous: [] })).toMatchObject({
      ok: false,
    });
  });

  it('deletes the offending message', async () => {
    const d = fakeDiscord();
    const outcome = await new DiscordActionExecutor(d.client).execute('delete', { guild: makeGuild(), detection, previous: [] });
    expect(outcome.ok).toBe(true);
    expect(d.channel.messages.delete).toHaveBeenCalledWith(detection.messageId);
  });

  it('does not delete without a message', async () => {
    const d = fakeDiscord();
    const outcome = await new DiscordActionExecutor(d.client).execute('delete', {
      guild: makeGuild(),
      detection: { ...detection, messageId: null },
      previous: [],
    });
    expect(outcome).toMatchObject({ ok: false, detail: 'No message to delete' });
  });

  it('quarantines with a traceable reason', async () => {
    const d = fakeDiscord();
    const guild = makeGuild();
    await new DiscordActionExecutor(d.client).execute('quarantine', { guild, detection, previous: [] });
    expect(d.member.roles.add).toHaveBeenCalledWith(guild.quarantineRoleId, `Equinox detection ${detection.id}`);
  });

  it('refuses to quarantine without a quarantine role', async () => {
    const d = fakeDiscord();
    const outcome = await new DiscordActionExecutor(d.client).execute('quarantine', {
      guild: makeGuild({ quarantineRoleId: null }),
      detection,
      previous: [],
    });
    expect(outcome.ok).toBe(false);
    expect(d.member.roles.add).not.toHaveBeenCalled();
  });

  it('times out for a bounded period', async () => {
    const d = fakeDiscord();
    await new DiscordActionExecutor(d.client).execute('timeout', { guild: makeGuild(), detection, previous: [] });
    expect(d.member.timeout).toHaveBeenCalledWith(10 * 60 * 1000, expect.any(String));
  });

  it.each(['kick', 'ban'] as const)('never performs %s automatically', async (action) => {
    const d = fakeDiscord();
    const outcome = await new DiscordActionExecutor(d.client).execute(action, { guild: makeGuild(), detection, previous: [] });
    expect(outcome).toMatchObject({ ok: false, detail: 'Requires moderator confirmation' });
    expect(d.guild.members.fetch).not.toHaveBeenCalled();
  });
});

describe('DiscordActionExecutor.revert', () => {
  it('removes the quarantine role', async () => {
    const d = fakeDiscord();
    const guild = makeGuild();
    expect((await new DiscordActionExecutor(d.client).revert('quarantine', guild, detection)).ok).toBe(true);
    expect(d.member.roles.remove).toHaveBeenCalledWith(guild.quarantineRoleId, expect.stringMatching(/reverted/));
  });

  it('clears a timeout', async () => {
    const d = fakeDiscord();
    await new DiscordActionExecutor(d.client).revert('timeout', makeGuild(), detection);
    expect(d.member.timeout).toHaveBeenCalledWith(null, expect.any(String));
  });

  it('lifts a ban', async () => {
    const d = fakeDiscord();
    await new DiscordActionExecutor(d.client).revert('ban', makeGuild(), detection);
    expect(d.guild.bans.remove).toHaveBeenCalledWith(detection.userId, expect.any(String));
  });

  it('reports deletions as not reversible', async () => {
    const d = fakeDiscord();
    expect(await new DiscordActionExecutor(d.client).revert('delete', makeGuild(), detection)).toMatchObject({
      ok: false,
      detail: 'Not reversible',
    });
  });
});
