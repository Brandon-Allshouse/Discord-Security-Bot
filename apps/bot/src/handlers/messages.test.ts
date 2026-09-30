import type { Message } from 'discord.js';
import { describe, expect, it } from 'vitest';
import { makeGuild } from '@equinox/core/testing';
import { createFakeContext, OTHER_TENANT, TENANT } from '../test-helpers.js';
import { scanMessage, SeenEdits } from './messages.js';

function fakeMessage(content: string, overrides: Record<string, unknown> = {}) {
  return {
    inGuild: () => true,
    content,
    guildId: TENANT,
    channelId: '300000000000000001',
    id: '400000000000000001',
    author: { id: '200000000000000001' },
    ...overrides,
  } as unknown as Message;
}

describe('SeenEdits', () => {
  it('ignores updates that aren’t edits, like link previews loading', () => {
    expect(new SeenEdits().isNew('1', null)).toBe(false);
  });

  it('passes each edit once, even when the same edit is delivered again', () => {
    const seen = new SeenEdits();
    expect(seen.isNew('1', 1000)).toBe(true);
    expect(seen.isNew('1', 1000)).toBe(false);
    expect(seen.isNew('1', 2000)).toBe(true);
    expect(seen.isNew('2', 1000)).toBe(true);
  });

  it('stays bounded by forgetting the oldest message', () => {
    const seen = new SeenEdits(2);
    seen.isNew('1', 1000);
    seen.isNew('2', 1000);
    seen.isNew('3', 1000);
    expect(seen.isNew('3', 1000)).toBe(false);
    expect(seen.isNew('1', 1000)).toBe(true);
  });
});

describe('scanMessage (link sensor)', () => {
  it('turns a scam link into a detection with message context', async () => {
    const t = createFakeContext();
    await scanMessage(fakeMessage('free nitro https://dlscord.gift/abc'), t.ctx);
    const [detection] = [...t.fake.detections.values()];
    expect(detection).toMatchObject({
      guildId: TENANT,
      userId: '200000000000000001',
      messageId: '400000000000000001',
      subject: 'https://dlscord.gift/abc',
      signalKind: 'url',
    });
    expect(t.fake.executed.map((e) => e.action)).toEqual(['alert']);
  });

  it('does nothing for legitimate links', async () => {
    const t = createFakeContext();
    await scanMessage(fakeMessage('see https://github.com/discordjs/discord.js'), t.ctx);
    expect(t.fake.detections.size).toBe(0);
  });

  it('creates one detection per message even with several bad links', async () => {
    const t = createFakeContext();
    await scanMessage(fakeMessage('https://dlscord.gift/a https://stearncommunity.com/b'), t.ctx);
    expect(t.fake.detections.size).toBe(1);
  });

  it('flags a low-score link that is on the blocklist', async () => {
    const t = createFakeContext();
    t.fake.blocklist.add('https://innocent-looking.example/');
    await scanMessage(fakeMessage('https://innocent-looking.example/'), t.ctx);
    expect([...t.fake.detections.values()][0]?.verdict.sources).toEqual(['blocklist']);
  });

  it('ignores DMs, empty messages and its own messages', async () => {
    const t = createFakeContext();
    await scanMessage(fakeMessage('https://dlscord.gift/a', { inGuild: () => false }), t.ctx);
    await scanMessage(fakeMessage(''), t.ctx);
    await scanMessage(fakeMessage('https://dlscord.gift/a', { author: { id: '999999999999999999' } }), t.ctx);
    expect(t.fake.detections.size).toBe(0);
  });

  it('ignores servers that are not tenants', async () => {
    const t = createFakeContext(makeGuild({ id: OTHER_TENANT }));
    await scanMessage(fakeMessage('https://dlscord.gift/a'), t.ctx);
    expect(t.fake.detections.size).toBe(0);
  });

  it('scans messages from other bots too (compromised bots spread scams)', async () => {
    const t = createFakeContext();
    await scanMessage(fakeMessage('https://dlscord.gift/a', { author: { id: '777777777777777777', bot: true } }), t.ctx);
    expect(t.fake.detections.size).toBe(1);
  });
});
