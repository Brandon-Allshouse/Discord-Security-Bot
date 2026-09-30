import { readFile } from 'node:fs/promises';
import type { Redis } from 'ioredis';
import { describe, expect, it, vi } from 'vitest';
import { BRAND, findLinks, processSignal, slash } from '@equinox/core';
import { makeGuild, makeSignal } from '@equinox/core/testing';
import { commandDefinitions } from './commands.js';
import { handleInteraction } from './handlers/interactions.js';
import { scanMessage } from './handlers/messages.js';
import { seedBlocklist } from './indicators.js';
import { createFakeContext, fakeCommand, replyText, TENANT } from './test-helpers.js';

describe('branding', () => {
  it('names the slash command after the brand', () => {
    expect(commandDefinitions[0]?.name).toBe(BRAND.command);
    expect(commandDefinitions[0]?.description).toContain(BRAND.name);
  });

  it('uses a command name Discord accepts', () => {
    expect(BRAND.command).toMatch(/^[a-z0-9_-]{1,32}$/);
  });

  it('formats commands the way users type them', () => {
    expect(slash('setup')).toBe(`/${BRAND.command} setup`);
  });

  it('shows the brand in user-facing replies', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'check' }, { url: `https://${BRAND.testDomain}/` }, { manageGuild: true });
    t.fake.blocklist.add(BRAND.testDomain);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toContain(`${BRAND.name} blocklist`);
  });

  it('shows the brand in blocklist verdicts', async () => {
    const t = createFakeContext();
    const url = `https://${BRAND.testDomain}/x`;
    t.fake.blocklist.add(url);
    const result = await processSignal(makeSignal({ subject: url, heuristicScore: 0 }), t.ctx.deps);
    expect(result.status === 'detected' && result.verdict.reasons[0]).toBe(`Known threat on the ${BRAND.name} network`);
  });
});

describe('safe test link', () => {
  const testUrl = `https://${BRAND.testDomain}/phish`;

  it('is in the real seed blocklist file', async () => {
    const text = await readFile(new URL('../data/seed-blocklist.txt', import.meta.url), 'utf8');
    const sadd = vi.fn((_key: string, ...members: string[]) => Promise.resolve(members.length));
    await seedBlocklist({ sadd } as unknown as Redis, text);
    expect(sadd.mock.calls[0]?.slice(1)).toContain(BRAND.testDomain);
  });

  it('uses a reserved TLD that can never resolve to a real site', () => {
    expect(BRAND.testDomain.endsWith('.invalid')).toBe(true);
  });

  it('is picked up from a message and scores clean on its own, so only the blocklist flags it', () => {
    const [finding] = findLinks(`check ${testUrl}`);
    expect(finding?.normalized.host).toBe(BRAND.testDomain);
    expect(finding?.score).toBe(0);
  });

  it('triggers a detection when posted in a server', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT }));
    t.fake.blocklist.add(testUrl);
    await scanMessage(
      {
        inGuild: () => true,
        content: testUrl,
        guildId: TENANT,
        channelId: '300000000000000001',
        id: '400000000000000001',
        author: { id: '200000000000000001' },
      } as never,
      t.ctx,
    );
    const [detection] = [...t.fake.detections.values()];
    expect(detection?.verdict).toMatchObject({ level: 'malicious', sources: ['blocklist'] });
  });
});
