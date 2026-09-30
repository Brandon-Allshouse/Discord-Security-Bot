import { RedisContainer, type StartedRedisContainer } from '@testcontainers/redis';
import { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { makeSignal } from '@equinox/core/testing';
import type { AllowlistStore } from '@equinox/db';
import { buildAlertMessage, parseReviewCustomId, reviewCustomId } from './alerts.js';
import { commandDefinitions } from './commands.js';
import { IndicatorService, seedBlocklist } from './indicators.js';

describe('review button IDs', () => {
  const id = '0b7f5c8e-1d2a-4c3b-9e8f-7a6b5c4d3e2f';

  it('round-trips', () => {
    expect(parseReviewCustomId(reviewCustomId('false_positive', id))).toEqual({ decision: 'false_positive', detectionId: id });
  });

  it.each([
    'eq:ban:' + id,
    'eq:restore:not-a-uuid',
    'eq:restore:' + id + ':extra',
    'xx:restore:' + id,
    'eq:restore:' + id.toUpperCase(),
    '',
  ])('rejects tampered ID %s', (customId) => {
    expect(parseReviewCustomId(customId)).toBeNull();
  });
});

describe('alert message', () => {
  const detection = {
    id: '0b7f5c8e-1d2a-4c3b-9e8f-7a6b5c4d3e2f',
    guildId: '100000000000000001',
    userId: '200000000000000001',
    channelId: '300000000000000001',
    messageId: '400000000000000001',
    signalKind: 'url' as const,
    subject: 'https://evil.example/`@everyone`',
    verdict: { level: 'malicious' as const, score: 0.9, sources: ['heuristic'], reasons: ['**bold** @everyone [x](https://y.z)'] },
    actionsTaken: [],
    status: 'open' as const,
    createdAt: new Date(),
  };
  const message = buildAlertMessage(detection, 'protect', [{ action: 'delete', ok: true }]);
  const json = JSON.stringify(message.embeds);

  it('never pings anyone', () => {
    expect(message.allowedMentions).toEqual({ parse: [] });
  });

  it('defangs the link and neutralizes markdown and backticks', () => {
    expect(json).toContain('hxxps://evil[.]example');
    expect(json).not.toContain('https://evil.example');
    expect(json).toContain('\\\\*\\\\*bold');
  });

  it('has the three review buttons', () => {
    const ids = JSON.stringify(message.components);
    for (const decision of ['restore', 'false_positive', 'confirm']) expect(ids).toContain(`eq:${decision}:`);
  });
});

describe('slash commands', () => {
  it('are hidden from non-admins by default and guild-only', () => {
    const [command] = commandDefinitions;
    expect(command?.default_member_permissions).toBe('32'); // Manage Server
    expect(command?.contexts).toEqual([0]);
  });
});

describe('Redis blocklist', () => {
  let container: StartedRedisContainer;
  let redis: Redis;
  let service: IndicatorService;

  beforeAll(async () => {
    container = await new RedisContainer('redis:7-alpine').start();
    redis = new Redis(container.getConnectionUrl());
    const noAllowlist = { hasAny: () => Promise.resolve(false) } as unknown as AllowlistStore;
    service = new IndicatorService(redis, noAllowlist);
    await seedBlocklist(redis, '# comment\nevil.example\n\nnot a domain\nBAD.example # trailing comment\n');
  }, 120_000);

  afterAll(async () => {
    redis?.disconnect();
    await container?.stop();
  });

  it('loads the seed file, skipping comments and junk', async () => {
    expect((await redis.smembers('equinox:blocklist:domain')).sort()).toEqual(['bad.example', 'evil.example']);
  });

  it('matches subdomains of blocklisted domains', async () => {
    expect(await service.isBlocklisted(makeSignal({ subject: 'https://login.evil.example/x' }))).toBe(true);
    expect(await service.isBlocklisted(makeSignal({ subject: 'https://evil.example.com/x' }))).toBe(false);
  });

  it('adds under 5 ms at p95', async () => {
    const signal = makeSignal({ subject: 'https://a.b.c.example.org/path' });
    const durations: number[] = [];
    for (let i = 0; i < 500; i++) {
      const start = performance.now();
      await service.isBlocklisted(signal);
      durations.push(performance.now() - start);
    }
    durations.sort((a, b) => a - b);
    expect(durations[Math.floor(durations.length * 0.95)]).toBeLessThan(5);
  });
});
