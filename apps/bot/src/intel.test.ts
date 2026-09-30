import { RedisContainer, type StartedRedisContainer } from '@testcontainers/redis';
import { Redis } from 'ioredis';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  intelSummaryKey,
  intelWaitersKey,
  LOOKUPS_PER_GUILD_PER_MINUTE,
  MAX_WAITERS,
  RateLimiter,
  URLHAUS_URLS_KEY,
  type IntelResolved,
} from '@equinox/core';
import { createFakeDeps, makeGuild, makeSignal } from '@equinox/core/testing';
import { handleResolved, IntelCache, IntelRequests, type LookupQueue } from './intel.js';
import { silentLogger, TENANT, OTHER_TENANT } from './test-helpers.js';

let container: StartedRedisContainer;
let redis: Redis;

beforeAll(async () => {
  container = await new RedisContainer('redis:7-alpine').start();
  redis = new Redis(container.getConnectionUrl());
}, 120_000);

afterAll(async () => {
  redis?.disconnect();
  await container?.stop();
});

beforeEach(async () => {
  await redis.flushall();
});

const waiter = (guildId = TENANT, messageId = '400000000000000001') => ({
  guildId,
  userId: '200000000000000001',
  channelId: '300000000000000001',
  messageId,
  heuristicScore: 0.1,
  reasons: [],
});

describe('IntelCache', () => {
  it('reads the cached summary and the URLhaus set, and nothing else', async () => {
    const cache = new IntelCache(redis);
    const url = 'https://cached.test/';
    expect(await cache.forUrl(url)).toBeNull();

    await redis.set(intelSummaryKey(url), JSON.stringify({ level: 'suspicious', score: 0.6, sources: ['rdap'], reasons: ['New'] }));
    expect(await cache.forUrl(url)).toEqual({ level: 'suspicious', score: 0.6, sources: ['rdap'], reasons: ['New'] });

    await redis.sadd(URLHAUS_URLS_KEY, url);
    expect(await cache.summaryFor(makeSignal({ subject: url }))).toMatchObject({ level: 'malicious', sources: ['urlhaus'] });
    expect(await cache.summaryFor(makeSignal({ subject: url, kind: 'file' }))).toBeNull();
  });

  it('ignores junk in the cache', async () => {
    await redis.set(intelSummaryKey('https://junk.test/'), JSON.stringify({ level: 'evil', score: 7 }));
    expect(await new IntelCache(redis).forUrl('https://junk.test/')).toBeNull();
  });
});

describe('IntelRequests', () => {
  it('queues one job per URL and keeps a bounded, expiring list of waiting messages', async () => {
    const jobs: { data: unknown; jobId: string }[] = [];
    const queue: LookupQueue = {
      add: (_name, data, opts) => {
        jobs.push({ data, jobId: opts.jobId });
        return Promise.resolve();
      },
    };
    const requests = new IntelRequests(redis, queue, new RateLimiter(10_000, 60_000));
    const url = 'https://spammed.test/';
    for (let i = 0; i < MAX_WAITERS + 20; i++) await requests.request(url, waiter(TENANT, String(400000000000000000n + BigInt(i))));

    expect(new Set(jobs.map((j) => j.jobId)).size).toBe(1);
    expect(jobs[0]?.data).toEqual({ subject: url, heuristicScore: 0.1 });
    expect(await redis.llen(intelWaitersKey(url))).toBe(MAX_WAITERS);
    expect(await redis.ttl(intelWaitersKey(url))).toBeGreaterThan(3000);
  });
});

describe('per-server lookup limit', () => {
  it('stops one server from flooding the worker, without affecting other servers', async () => {
    let now = 0;
    const jobs: string[] = [];
    const queue: LookupQueue = {
      add: (_name, data) => {
        jobs.push(data.subject);
        return Promise.resolve();
      },
    };
    const requests = new IntelRequests(redis, queue, new RateLimiter(LOOKUPS_PER_GUILD_PER_MINUTE, 60_000, () => now));
    const results: boolean[] = [];
    for (let i = 0; i < LOOKUPS_PER_GUILD_PER_MINUTE + 5; i++) results.push(await requests.request(`https://u${i}.test/`, waiter()));
    expect(results.filter(Boolean)).toHaveLength(LOOKUPS_PER_GUILD_PER_MINUTE);
    expect(jobs).toHaveLength(LOOKUPS_PER_GUILD_PER_MINUTE);
    // Refused requests leave nothing behind in Redis.
    expect(await redis.exists(intelWaitersKey(`https://u${LOOKUPS_PER_GUILD_PER_MINUTE}.test/`))).toBe(0);

    expect(await requests.request('https://other.test/', waiter(OTHER_TENANT))).toBe(true);
    now += 60_000;
    expect(await requests.request('https://later.test/', waiter())).toBe(true);
  });
});

describe('handleResolved', () => {
  const resolved = (waiters: ReturnType<typeof waiter>[]): string =>
    JSON.stringify({
      subject: 'https://late.test/',
      summary: { level: 'malicious', score: 0.95, sources: ['urlhaus'], reasons: ['Listed by URLhaus as a malware link'] },
      waiters,
    } satisfies IntelResolved);

  it('re-runs waiting messages in this shard’s servers only, and acts once', async () => {
    const fake = createFakeDeps([makeGuild({ id: TENANT, mode: 'protect' }), makeGuild({ id: OTHER_TENANT })]);
    fake.intel.set('https://late.test/', {
      level: 'malicious',
      score: 0.95,
      sources: ['urlhaus'],
      reasons: ['Listed by URLhaus as a malware link'],
    });
    const ctx = { deps: fake.deps, logger: silentLogger(), servesGuild: (id: string) => id === TENANT };

    await handleResolved(resolved([waiter(TENANT), waiter(OTHER_TENANT)]), ctx);
    expect([...fake.detections.values()].map((d) => d.guildId)).toEqual([TENANT]);
    expect(fake.executed.map((e) => e.action)).toEqual(['delete', 'alert']);

    // The same result delivered again doesn't act again.
    await handleResolved(resolved([waiter(TENANT)]), ctx);
    expect(fake.detections.size).toBe(1);
    expect(fake.executed).toHaveLength(2);
  });

  it('drops malformed messages', async () => {
    const fake = createFakeDeps([makeGuild({ id: TENANT })]);
    const ctx = { deps: fake.deps, logger: silentLogger(), servesGuild: () => true };
    await handleResolved('not json', ctx);
    await handleResolved(JSON.stringify({ subject: 'x', summary: {}, waiters: [] }), ctx);
    expect(ctx.logger.warn).toHaveBeenCalledTimes(2);
    expect(fake.detections.size).toBe(0);
  });
});
