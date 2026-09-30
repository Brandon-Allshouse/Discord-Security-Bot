import { RedisContainer, type StartedRedisContainer } from '@testcontainers/redis';
import { Queue, type Worker } from 'bullmq';
import { Redis } from 'ioredis';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  INTEL_LOOKUP_QUEUE,
  INTEL_RESOLVED_CHANNEL,
  INTEL_STATUS_KEY,
  INTEL_STATUS_TTL_SECONDS,
  intelStatusSchema,
  INTEL_VT_QUEUE,
  intelResolvedSchema,
  intelSummaryKey,
  intelWaitersKey,
  QUEUE_PREFIX,
  URLHAUS_URLS_KEY,
  type IntelResolved,
  type IntelWaiter,
} from '@equinox/core';
import { ApiBudget } from './budget.js';
import { resolveUrl } from './chain.js';
import {
  processLookup,
  processVirusTotal,
  VT_MAX_BACKLOG,
  VT_PRIORITY,
  type JobDeps,
  type VirusTotalJob,
  type VtQueue,
} from './jobs.js';
import type { FetchLike } from './net/http.js';
import { URLHAUS_FEED_URL, UrlhausFeed } from './providers/urlhaus.js';
import { VirusTotalAuthError } from './providers/virustotal.js';
import { recordUrlhausSync, URLHAUS_META_KEY, writeStatus } from './status.js';
import { FakeProvider, MemoryCache, silentLogger } from './test-helpers.js';
import { startIntelWorkers } from './workers.js';

let container: StartedRedisContainer;
let redis: Redis;
let subscriber: Redis;
let url: string;

beforeAll(async () => {
  container = await new RedisContainer('redis:7-alpine').start();
  url = container.getConnectionUrl();
  redis = new Redis(url);
  subscriber = new Redis(url);
}, 120_000);

afterAll(async () => {
  redis?.disconnect();
  subscriber?.disconnect();
  await container?.stop();
});

beforeEach(async () => {
  await redis.flushall();
});

const waiter = (guildId: string, messageId = '400000000000000001'): IntelWaiter => ({
  guildId,
  userId: '200000000000000001',
  channelId: '300000000000000001',
  messageId,
  heuristicScore: 0,
  reasons: [],
});

function setup() {
  const logger = silentLogger();
  const redirects = new FakeProvider('redirects', ['url']);
  const rdap = new FakeProvider('rdap', ['domain']);
  const vtProvider = new FakeProvider('virustotal', ['url']);
  const cache = new MemoryCache();
  const queued: { data: VirusTotalJob; opts: { jobId: string; priority: number } }[] = [];
  const queue: VtQueue = {
    add: (_name, data, opts) => {
      queued.push({ data, opts });
      return Promise.resolve();
    },
    count: () => Promise.resolve(queued.length),
  };
  const budget = new ApiBudget(redis, 'virustotal', { perDay: 500, perMinute: 4 });
  const deps: JobDeps = {
    redis,
    cache,
    logger,
    redirects,
    urlhaus: new UrlhausFeed(redis),
    rdap,
    vt: { provider: vtProvider, budget, queue },
  };
  return { deps, logger, redirects, rdap, vtProvider, cache, queued, budget };
}

async function listen(): Promise<IntelResolved[]> {
  const received: IntelResolved[] = [];
  await subscriber.subscribe(INTEL_RESOLVED_CHANNEL);
  subscriber.on('message', (_channel, message) => received.push(intelResolvedSchema.parse(JSON.parse(message))));
  return received;
}

afterEach(async () => {
  subscriber.removeAllListeners('message');
  await subscriber.unsubscribe();
});

const settle = () => new Promise((resolve) => setTimeout(resolve, 100));

describe('exit check: an unknown URL resolves through the chain', () => {
  it('follows a shortener, finds the target on URLhaus, caches the answer and tells the waiting shards', async () => {
    const { deps, redirects, vtProvider, queued } = setup();
    const short = 'https://bit.ly/abc123';
    const target = 'http://payload.test/free-nitro.exe';
    redirects.answers.set(short, { details: { finalUrl: target, hops: 1, stoppedBy: 'final' } });
    await redis.sadd(URLHAUS_URLS_KEY, target);
    await redis.rpush(intelWaitersKey(short), JSON.stringify(waiter('100000000000000001')));
    const received = await listen();

    const outcome = await processLookup({ subject: short, heuristicScore: 0 }, deps);
    await settle();

    expect(outcome).toEqual({ level: 'malicious', virustotal: 'not_needed' });
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ subject: short, summary: { level: 'malicious' }, waiters: [waiter('100000000000000001')] });
    expect(received[0]?.summary.sources).toContain('urlhaus');
    expect(JSON.parse((await redis.get(intelSummaryKey(short)))!)).toMatchObject({ level: 'malicious' });
    expect(await redis.ttl(intelSummaryKey(short))).toBeGreaterThan(29 * 24 * 3600);
    expect(await redis.exists(intelWaitersKey(short))).toBe(0);
    // Confident without VirusTotal, so no budget spent.
    expect(vtProvider.calls).toBe(0);
    expect(queued).toHaveLength(0);
  });

  it('checks domain age and hands still-unresolved links to VirusTotal, campaigns first', async () => {
    const { deps, rdap, vtProvider, queued } = setup();
    const link = 'https://fresh-giveaway.test/claim';
    rdap.answers.set('fresh-giveaway.test', { level: 'suspicious', weight: 0.4, reasons: ['Domain was registered 1 day ago'] });
    await redis.rpush(
      intelWaitersKey(link),
      JSON.stringify(waiter('100000000000000001')),
      JSON.stringify(waiter('100000000000000002')),
      'not json',
      JSON.stringify({ guildId: 'junk' }),
    );
    const received = await listen();

    expect(await processLookup({ subject: link, heuristicScore: 0.3 }, deps)).toEqual({ level: 'clean', virustotal: 'queued' });
    expect(queued[0]).toMatchObject({ data: { subject: link, finalUrl: link }, opts: { priority: VT_PRIORITY.multiGuild } });
    await settle();
    // The fast answer goes out right away; bad waiter entries are dropped; the waiters stay for VirusTotal.
    expect(received[0]?.waiters).toHaveLength(2);
    expect(await redis.llen(intelWaitersKey(link))).toBe(4);

    vtProvider.answers.set(link, { level: 'malicious', weight: 0.9, reasons: ['Flagged as malicious by 7 VirusTotal engines'] });
    expect(await processVirusTotal(queued[0]!.data, deps)).toBe('looked_up');
    await settle();
    expect(received[1]).toMatchObject({ summary: { level: 'malicious', sources: ['rdap', 'virustotal'] } });
    expect(await redis.exists(intelWaitersKey(link))).toBe(0);
    expect(await deps.vt!.budget.usedToday()).toBe(1);

    // A second job for the same URL uses the cached VirusTotal answer.
    expect(await processVirusTotal(queued[0]!.data, deps)).toBe('cached');
    expect(vtProvider.calls).toBe(1);
  });

  it('gives single-server links lower VirusTotal priority and skips links with no sign of trouble', async () => {
    const { deps, queued } = setup();
    await redis.rpush(intelWaitersKey('https://one.test/'), JSON.stringify(waiter('100000000000000001')));
    await processLookup({ subject: 'https://one.test/', heuristicScore: 0.1 }, deps);
    expect(queued[0]?.opts.priority).toBe(VT_PRIORITY.singleGuild);

    expect(await processLookup({ subject: 'https://plain.test/', heuristicScore: 0 }, deps)).toEqual({
      level: 'clean',
      virustotal: 'not_needed',
    });
    expect(await processLookup({ subject: 'http://192.168.0.1/', heuristicScore: 0.35 }, deps)).toMatchObject({
      virustotal: 'not_needed',
    });
  });

  it('drops old VirusTotal jobs and stops for the day when the budget is spent', async () => {
    const { deps, vtProvider } = setup();
    const job: VirusTotalJob = { subject: 'https://a.test/', finalUrl: 'https://a.test/', heuristicScore: 0.3, queuedAt: Date.now() };
    expect(await processVirusTotal({ ...job, queuedAt: Date.now() - 7 * 3600_000 }, deps)).toBe('stale');

    const spent = { ...deps, vt: { ...deps.vt!, budget: new ApiBudget(redis, 'spent', { perDay: 0, perMinute: 4 }) } };
    await redis.rpush(intelWaitersKey(job.subject), JSON.stringify(waiter('100000000000000001')));
    expect(await processVirusTotal(job, spent)).toBe('daily_budget_spent');
    expect(await redis.exists(intelWaitersKey(job.subject))).toBe(0);
    expect(vtProvider.calls).toBe(0);
  });
});

describe('exit check: a provider outage degrades gracefully', () => {
  it('keeps going with whatever still works, and caches nothing from the broken source', async () => {
    const { deps, redirects, rdap, logger, cache } = setup();
    redirects.down = true;
    rdap.down = true;
    const resolution = await resolveUrl('https://bit.ly/x', 0.5, deps);
    expect(resolution.summary).toEqual({ level: 'clean', score: 0, sources: [], reasons: [] });
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ provider: 'redirects' }),
      'intel provider failed, continuing without it',
    );
    expect([...cache.entries.keys()].some((k) => k.startsWith('redirects|'))).toBe(false);

    rdap.down = false;
    rdap.answers.set('bit.ly', { level: 'clean' });
    expect((await resolveUrl('https://bit.ly/x', 0.5, deps)).results.map((r) => r.provider)).toEqual(['urlhaus', 'rdap']);
  });

  it('publishes without VirusTotal when VirusTotal is down', async () => {
    const { deps, vtProvider, rdap } = setup();
    vtProvider.down = true;
    rdap.answers.set('odd.test', { level: 'suspicious', weight: 0.4, reasons: ['New'] });
    await redis.rpush(intelWaitersKey('https://odd.test/'), JSON.stringify(waiter('100000000000000001')));
    const received = await listen();
    const job: VirusTotalJob = { subject: 'https://odd.test/', finalUrl: 'https://odd.test/', heuristicScore: 0.3, queuedAt: Date.now() };
    expect(await processVirusTotal(job, deps)).toBe('unavailable');
    await settle();
    expect(received[0]?.summary.sources).toEqual(['rdap']);
  });

  it('survives Redis-side junk in the feed or the cache', async () => {
    const { deps } = setup();
    await redis.set(URLHAUS_URLS_KEY, 'wrong type');
    const resolution = await resolveUrl('https://x.test/', 0, deps);
    expect(resolution.summary.level).toBe('clean');
  });
});

describe('exit check: the VirusTotal budget is never exceeded under load', () => {
  it('hands out exactly the per-minute limit to concurrent callers, then more once the window moves', async () => {
    let now = 1_800_000_000_000;
    const budget = new ApiBudget(redis, 'minute-test', { perDay: 500, perMinute: 4 }, () => now);
    const results = await Promise.all(Array.from({ length: 50 }, () => budget.take()));
    expect(results.filter((r) => r.ok)).toHaveLength(4);
    expect(results.find((r) => !r.ok)).toMatchObject({ reason: 'rate_limited' });

    now += 30_000;
    expect((await budget.take()).ok).toBe(false);
    now += 30_001;
    const next = await Promise.all(Array.from({ length: 10 }, () => budget.take()));
    expect(next.filter((r) => r.ok)).toHaveLength(4);
  });

  it('hands out exactly the daily budget across concurrent workers', async () => {
    const budgets = Array.from({ length: 5 }, () => new ApiBudget(redis, 'day-test', { perDay: 37, perMinute: 10_000 }));
    const results = await Promise.all(Array.from({ length: 200 }, (_, i) => budgets[i % 5]!.take()));
    expect(results.filter((r) => r.ok)).toHaveLength(37);
    expect(results.filter((r) => !r.ok).every((r) => !r.ok && r.reason === 'daily_budget_spent')).toBe(true);
    expect(await budgets[0]!.usedToday()).toBe(37);
  });

  it('runs 150 lookups through the real queues and calls VirusTotal exactly as often as the budget allows', async () => {
    const { deps, vtProvider, logger } = setup();
    const connection = new Redis(url, { maxRetriesPerRequest: null });
    const vtQueue = new Queue(INTEL_VT_QUEUE, { connection, prefix: QUEUE_PREFIX, defaultJobOptions: { removeOnComplete: true } });
    const lookupQueue = new Queue(INTEL_LOOKUP_QUEUE, { connection, prefix: QUEUE_PREFIX, defaultJobOptions: { removeOnComplete: true } });
    const budget = new ApiBudget(redis, 'load-test', { perDay: 25, perMinute: 10_000 });
    const loadDeps: JobDeps = { ...deps, vt: { provider: vtProvider, budget, queue: vtQueue } };
    const workers: Worker[] = startIntelWorkers({
      deps: loadDeps,
      connection,
      logger,
      vtPerMinute: 1000,
      vtLimiterDurationMs: 1000,
      lookupConcurrency: 8,
    });

    try {
      await lookupQueue.addBulk(
        Array.from({ length: 150 }, (_, i) => ({
          name: 'lookup',
          data: { subject: `https://load-${i}.test/`, heuristicScore: 0.3 },
          opts: { jobId: `load-${i}` },
        })),
      );
      await waitFor(async () => (await lookupQueue.count()) === 0 && (await vtQueue.count()) === 0, 30_000);
      await new Promise((resolve) => setTimeout(resolve, 300));

      expect(vtProvider.calls).toBe(25);
      expect(await budget.usedToday()).toBe(25);
    } finally {
      await Promise.all(workers.map((w) => w.close()));
      await Promise.all([vtQueue.close(), lookupQueue.close()]);
      connection.disconnect();
    }
  }, 60_000);

  it('never goes over the per-minute limit in any sliding window, with the queue limiter and budget together', async () => {
    const { deps, vtProvider, logger } = setup();
    // Record the clock reading the budget granted each call at (the VT worker runs one job at a time).
    const times: number[] = [];
    let lastReading = 0;
    const clock = () => (lastReading = Date.now());
    const connection = new Redis(url, { maxRetriesPerRequest: null });
    const vtQueue = new Queue(INTEL_VT_QUEUE, { connection, prefix: QUEUE_PREFIX, defaultJobOptions: { removeOnComplete: true } });
    // A one-second "minute" so the test runs quickly; production uses 60 seconds.
    const budget = new ApiBudget(redis, 'pace-test', { perDay: 500, perMinute: 3 }, clock, 1000);
    const take = budget.take.bind(budget);
    budget.take = async () => {
      const result = await take();
      if (result.ok) times.push(lastReading);
      return result;
    };
    const workers = startIntelWorkers({
      deps: { ...deps, vt: { provider: vtProvider, budget, queue: vtQueue } },
      connection,
      logger,
      vtPerMinute: 3,
      vtLimiterDurationMs: 1000,
    });

    try {
      await vtQueue.addBulk(
        Array.from({ length: 9 }, (_, i) => ({
          name: 'lookup',
          data: { subject: `https://pace-${i}.test/`, finalUrl: `https://pace-${i}.test/`, heuristicScore: 0.3, queuedAt: Date.now() },
          opts: { priority: VT_PRIORITY.singleGuild },
        })),
      );
      await waitFor(() => Promise.resolve(times.length === 9), 20_000);
      expect(await budget.usedToday()).toBe(9);
      // No one-second window, wherever it starts, may contain more than 3 calls.
      for (const start of times) {
        expect(times.filter((t) => t >= start && t < start + 1000).length).toBeLessThanOrEqual(3);
      }
    } finally {
      await Promise.all(workers.map((w) => w.close()));
      await vtQueue.close();
      connection.disconnect();
    }
  }, 30_000);
});

async function waitFor(check: () => Promise<boolean>, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('timed out waiting');
}

describe('URLhaus feed sync', () => {
  const csv = (...urls: string[]) =>
    ['# header', ...urls.map((u, i) => `"${i}","2026-09-30","${u}","online","","malware_download","","",""`)].join('\n');

  function feed(body: () => Response, authKey?: string) {
    const calls: { url: string; headers: Record<string, string> }[] = [];
    const fetch: FetchLike = (url, init) => {
      calls.push({ url, headers: (init?.headers ?? {}) as Record<string, string> });
      return Promise.resolve(body());
    };
    return { feed: new UrlhausFeed(redis, { authKey, fetch }), calls };
  }

  it('replaces the whole set in one step, and sends the Auth-Key only when there is one', async () => {
    await redis.sadd(URLHAUS_URLS_KEY, 'http://old.test/gone.exe');
    const withKey = feed(() => new Response(csv('http://A.test/x.exe', 'http://b.test/y.exe')), 'k'.repeat(40));
    expect(await withKey.feed.sync()).toBe(2);
    expect((await redis.smembers(URLHAUS_URLS_KEY)).sort()).toEqual(['http://a.test/x.exe', 'http://b.test/y.exe']);
    expect(withKey.calls[0]).toMatchObject({ url: URLHAUS_FEED_URL, headers: { 'auth-key': 'k'.repeat(40) } });
    expect(await redis.exists(`${URLHAUS_URLS_KEY}:staging`)).toBe(0);

    const noKey = feed(() => new Response(csv('http://c.test/z.exe')));
    await noKey.feed.sync();
    expect(noKey.calls[0]?.headers).toEqual({});
  });

  it('keeps the previous copy when the download fails or comes back empty', async () => {
    await redis.sadd(URLHAUS_URLS_KEY, 'http://kept.test/a.exe');
    await expect(feed(() => new Response('denied', { status: 401 })).feed.sync()).rejects.toThrow(/401/);
    expect(await feed(() => new Response('# nothing here\n')).feed.sync()).toBe(0);
    expect(await redis.smembers(URLHAUS_URLS_KEY)).toEqual(['http://kept.test/a.exe']);
  });

  it('matches exact URLs only, never whole hosts', async () => {
    await redis.sadd(URLHAUS_URLS_KEY, 'https://cdn.discordapp.com/attachments/1/2/bad.exe');
    const urlhaus = new UrlhausFeed(redis);
    expect(await urlhaus.lookup('https://cdn.discordapp.com/attachments/1/2/bad.exe', 'url')).toMatchObject({ level: 'malicious' });
    expect(await urlhaus.lookup('https://cdn.discordapp.com/attachments/3/4/fine.png', 'url')).toMatchObject({ level: 'unknown' });
    expect(await urlhaus.lookup('cdn.discordapp.com', 'domain')).toBeNull();
  });
});

describe('VirusTotal failure handling', () => {
  it('skips VirusTotal when its queue is already backed up', async () => {
    const { deps } = setup();
    const full = { ...deps, vt: { ...deps.vt!, queue: { add: () => Promise.resolve(), count: () => Promise.resolve(VT_MAX_BACKLOG) } } };
    expect(await processLookup({ subject: 'https://busy.test/', heuristicScore: 0.3 }, full)).toEqual({
      level: 'clean',
      virustotal: 'backlog_full',
    });
  });

  it('reports that VirusTotal is off when there is no key', async () => {
    const { deps } = setup();
    const off = { ...deps, vt: null };
    expect(await processLookup({ subject: 'https://nokey.test/', heuristicScore: 0.3 }, off)).toMatchObject({ virustotal: 'disabled' });
    const job: VirusTotalJob = { subject: 'https://nokey.test/', finalUrl: 'https://nokey.test/', heuristicScore: 0.3, queuedAt: Date.now() };
    expect(await processVirusTotal(job, off)).toBe('unavailable');
  });

  it('surfaces a rejected key instead of treating it as an outage', async () => {
    const { deps, vtProvider } = setup();
    vtProvider.lookup = () => Promise.reject(new VirusTotalAuthError());
    const job: VirusTotalJob = { subject: 'https://k.test/', finalUrl: 'https://k.test/', heuristicScore: 0.3, queuedAt: Date.now() };
    await expect(processVirusTotal(job, deps)).rejects.toBeInstanceOf(VirusTotalAuthError);
  });

  it('pauses VirusTotal lookups when the key is rejected, and says so', async () => {
    const { deps, vtProvider, logger } = setup();
    vtProvider.lookup = () => Promise.reject(new VirusTotalAuthError());
    const connection = new Redis(url, { maxRetriesPerRequest: null });
    const vtQueue = new Queue(INTEL_VT_QUEUE, { connection, prefix: QUEUE_PREFIX, defaultJobOptions: { removeOnComplete: true } });
    const workers = startIntelWorkers({ deps: { ...deps, vt: { ...deps.vt!, queue: vtQueue } }, connection, logger, vtPerMinute: 4 });
    const vtWorker = workers.find((w) => w.name === INTEL_VT_QUEUE)!;
    try {
      await vtQueue.add(
        'lookup',
        { subject: 'https://k.test/', finalUrl: 'https://k.test/', heuristicScore: 0.3, queuedAt: Date.now() },
        { priority: VT_PRIORITY.singleGuild },
      );
      await waitFor(() => Promise.resolve(vtWorker.isPaused()), 10_000);
      expect(logger.error).toHaveBeenCalledWith(expect.stringMatching(/rejected VT_API_KEY/));
    } finally {
      await Promise.all(workers.map((w) => w.close()));
      await vtQueue.close();
      connection.disconnect();
    }
  }, 20_000);
});

describe('worker status for the dashboard', () => {
  it('reports which sources are on and the last URLhaus sync, and expires if the worker stops', async () => {
    const now = new Date('2026-09-30T12:00:00Z');
    expect(await writeStatus(redis, { virustotal: false }, now)).toEqual({ virustotal: false, urlhaus: null, heartbeatAt: now.toISOString() });

    await recordUrlhausSync(redis, 1234, now);
    const status = await writeStatus(redis, { virustotal: true }, now);
    expect(status).toEqual({ virustotal: true, urlhaus: { count: 1234, syncedAt: now.toISOString() }, heartbeatAt: now.toISOString() });
    expect(intelStatusSchema.parse(JSON.parse((await redis.get(INTEL_STATUS_KEY))!))).toEqual(status);
    const ttl = await redis.ttl(INTEL_STATUS_KEY);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(INTEL_STATUS_TTL_SECONDS);
  });

  it('records a sync whenever the feed is replaced', async () => {
    const fetch: FetchLike = () => Promise.resolve(new Response('"1","d","http://x.test/a.exe","online"\n'));
    await new UrlhausFeed(redis, { fetch }).sync();
    expect(JSON.parse((await redis.get(URLHAUS_META_KEY))!)).toMatchObject({ count: 1 });
  });

  it('ignores a corrupted sync record', async () => {
    await redis.set(URLHAUS_META_KEY, 'garbage');
    expect((await writeStatus(redis, { virustotal: true })).urlhaus).toBeNull();
  });

  it('reports a list loaded before any sync was recorded by its size', async () => {
    await redis.sadd(URLHAUS_URLS_KEY, 'http://a.test/1', 'http://a.test/2');
    expect((await writeStatus(redis, { virustotal: true })).urlhaus).toEqual({ count: 2, syncedAt: null });
  });
});
