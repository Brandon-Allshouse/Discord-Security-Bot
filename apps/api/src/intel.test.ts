import type { Redis } from 'ioredis';
import { describe, expect, it } from 'vitest';
import { BLOCKLIST_DOMAINS_KEY, INTEL_STATUS_KEY, intelSummaryKey, subjectId, type IntelStatus } from '@equinox/core';
import { RedisDashboardIntel, type LookupQueue } from './intel.js';

const STATUS: IntelStatus = {
  virustotal: true,
  urlhaus: { count: 13329, syncedAt: '2026-09-30T12:00:00.000Z' },
  heartbeatAt: '2026-09-30T12:05:00.000Z',
};

/** Enough of Redis for the API's intel reads. */
function fakeRedis(values: Record<string, string>, sets: Record<string, string[]> = {}) {
  return {
    get: (key: string) => Promise.resolve(values[key] ?? null),
    sismember: (key: string, member: string) => Promise.resolve(sets[key]?.includes(member) ? 1 : 0),
    smismember: (key: string, ...members: string[]) => Promise.resolve(members.map((m) => (sets[key]?.includes(m) ? 1 : 0))),
  } as unknown as Redis;
}

describe('RedisDashboardIntel', () => {
  const noQueue: LookupQueue = { add: () => Promise.resolve() };

  it('reads the worker status, and treats a missing or corrupt one as not running', async () => {
    expect(await new RedisDashboardIntel(fakeRedis({ [INTEL_STATUS_KEY]: JSON.stringify(STATUS) }), noQueue).status()).toEqual(STATUS);
    expect(await new RedisDashboardIntel(fakeRedis({}), noQueue).status()).toBeNull();
    expect(await new RedisDashboardIntel(fakeRedis({ [INTEL_STATUS_KEY]: 'junk' }), noQueue).status()).toBeNull();
    expect(await new RedisDashboardIntel(fakeRedis({ [INTEL_STATUS_KEY]: '{"virustotal":"yes"}' }), noQueue).status()).toBeNull();
  });

  it('reads cached intel and the blocklist', async () => {
    const summary = { level: 'suspicious', score: 0.6, sources: ['rdap'], reasons: ['New'] };
    const intel = new RedisDashboardIntel(
      fakeRedis({ [intelSummaryKey('https://a.test/')]: JSON.stringify(summary) }, { [BLOCKLIST_DOMAINS_KEY]: ['bad.test'] }),
      noQueue,
    );
    expect(await intel.cached('https://a.test/')).toEqual(summary);
    expect(await intel.isBlocklisted(['www.bad.test', 'bad.test'])).toBe(true);
    expect(await intel.isBlocklisted(['good.test'])).toBe(false);
    expect(await intel.isBlocklisted([])).toBe(false);
  });

  it('queues lookups under the same job ID the bot uses, so a link is looked up once', async () => {
    const jobs: { data: unknown; jobId: string }[] = [];
    const queue: LookupQueue = {
      add: (_name, data, opts) => {
        jobs.push({ data, jobId: opts.jobId });
        return Promise.resolve();
      },
    };
    await new RedisDashboardIntel(fakeRedis({}), queue).requestLookup('https://a.test/', 0.2);
    expect(jobs).toEqual([{ data: { subject: 'https://a.test/', heuristicScore: 0.2 }, jobId: `lookup-${subjectId('https://a.test/')}` }]);
  });
});
