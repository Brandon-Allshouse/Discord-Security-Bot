import type { Redis } from 'ioredis';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeGuild, makeSignal } from '@equinox/core/testing';
import type { AllowlistStore, GuildStore } from '@equinox/db';
import { CachedGuildRepository, IndicatorService, seedBlocklist } from './indicators.js';

afterEach(() => {
  vi.useRealTimers();
});

describe('CachedGuildRepository', () => {
  it('caches tenant settings until the TTL passes', async () => {
    vi.useFakeTimers();
    const get = vi.fn(() => Promise.resolve(makeGuild()));
    const cache = new CachedGuildRepository({ get } as unknown as GuildStore, 1000);
    await cache.get('1');
    await cache.get('1');
    expect(get).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1001);
    await cache.get('1');
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('caches per tenant and can be invalidated', async () => {
    const get = vi.fn((id: string) => Promise.resolve(makeGuild({ id })));
    const cache = new CachedGuildRepository({ get } as unknown as GuildStore);
    expect((await cache.get('100000000000000001'))?.id).toBe('100000000000000001');
    expect((await cache.get('100000000000000002'))?.id).toBe('100000000000000002');
    cache.invalidate('100000000000000001');
    await cache.get('100000000000000001');
    expect(get).toHaveBeenCalledTimes(3);
  });

  it('caches "not a tenant" too, so unknown servers don’t hit the database per message', async () => {
    const get = vi.fn(() => Promise.resolve(null));
    const cache = new CachedGuildRepository({ get } as unknown as GuildStore);
    await cache.get('1');
    await cache.get('1');
    expect(get).toHaveBeenCalledTimes(1);
  });
});

describe('IndicatorService', () => {
  const redis = { smismember: vi.fn((_key: string, ...members: string[]) => Promise.resolve(members.map((m) => (m === 'evil.example' ? 1 : 0)))) };
  const hasAny = vi.fn((_g: string, _t: string, values: string[]) => Promise.resolve(values.includes('example.org')));
  const service = new IndicatorService(redis as unknown as Redis, { hasAny } as unknown as AllowlistStore);

  it('checks the host and every parent domain against the blocklist', async () => {
    expect(await service.isBlocklisted(makeSignal({ subject: 'https://a.b.evil.example/x' }))).toBe(true);
    expect(redis.smismember).toHaveBeenLastCalledWith('equinox:blocklist:domain', 'a.b.evil.example', 'b.evil.example', 'evil.example');
  });

  it('checks the tenant allowlist for the host and parents', async () => {
    expect(await service.isAllowlisted('100000000000000001', makeSignal({ subject: 'https://cdn.example.org/' }))).toBe(true);
    expect(hasAny).toHaveBeenLastCalledWith('100000000000000001', 'domain', ['cdn.example.org', 'example.org']);
  });

  it('only applies to url signals', async () => {
    redis.smismember.mockClear();
    expect(await service.isBlocklisted(makeSignal({ kind: 'file', subject: 'abc' }))).toBe(false);
    expect(await service.isAllowlisted('100000000000000001', makeSignal({ kind: 'file', subject: 'abc' }))).toBe(false);
    expect(redis.smismember).not.toHaveBeenCalled();
  });

  it('treats unparseable subjects as not listed', async () => {
    expect(await service.isBlocklisted(makeSignal({ subject: 'not a url' }))).toBe(false);
  });
});

describe('seedBlocklist', () => {
  it('does nothing for an empty file', async () => {
    const sadd = vi.fn();
    expect(await seedBlocklist({ sadd } as unknown as Redis, '# only comments\n\n')).toBe(0);
    expect(sadd).not.toHaveBeenCalled();
  });
});
