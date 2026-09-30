import type { Redis } from 'ioredis';
import {
  BLOCKLIST_DOMAINS_KEY,
  domainCandidates,
  normalizeUrl,
  type GuildRepository,
  type GuildSettings,
  type IndicatorLookup,
  type Signal,
} from '@equinox/core';
import type { AllowlistStore, GuildStore } from '@equinox/db';

export { BLOCKLIST_DOMAINS_KEY };

/** Blocklist lives in Redis (sub-ms set lookups); allowlists live in Postgres per guild. */
export class IndicatorService implements IndicatorLookup {
  constructor(
    private readonly redis: Redis,
    private readonly allowlist: AllowlistStore,
  ) {}

  async isAllowlisted(guildId: string, signal: Signal): Promise<boolean> {
    if (signal.kind !== 'url') return false;
    const normalized = normalizeUrl(signal.subject);
    if (!normalized) return false;
    return this.allowlist.hasAny(guildId, 'domain', domainCandidates(normalized));
  }

  async isBlocklisted(signal: Signal): Promise<boolean> {
    if (signal.kind !== 'url') return false;
    const normalized = normalizeUrl(signal.subject);
    if (!normalized) return false;
    return this.isDomainBlocklisted(domainCandidates(normalized));
  }

  async isDomainBlocklisted(candidates: string[]): Promise<boolean> {
    const hits = await this.redis.smismember(BLOCKLIST_DOMAINS_KEY, ...candidates);
    return hits.some((hit) => hit === 1);
  }
}

/** Loads the seed blocklist: one domain per line, '#' comments allowed. */
export async function seedBlocklist(redis: Redis, text: string): Promise<number> {
  const domains = text
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*/, '').trim().toLowerCase())
    .filter((line) => /^[a-z0-9.-]+\.[a-z0-9-]+$/.test(line));
  if (domains.length === 0) return 0;
  return redis.sadd(BLOCKLIST_DOMAINS_KEY, ...domains);
}

/**
 * Short-lived cache in front of guild settings so busy servers don't hit Postgres per message.
 * Commands that change settings call invalidate().
 */
export class CachedGuildRepository implements GuildRepository {
  private readonly cache = new Map<string, { value: GuildSettings | null; expires: number }>();

  constructor(
    private readonly store: GuildStore,
    private readonly ttlMs = 30_000,
  ) {}

  async get(guildId: string): Promise<GuildSettings | null> {
    const hit = this.cache.get(guildId);
    if (hit && hit.expires > Date.now()) return hit.value;
    const value = await this.store.get(guildId);
    this.cache.set(guildId, { value, expires: Date.now() + this.ttlMs });
    return value;
  }

  invalidate(guildId: string): void {
    this.cache.delete(guildId);
  }
}
