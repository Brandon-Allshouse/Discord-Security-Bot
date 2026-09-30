import type { Redis } from 'ioredis';
import {
  BLOCKLIST_DOMAINS_KEY,
  INTEL_STATUS_KEY,
  intelStatusSchema,
  readCachedIntel,
  subjectId,
  type IntelLookupJob,
  type IntelStatus,
  type IntelSummary,
} from '@equinox/core';

/** What the dashboard needs from threat intel. Reads caches only; lookups go to the worker's queue. */
export interface DashboardIntel {
  /** The worker's heartbeat, or null when it isn't running. */
  status(): Promise<IntelStatus | null>;
  cached(url: string): Promise<IntelSummary | null>;
  isBlocklisted(domainCandidates: string[]): Promise<boolean>;
  requestLookup(url: string, heuristicScore: number): Promise<void>;
}

export interface LookupQueue {
  add(name: string, data: IntelLookupJob, opts: { jobId: string }): Promise<unknown>;
}

export class RedisDashboardIntel implements DashboardIntel {
  constructor(
    private readonly redis: Redis,
    private readonly queue: LookupQueue,
  ) {}

  async status(): Promise<IntelStatus | null> {
    const raw = await this.redis.get(INTEL_STATUS_KEY);
    if (!raw) return null;
    try {
      const parsed = intelStatusSchema.safeParse(JSON.parse(raw));
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }

  cached(url: string): Promise<IntelSummary | null> {
    return readCachedIntel(this.redis, url);
  }

  async isBlocklisted(domainCandidates: string[]): Promise<boolean> {
    if (domainCandidates.length === 0) return false;
    const hits = await this.redis.smismember(BLOCKLIST_DOMAINS_KEY, ...domainCandidates);
    return hits.some((hit) => hit === 1);
  }

  async requestLookup(url: string, heuristicScore: number): Promise<void> {
    // Same job ID as the bot uses, so a link checked in both places is looked up once.
    await this.queue.add('lookup', { subject: url, heuristicScore }, { jobId: `lookup-${subjectId(url)}` });
  }
}
