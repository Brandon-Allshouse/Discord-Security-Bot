import { isIP } from 'node:net';
import type { Redis } from 'ioredis';
import {
  cacheTtlSeconds,
  INTEL_RESOLVED_CHANNEL,
  intelSummaryKey,
  intelWaiterSchema,
  intelWaitersKey,
  MAX_WAITERS,
  subjectId,
  summarizeIntel,
  type IntelLookupJob,
  type IntelProvider,
  type IntelResolved,
  type IntelSummary,
  type IntelWaiter,
  type ProviderResult,
} from '@equinox/core';
import type { ApiBudget } from './budget.js';
import { resolveUrl, type ChainDeps } from './chain.js';
import { isBlockedAddress } from './net/address-policy.js';
import { VirusTotalAuthError } from './providers/virustotal.js';

export interface VirusTotalJob extends IntelLookupJob {
  /** Where the link really ends up; that's what VirusTotal is asked about. */
  finalUrl: string;
  /** When the lookup was queued. Old jobs are dropped rather than answered hours late. */
  queuedAt: number;
}

export interface VtQueue {
  add(name: string, data: VirusTotalJob, opts: { jobId: string; priority: number }): Promise<unknown>;
  count(): Promise<number>;
}

export interface JobDeps extends ChainDeps {
  redis: Redis;
  vt: { provider: IntelProvider; budget: ApiBudget; queue: VtQueue } | null;
}

/** Past this many queued VirusTotal lookups, new ones are skipped: 4 a minute can't catch up anyway. */
export const VT_MAX_BACKLOG = 1000;
export const VT_MAX_AGE_MS = 6 * 3600 * 1000;
/** BullMQ priorities: lower runs first, and 0 would mean "before everything". */
export const VT_PRIORITY = { multiGuild: 1, singleGuild: 10 } as const;

/** Thrown when the per-minute limit is reached; the worker pauses the queue and retries the job. */
export class RateLimitedError extends Error {
  constructor(readonly retryInMs: number) {
    super('rate limited');
    this.name = 'RateLimitedError';
  }
}

async function readWaiters(redis: Redis, subject: string): Promise<IntelWaiter[]> {
  const raw = await redis.lrange(intelWaitersKey(subject), 0, MAX_WAITERS - 1);
  const waiters: IntelWaiter[] = [];
  for (const item of raw) {
    try {
      const parsed = intelWaiterSchema.safeParse(JSON.parse(item));
      if (parsed.success) waiters.push(parsed.data);
    } catch {
      // Not JSON: skip it.
    }
  }
  return waiters;
}

/**
 * Caches the summary for the bot's fast path, then tells the shards which messages were
 * waiting for it. `final` clears the waiters; otherwise a VirusTotal answer is still coming.
 */
export async function publishSummary(redis: Redis, subject: string, summary: IntelSummary, final: boolean): Promise<number> {
  await redis.set(intelSummaryKey(subject), JSON.stringify(summary), 'EX', cacheTtlSeconds(summary.level));
  const waiters = await readWaiters(redis, subject);
  if (final) await redis.del(intelWaitersKey(subject));
  // A summary that found nothing can't change any verdict.
  if (waiters.length === 0 || summary.score === 0) return 0;
  const message: IntelResolved = { subject, summary, waiters };
  await redis.publish(INTEL_RESOLVED_CHANNEL, JSON.stringify(message));
  return waiters.length;
}

function isPrivateIpUrl(url: string): boolean {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  return isIP(host) !== 0 && isBlockedAddress(host);
}

export type LookupOutcome = { level: IntelSummary['level']; virustotal: 'queued' | 'not_needed' | 'disabled' | 'backlog_full' };

/** One unknown URL through the chain, then (if still unresolved) onto the VirusTotal queue. */
export async function processLookup(job: IntelLookupJob, deps: JobDeps): Promise<LookupOutcome> {
  const resolution = await resolveUrl(job.subject, job.heuristicScore, deps);
  const { summary } = resolution;

  let virustotal: LookupOutcome['virustotal'] = 'disabled';
  if (deps.vt) {
    const waiters = await readWaiters(deps.redis, job.subject);
    const guildCount = new Set(waiters.map((w) => w.guildId)).size;
    // Stop when confident. Otherwise only spend budget on links that show some sign of trouble,
    // or that turn up in several servers at once (a campaign). This also keeps ordinary links
    // people share out of a third-party service.
    const worthAsking =
      summary.level !== 'malicious' &&
      (summary.score > 0 || job.heuristicScore > 0 || guildCount >= 2) &&
      !isPrivateIpUrl(resolution.finalUrl);
    if (!worthAsking) virustotal = 'not_needed';
    else if ((await deps.vt.queue.count()) >= VT_MAX_BACKLOG) virustotal = 'backlog_full';
    else {
      await deps.vt.queue.add(
        'lookup',
        { ...job, finalUrl: resolution.finalUrl, queuedAt: Date.now() },
        {
          jobId: `vt-${subjectId(job.subject)}`,
          priority: guildCount >= 2 ? VT_PRIORITY.multiGuild : VT_PRIORITY.singleGuild,
        },
      );
      virustotal = 'queued';
    }
  }

  await publishSummary(deps.redis, job.subject, summary, virustotal !== 'queued');
  return { level: summary.level, virustotal };
}

export type VirusTotalOutcome = 'looked_up' | 'cached' | 'daily_budget_spent' | 'stale' | 'unavailable';

export async function processVirusTotal(job: VirusTotalJob, deps: JobDeps, now = Date.now()): Promise<VirusTotalOutcome> {
  const vt = deps.vt;
  if (!vt) return 'unavailable';
  if (now - job.queuedAt > VT_MAX_AGE_MS) {
    await deps.redis.del(intelWaitersKey(job.subject));
    return 'stale';
  }

  let outcome: VirusTotalOutcome = 'cached';
  let result: ProviderResult | null = await deps.cache.get(vt.provider.name, 'url', job.finalUrl).catch(() => null);
  if (!result) {
    const slot = await vt.budget.take();
    if (!slot.ok && slot.reason === 'rate_limited') throw new RateLimitedError(slot.retryInMs);
    if (!slot.ok) {
      // Out of budget for today: the fast-path answer already went out, so just stop here.
      await deps.redis.del(intelWaitersKey(job.subject));
      return 'daily_budget_spent';
    }
    try {
      result = await vt.provider.lookup(job.finalUrl, 'url');
      if (result) await deps.cache.put(result, cacheTtlSeconds(result.level));
      outcome = result ? 'looked_up' : 'unavailable';
    } catch (error) {
      // A rejected key needs a person; anything else is an outage and we carry on without VirusTotal.
      if (error instanceof VirusTotalAuthError) throw error;
      deps.logger.warn({ err: { message: error instanceof Error ? error.message : 'unknown' } }, 'virustotal lookup failed');
      outcome = 'unavailable';
    }
  }

  // Everything else is cached by now, so this is cheap.
  const resolution = await resolveUrl(job.subject, job.heuristicScore, deps);
  const summary = summarizeIntel(result ? [...resolution.results, result] : resolution.results);
  await publishSummary(deps.redis, job.subject, summary, true);
  return outcome;
}
