import { randomUUID } from 'node:crypto';
import type { Redis } from 'ioredis';
import {
  intelResolvedSchema,
  intelWaitersKey,
  LOOKUPS_PER_GUILD_PER_MINUTE,
  MAX_WAITERS,
  RateLimiter,
  readCachedIntel,
  reevaluateSignal,
  subjectId,
  WAITER_TTL_SECONDS,
  type IntelLookup,
  type IntelLookupJob,
  type IntelSummary,
  type IntelWaiter,
  type PipelineDeps,
  type Signal,
} from '@equinox/core';
import type { Logger } from './logger.js';

/**
 * The bot's fast path for threat intel: two Redis reads, no network lookups.
 * The cached summary comes from the intel worker; the URLhaus set is synced by it too.
 */
export class IntelCache implements IntelLookup {
  constructor(private readonly redis: Redis) {}

  summaryFor(signal: Signal): Promise<IntelSummary | null> {
    return signal.kind === 'url' ? this.forUrl(signal.subject) : Promise.resolve(null);
  }

  /** `url` must already be normalized (normalizeUrl().url), as signal subjects are. */
  forUrl(url: string): Promise<IntelSummary | null> {
    return readCachedIntel(this.redis, url);
  }
}

/** Where lookup jobs go. A BullMQ queue in production. */
export interface LookupQueue {
  add(name: string, data: IntelLookupJob, opts: { jobId: string }): Promise<unknown>;
}

/**
 * Asks the intel worker about a URL, and remembers which message to come back to.
 * One job per URL at a time (the job ID is derived from it), however many messages post it.
 */
export class IntelRequests {
  constructor(
    private readonly redis: Redis,
    private readonly queue: LookupQueue,
    /** Per server. In memory is enough: a server always lives on one shard. */
    private readonly perGuild = new RateLimiter(LOOKUPS_PER_GUILD_PER_MINUTE, 60_000),
  ) {}

  /** Look the URL up; nothing waits for the answer except the cache (used by the check command). */
  async lookup(subject: string, heuristicScore: number): Promise<void> {
    await this.queue.add('lookup', { subject, heuristicScore }, { jobId: `lookup-${subjectId(subject)}` });
  }

  /** Returns false when the server is over its lookup limit; the link is still judged locally. */
  async request(subject: string, waiter: IntelWaiter): Promise<boolean> {
    if (!this.perGuild.take(waiter.guildId)) return false;
    const key = intelWaitersKey(subject);
    await this.redis
      .multi()
      .rpush(key, JSON.stringify(waiter))
      .ltrim(key, -MAX_WAITERS, -1)
      .expire(key, WAITER_TTL_SECONDS)
      .exec();
    await this.lookup(subject, waiter.heuristicScore);
    return true;
  }
}

/**
 * Handles a result from the intel worker: every waiting message in a server this shard
 * serves goes through the pipeline again. The pipeline decides whether anything changes,
 * so a result that arrives twice doesn't act twice.
 */
export async function handleResolved(
  raw: string,
  ctx: { deps: PipelineDeps; logger: Pick<Logger, 'info' | 'warn'>; servesGuild: (guildId: string) => boolean },
): Promise<void> {
  let message;
  try {
    message = intelResolvedSchema.parse(JSON.parse(raw));
  } catch {
    ctx.logger.warn('ignored a malformed intel result');
    return;
  }

  for (const waiter of message.waiters) {
    if (!ctx.servesGuild(waiter.guildId)) continue;
    const result = await reevaluateSignal(
      {
        id: randomUUID(),
        kind: 'url',
        guildId: waiter.guildId,
        userId: waiter.userId,
        channelId: waiter.channelId,
        messageId: waiter.messageId,
        subject: message.subject,
        heuristicScore: waiter.heuristicScore,
        reasons: waiter.reasons,
        createdAt: new Date(),
      },
      ctx.deps,
    );
    if (result.status === 'detected' || result.status === 'escalated') {
      ctx.logger.info(
        { guildId: waiter.guildId, detectionId: result.detection.id, level: result.verdict.level, status: result.status },
        'link detection from threat intel',
      );
    }
  }
}
