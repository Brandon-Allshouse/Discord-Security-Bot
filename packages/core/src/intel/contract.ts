import { createHash } from 'node:crypto';
import { z } from 'zod';
import { snowflakeSchema, VERDICT_LEVELS } from '../types.js';

/**
 * How the bot and the intel worker talk. Both sides validate everything they read,
 * so a bad message on Redis can't push junk into the pipeline.
 *
 * 1. The bot finds a link it knows nothing about. It adds a "waiter" (which message to come
 *    back to) to a short-lived list for that URL and queues a lookup job.
 * 2. The worker resolves the URL through the provider chain, caches a summary under
 *    `intelSummaryKey`, and publishes it with the waiters on `INTEL_RESOLVED_CHANNEL`.
 * 3. Each shard picks the waiters in its own servers and runs them through the pipeline again.
 *
 * Only IDs and the normalized URL travel this way, never message content.
 */

export const INTEL_LOOKUP_QUEUE = 'intel-lookup';
export const INTEL_VT_QUEUE = 'intel-virustotal';
export const INTEL_FEED_QUEUE = 'intel-feeds';
/** BullMQ key prefix, so queue keys sit under the same namespace as everything else. */
export const QUEUE_PREFIX = 'equinox:bull';

export const INTEL_RESOLVED_CHANNEL = 'equinox:intel:resolved';
/** Confirmed bad domains on the network blocklist (a Redis set). */
export const BLOCKLIST_DOMAINS_KEY = 'equinox:blocklist:domain';
/** The worker's heartbeat and source status, for the dashboard. Expires if the worker stops. */
export const INTEL_STATUS_KEY = 'equinox:intel:status';
export const INTEL_STATUS_TTL_SECONDS = 180;
/** Set of normalized URLs currently listed by URLhaus. */
export const URLHAUS_URLS_KEY = 'equinox:feed:urlhaus:urls';

/** How long a queued message waits for its intel before we stop coming back to it. */
export const WAITER_TTL_SECONDS = 3600;
/**
 * Lookups one server may ask for per minute. Each lookup can mean outside requests
 * (registries, redirects), so a server flooding unique links can't flood the worker.
 */
export const LOOKUPS_PER_GUILD_PER_MINUTE = 30;

/** Waiters kept per URL. A link spammed everywhere doesn't need thousands of entries. */
export const MAX_WAITERS = 200;

/** Short, fixed-length ID for a URL, used in Redis keys and job IDs. */
export function subjectId(subject: string): string {
  return createHash('sha256').update(subject).digest('hex').slice(0, 32);
}

export const intelSummaryKey = (subject: string) => `equinox:intel:summary:${subjectId(subject)}`;
export const intelWaitersKey = (subject: string) => `equinox:intel:waiters:${subjectId(subject)}`;

export const intelSummarySchema = z.object({
  level: z.enum(VERDICT_LEVELS),
  score: z.number().min(0).max(1),
  sources: z.array(z.string().min(1).max(50)).max(10),
  reasons: z.array(z.string().min(1).max(200)).max(10),
});

/** A message that is waiting for intel about one of its links. */
export const intelWaiterSchema = z.object({
  guildId: snowflakeSchema,
  userId: snowflakeSchema,
  channelId: snowflakeSchema,
  messageId: snowflakeSchema,
  heuristicScore: z.number().min(0).max(1),
  reasons: z.array(z.string().min(1).max(200)).max(10),
});
export type IntelWaiter = z.infer<typeof intelWaiterSchema>;

export const intelLookupJobSchema = z.object({
  subject: z.string().min(1).max(2048),
  /** Highest local score among the messages that asked; decides whether to follow redirects. */
  heuristicScore: z.number().min(0).max(1),
});
export type IntelLookupJob = z.infer<typeof intelLookupJobSchema>;

/**
 * What the dashboard may show every tenant about the intel service. Deliberately no budget
 * numbers: anyone can install the bot, and "VirusTotal is used up today" would tell an attacker when to strike.
 */
export const intelStatusSchema = z.object({
  virustotal: z.boolean(),
  /** null: no list yet. syncedAt null: a list is loaded but it's not known when (before the first sync is recorded). */
  urlhaus: z.object({ count: z.number().int().min(0), syncedAt: z.iso.datetime().nullable() }).nullable(),
  heartbeatAt: z.iso.datetime(),
});
export type IntelStatus = z.infer<typeof intelStatusSchema>;

export const intelResolvedSchema = z.object({
  subject: z.string().min(1).max(2048),
  summary: intelSummarySchema,
  waiters: z.array(intelWaiterSchema).max(MAX_WAITERS),
});
export type IntelResolved = z.infer<typeof intelResolvedSchema>;
