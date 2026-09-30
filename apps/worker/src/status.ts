import type { Redis } from 'ioredis';
import { INTEL_STATUS_KEY, INTEL_STATUS_TTL_SECONDS, intelStatusSchema, URLHAUS_URLS_KEY, type IntelStatus } from '@equinox/core';

export const URLHAUS_META_KEY = 'equinox:feed:urlhaus:meta';
const metaSchema = intelStatusSchema.shape.urlhaus.unwrap();

/** Remembers the last successful URLhaus sync, so the status survives worker restarts. */
export async function recordUrlhausSync(redis: Redis, count: number, now = new Date()): Promise<void> {
  await redis.set(URLHAUS_META_KEY, JSON.stringify({ count, syncedAt: now.toISOString() }));
}

/**
 * Writes the worker's status for the dashboard. It expires after a few minutes, so a stopped
 * worker shows up as "not running" instead of looking healthy forever.
 */
export async function writeStatus(redis: Redis, options: { virustotal: boolean }, now = new Date()): Promise<IntelStatus> {
  const raw = await redis.get(URLHAUS_META_KEY);
  let urlhaus: IntelStatus['urlhaus'] = null;
  try {
    const parsed = metaSchema.safeParse(raw ? JSON.parse(raw) : null);
    if (parsed.success) urlhaus = parsed.data;
  } catch {
    urlhaus = null;
  }
  // A list can be loaded without a sync record (e.g. loaded by an older version): report its size.
  if (!urlhaus) {
    const count = await redis.scard(URLHAUS_URLS_KEY);
    if (count > 0) urlhaus = { count, syncedAt: null };
  }
  const status: IntelStatus = { virustotal: options.virustotal, urlhaus, heartbeatAt: now.toISOString() };
  await redis.set(INTEL_STATUS_KEY, JSON.stringify(status), 'EX', INTEL_STATUS_TTL_SECONDS);
  return status;
}
