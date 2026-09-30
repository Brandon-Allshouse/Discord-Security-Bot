import { randomUUID } from 'node:crypto';
import type { Redis } from 'ioredis';

/**
 * Hard limits for a paid-per-call or rate-limited API, shared by every worker process.
 * One Lua script checks and takes a slot atomically, so concurrent workers can't
 * both see "one left" and both spend it.
 *
 * - Daily budget: a counter per UTC day.
 * - Per-minute limit: a sliding 60-second window (sorted set of call times), so there is
 *   no burst of 2x the limit around a minute boundary. (BullMQ's own limiter uses fixed
 *   windows and can allow exactly that burst, which is why this layer exists.)
 */
const TAKE_SCRIPT = `
local day_key, window_key = KEYS[1], KEYS[2]
local per_day, per_window = tonumber(ARGV[1]), tonumber(ARGV[2])
local now_ms, member, window_ms = tonumber(ARGV[3]), ARGV[4], tonumber(ARGV[5])

local used_today = tonumber(redis.call('GET', day_key) or '0')
if used_today >= per_day then return {0, 0} end

redis.call('ZREMRANGEBYSCORE', window_key, '-inf', now_ms - window_ms)
if redis.call('ZCARD', window_key) >= per_window then
  local oldest = redis.call('ZRANGE', window_key, 0, 0, 'WITHSCORES')
  return {-1, tonumber(oldest[2]) + window_ms - now_ms}
end

redis.call('INCR', day_key)
redis.call('EXPIRE', day_key, 172800)
redis.call('ZADD', window_key, now_ms, member)
redis.call('PEXPIRE', window_key, window_ms + 1000)
return {1, 0}
`;

export type TakeResult =
  | { ok: true }
  | { ok: false; reason: 'daily_budget_spent' }
  | { ok: false; reason: 'rate_limited'; retryInMs: number };

export class ApiBudget {
  constructor(
    private readonly redis: Redis,
    private readonly name: string,
    private readonly limits: { perDay: number; perMinute: number },
    private readonly now: () => number = Date.now,
    /** Length of the "minute". Only tests shorten it. */
    private readonly windowMs = 60_000,
  ) {}

  private dayKey(now: number): string {
    return `equinox:budget:${this.name}:${new Date(now).toISOString().slice(0, 10)}`;
  }

  /** Takes one call from the budget if both limits allow it. */
  async take(): Promise<TakeResult> {
    const now = this.now();
    const [status, wait] = (await this.redis.eval(
      TAKE_SCRIPT,
      2,
      this.dayKey(now),
      `equinox:budget:${this.name}:window`,
      this.limits.perDay,
      this.limits.perMinute,
      now,
      randomUUID(),
      this.windowMs,
    )) as [number, number];
    if (status === 1) return { ok: true };
    if (status === 0) return { ok: false, reason: 'daily_budget_spent' };
    return { ok: false, reason: 'rate_limited', retryInMs: Math.max(1, wait) };
  }

  async usedToday(): Promise<number> {
    return Number((await this.redis.get(this.dayKey(this.now()))) ?? 0);
  }
}
