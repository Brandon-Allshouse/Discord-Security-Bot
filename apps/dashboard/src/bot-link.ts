import { Queue, QueueEvents } from 'bullmq';
import type { Redis } from 'ioredis';
import {
  BOT_SHARD_COUNT_KEY,
  dashboardActionQueue,
  dashboardResultSchema,
  guildSnapshotKey,
  guildSnapshotSchema,
  QUEUE_PREFIX,
  shardForGuild,
  signAction,
  type DashboardAction,
  type DashboardResultCode,
  type GuildSnapshot,
} from '@equinox/core';

/** What came of a request to the bot. `off` means no signing key is configured. */
export type SendOutcome = DashboardResultCode | 'timeout' | 'bot_unavailable' | 'off';

/** How the dashboard reaches the bot. The dashboard never holds the bot token. */
export interface BotLink {
  /** Whether review, setup and test buttons can work at all (a signing key is configured). */
  readonly enabled: boolean;
  snapshot(guildId: string): Promise<GuildSnapshot | null>;
  send(action: DashboardAction): Promise<SendOutcome>;
}

/** Long enough for Discord to answer; short enough that the page doesn't hang. */
const WAIT_MS = 8000;

export class RedisBotLink implements BotLink {
  readonly enabled: boolean;
  private readonly queues = new Map<number, { queue: Queue; events: QueueEvents }>();

  constructor(
    private readonly redis: Redis,
    /** A connection factory: BullMQ's queue and event listener each need their own. */
    private readonly connect: () => Redis,
    private readonly signingKey: string | undefined,
    private readonly waitMs = WAIT_MS,
  ) {
    this.enabled = signingKey !== undefined;
  }

  async snapshot(guildId: string): Promise<GuildSnapshot | null> {
    const raw = await this.redis.get(guildSnapshotKey(guildId));
    if (!raw) return null;
    try {
      const parsed = guildSnapshotSchema.safeParse(JSON.parse(raw));
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }

  async send(action: DashboardAction): Promise<SendOutcome> {
    if (!this.signingKey) return 'off';
    const shardCount = Number(await this.redis.get(BOT_SHARD_COUNT_KEY));
    if (!Number.isInteger(shardCount) || shardCount < 1) return 'bot_unavailable';

    const { queue, events } = this.queueFor(shardForGuild(action.guildId, shardCount));
    const job = await queue.add(action.type, signAction(this.signingKey, action), {
      removeOnComplete: true,
      removeOnFail: true,
      // If the bot isn't there to pick it up, don't let it run minutes later.
      attempts: 1,
    });
    try {
      const result = dashboardResultSchema.safeParse(await job.waitUntilFinished(events, this.waitMs));
      return result.success ? result.data.code : 'bot_unavailable';
    } catch (error) {
      if (error instanceof Error && /timed out/i.test(error.message)) {
        // Not picked up in time: take it back, so it can't run after the user has been told it didn't.
        await job.remove().catch(() => undefined);
        return 'timeout';
      }
      return 'bot_unavailable';
    }
  }

  private queueFor(shardId: number) {
    let entry = this.queues.get(shardId);
    if (!entry) {
      const name = dashboardActionQueue(shardId);
      entry = {
        queue: new Queue(name, { connection: this.connect(), prefix: QUEUE_PREFIX }),
        events: new QueueEvents(name, { connection: this.connect(), prefix: QUEUE_PREFIX }),
      };
      this.queues.set(shardId, entry);
    }
    return entry;
  }

  async close(): Promise<void> {
    for (const { queue, events } of this.queues.values()) {
      await Promise.all([queue.close(), events.close()]);
    }
  }
}
