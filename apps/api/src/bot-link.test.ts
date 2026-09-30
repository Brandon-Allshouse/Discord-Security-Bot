import { RedisContainer, type StartedRedisContainer } from '@testcontainers/redis';
import { Worker } from 'bullmq';
import { Redis } from 'ioredis';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  BOT_SHARD_COUNT_KEY,
  dashboardActionQueue,
  guildSnapshotKey,
  QUEUE_PREFIX,
  shardForGuild,
  verifyAction,
  type DashboardAction,
  type GuildSnapshot,
} from '@equinox/core';
import { RedisBotLink } from './bot-link.js';

const KEY = 'ab'.repeat(32);
const GUILD = '100000000000000001';
const action: DashboardAction = { type: 'test', guildId: GUILD, actorId: '500000000000000001' };

let container: StartedRedisContainer;
let redis: Redis;
const connections: Redis[] = [];
const connect = () => {
  const connection = new Redis(container.getConnectionUrl(), { maxRetriesPerRequest: null });
  connections.push(connection);
  return connection;
};

beforeAll(async () => {
  container = await new RedisContainer('redis:7-alpine').start();
  redis = new Redis(container.getConnectionUrl());
}, 120_000);

afterAll(async () => {
  for (const c of connections) c.disconnect();
  redis?.disconnect();
  await container?.stop();
});

beforeEach(async () => {
  await redis.flushall();
});

describe('RedisBotLink', () => {
  it('is off without a signing key, and never queues anything then', async () => {
    const link = new RedisBotLink(redis, connect, undefined);
    expect(link.enabled).toBe(false);
    expect(await link.send(action)).toBe('off');
    expect(await redis.keys('*')).toEqual([]);
  });

  it('reports the bot as unavailable when no shard count has been published', async () => {
    const link = new RedisBotLink(redis, connect, KEY);
    expect(await link.send(action)).toBe('bot_unavailable');
  });

  it('reads the snapshot, and treats a missing or corrupt one as none', async () => {
    const link = new RedisBotLink(redis, connect, KEY);
    const snapshot: GuildSnapshot = { channels: [], roles: [], missingPermissions: ['ManageRoles'], updatedAt: new Date().toISOString() };
    expect(await link.snapshot(GUILD)).toBeNull();
    await redis.set(guildSnapshotKey(GUILD), JSON.stringify(snapshot));
    expect(await link.snapshot(GUILD)).toEqual(snapshot);
    await redis.set(guildSnapshotKey(GUILD), 'garbage');
    expect(await link.snapshot(GUILD)).toBeNull();
    await redis.set(guildSnapshotKey(GUILD), JSON.stringify({ ...snapshot, channels: 'no' }));
    expect(await link.snapshot(GUILD)).toBeNull();
  });

  it('sends a signed request to the right shard and returns the bot’s answer', async () => {
    await redis.set(BOT_SHARD_COUNT_KEY, '3');
    const shard = shardForGuild(GUILD, 3);
    const received: unknown[] = [];
    // Stands in for the bot: checks the signature like the real handler does.
    const bot = new Worker(
      dashboardActionQueue(shard),
      (job) => {
        received.push(job.data);
        return Promise.resolve(verifyAction(KEY, job.data) ? { code: 'test_sent' } : { code: 'rejected' });
      },
      { connection: connect(), prefix: QUEUE_PREFIX },
    );
    const link = new RedisBotLink(redis, connect, KEY);
    try {
      expect(await link.send(action)).toBe('test_sent');
      expect(verifyAction(KEY, received[0])).toEqual(action);
    } finally {
      await bot.close();
      await link.close();
    }
  }, 30_000);

  it('treats an answer it doesn’t recognise as the bot being unavailable', async () => {
    await redis.set(BOT_SHARD_COUNT_KEY, '1');
    const bot = new Worker(dashboardActionQueue(0), () => Promise.resolve({ code: '<script>' }), { connection: connect(), prefix: QUEUE_PREFIX });
    const link = new RedisBotLink(redis, connect, KEY);
    try {
      expect(await link.send(action)).toBe('bot_unavailable');
    } finally {
      await bot.close();
      await link.close();
    }
  }, 30_000);

  it('times out when no bot picks the request up, and takes the request back', async () => {
    await redis.set(BOT_SHARD_COUNT_KEY, '1');
    const link = new RedisBotLink(redis, connect, KEY, 500);
    try {
      expect(await link.send(action)).toBe('timeout');
      // Nothing is left waiting to run later, after the user was told it didn't happen.
      const waiting = await redis.keys(`${QUEUE_PREFIX}:${dashboardActionQueue(0)}:wait`);
      const pending = waiting.length ? await redis.llen(waiting[0]!) : 0;
      expect(pending).toBe(0);
    } finally {
      await link.close();
    }
  }, 30_000);
});
