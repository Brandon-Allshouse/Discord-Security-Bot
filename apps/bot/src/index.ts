import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { ShardingManager } from 'discord.js';
import { Redis } from 'ioredis';
import { loadConfig } from '@equinox/config';
import { BOT_SHARD_COUNT_KEY } from '@equinox/core';
import { createDb, runMigrations, SystemStore } from '@equinox/db';
import { seedBlocklist } from './indicators.js';
import { createLogger } from './logger.js';
import { inviteUrl, registerCommands } from './register.js';

const config = loadConfig();
const logger = createLogger(config.LOG_LEVEL, { role: 'manager' });

async function loadSeedBlocklist(url: string) {
  const redis = new Redis(url, { maxRetriesPerRequest: 2, lazyConnect: true });
  try {
    await redis.connect();
    const text = await readFile(new URL('../data/seed-blocklist.txt', import.meta.url), 'utf8');
    const added = await seedBlocklist(redis, text);
    logger.info({ added }, 'seed blocklist loaded');
  } finally {
    redis.disconnect();
  }
}

async function main() {
  await runMigrations(config.DATABASE_URL);
  logger.info('database migrations applied');
  await loadSeedBlocklist(config.REDIS_URL);

  // Print the invite first: on a first run the bot isn't in any server yet.
  logger.info(`Invite: ${inviteUrl(config.DISCORD_CLIENT_ID)}`);

  const registered = await registerCommands(config);
  if (registered === 'registered') {
    logger.info({ scope: config.DEV_GUILD_ID ? 'dev guild' : 'global' }, 'slash commands registered');
  } else {
    logger.warn(
      { devGuildId: config.DEV_GUILD_ID },
      'bot is not in DEV_GUILD_ID yet: invite it with the link above (commands register as soon as it joins). If it is already there, check DEV_GUILD_ID.',
    );
  }

  // Sharding from day one, even with one shard. In dev we run the .ts file through tsx.
  const runningTs = import.meta.url.endsWith('.ts');
  const manager = new ShardingManager(fileURLToPath(new URL(runningTs ? './shard.ts' : './shard.js', import.meta.url)), {
    token: config.DISCORD_TOKEN,
    totalShards: 'auto',
    respawn: true,
    execArgv: runningTs ? ['--import', 'tsx'] : [],
  });
  manager.on('shardCreate', (shard) => logger.info({ shard: shard.id }, 'shard launched'));
  await manager.spawn();
  await publishShardCount(config.REDIS_URL, manager.totalShards === 'auto' ? 1 : manager.totalShards);

  startRetentionJob(config.DATABASE_URL);
}

/** Tells the dashboard how many shards there are, so it can send each request to the right one. */
async function publishShardCount(url: string, count: number) {
  const redis = new Redis(url, { maxRetriesPerRequest: 2, lazyConnect: true });
  try {
    await redis.connect();
    await redis.set(BOT_SHARD_COUNT_KEY, String(count));
    logger.info({ shards: count }, 'shard count published');
  } finally {
    redis.disconnect();
  }
}

/** Every hour, delete detections past their expiry so we don't keep data longer than we said we would. */
function startRetentionJob(databaseUrl: string) {
  const { db } = createDb(databaseUrl, { max: 1 });
  const system = new SystemStore(db);
  const run = () =>
    system
      .deleteExpiredDetections()
      .then((deleted) => deleted > 0 && logger.info({ deleted }, 'retention: expired detections deleted'))
      .catch((err: unknown) => logger.error({ err: { message: err instanceof Error ? err.message : 'unknown' } }, 'retention failed'));
  void run();
  setInterval(() => void run(), 60 * 60 * 1000).unref();
}

try {
  await main();
} catch (error) {
  // One clean line instead of a dump of request bodies and internals.
  const code = error instanceof Error && 'status' in error ? String(error.status) : undefined;
  logger.fatal({ err: { message: error instanceof Error ? error.message : 'unknown error', code } }, 'startup failed');
  process.exit(1);
}
