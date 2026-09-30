import { Queue } from 'bullmq';
import { Redis } from 'ioredis';
import { pino } from 'pino';
import { loadDashboardConfig, logRedactPaths } from '@equinox/config';
import { INTEL_LOOKUP_QUEUE, QUEUE_PREFIX, type IntelLookupJob } from '@equinox/core';
import { createDb, createStores } from '@equinox/db';
import { buildApp } from './app.js';
import { RedisBotLink } from './bot-link.js';
import { DiscordOAuthClient } from './discord-oauth.js';
import { RedisDashboardIntel } from './intel.js';
import { RedisSessionStore } from './sessions.js';

const config = loadDashboardConfig();
const logger = pino({
  level: config.LOG_LEVEL,
  base: { service: 'dashboard' },
  redact: { paths: logRedactPaths, censor: '[redacted]' },
});

const dbHandle = createDb(config.DATABASE_URL, { max: 5 });
const redis = new Redis(config.REDIS_URL, { maxRetriesPerRequest: 2, connectTimeout: 5000 });
redis.on('error', (err) => logger.error({ err: { message: err.message } }, 'redis error'));
// "Check a link" queues lookups for the intel worker. BullMQ needs its own connection.
const queueConnection = new Redis(config.REDIS_URL, { maxRetriesPerRequest: null });
queueConnection.on('error', (err) => logger.error({ err: { message: err.message } }, 'redis error'));
const lookupQueue = new Queue<IntelLookupJob>(INTEL_LOOKUP_QUEUE, {
  connection: queueConnection,
  prefix: QUEUE_PREFIX,
  defaultJobOptions: { removeOnComplete: true, removeOnFail: 100 },
});

// Review, setup and test alerts go to the bot through signed requests (see bot-link.ts).
const botLink = new RedisBotLink(
  redis,
  () => {
    const connection = new Redis(config.REDIS_URL, { maxRetriesPerRequest: null });
    connection.on('error', (err) => logger.error({ err: { message: err.message } }, 'redis error'));
    return connection;
  },
  config.INTERNAL_SIGNING_KEY,
);
if (!botLink.enabled) logger.warn('INTERNAL_SIGNING_KEY not set: review, setup and test buttons are off in the dashboard');

const app = await buildApp({
  stores: createStores(dbHandle.db),
  sessions: new RedisSessionStore(redis),
  oauth: new DiscordOAuthClient(config.DISCORD_CLIENT_ID, config.DISCORD_CLIENT_SECRET, config.DASHBOARD_URL),
  intel: new RedisDashboardIntel(redis, lookupQueue),
  bot: botLink,
  publicUrl: config.DASHBOARD_URL,
  logger,
});

async function shutdown(signal: string) {
  logger.info({ signal }, 'shutting down');
  await app.close();
  await botLink.close();
  await lookupQueue.close();
  queueConnection.disconnect();
  redis.disconnect();
  await dbHandle.close();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

try {
  await app.listen({ host: config.DASHBOARD_HOST, port: config.DASHBOARD_PORT });
  logger.info(`Dashboard: ${config.DASHBOARD_URL} (OAuth redirect: ${new URL('/auth/callback', config.DASHBOARD_URL).toString()})`);
} catch (error) {
  logger.fatal({ err: { message: error instanceof Error ? error.message : 'unknown error' } }, 'startup failed');
  process.exit(1);
}
