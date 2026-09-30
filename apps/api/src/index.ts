import { Queue } from 'bullmq';
import { Redis } from 'ioredis';
import { pino } from 'pino';
import { loadApiConfig, logRedactPaths } from '@equinox/config';
import { INTEL_LOOKUP_QUEUE, QUEUE_PREFIX, type IntelLookupJob } from '@equinox/core';
import { createDb, createStores } from '@equinox/db';
import { buildApi } from './app.js';
import { RedisBotLink } from './bot-link.js';
import { DiscordOAuthClient } from './discord-oauth.js';
import { RedisDashboardIntel } from './intel.js';
import { RedisNonceStore } from './nonces.js';
import { RedisSessionStore } from './sessions.js';

const config = loadApiConfig();
const logger = pino({
  level: config.LOG_LEVEL,
  base: { service: 'api' },
  redact: { paths: logRedactPaths, censor: '[redacted]' },
});

const dbHandle = createDb(config.DATABASE_URL, { max: 5 });
const redis = new Redis(config.REDIS_URL, { maxRetriesPerRequest: 2, connectTimeout: 5000 });
redis.on('error', (err) => logger.error({ err: { message: err.message } }, 'redis error'));

/** BullMQ's queues and event listeners each need their own connection. */
function queueConnection() {
  const connection = new Redis(config.REDIS_URL, { maxRetriesPerRequest: null });
  connection.on('error', (err) => logger.error({ err: { message: err.message } }, 'redis error'));
  return connection;
}

// "Check a link" queues lookups for the intel worker.
const lookupQueue = new Queue<IntelLookupJob>(INTEL_LOOKUP_QUEUE, {
  connection: queueConnection(),
  prefix: QUEUE_PREFIX,
  defaultJobOptions: { removeOnComplete: true, removeOnFail: 100 },
});
// Review, setup and test alerts go to the bot as signed requests (see bot-link.ts).
const botLink = new RedisBotLink(redis, queueConnection, config.INTERNAL_SIGNING_KEY);
if (!botLink.enabled) logger.warn('INTERNAL_SIGNING_KEY not set: review, setup and test buttons are off in the dashboard');

const app = await buildApi({
  stores: createStores(dbHandle.db),
  sessions: new RedisSessionStore(redis),
  oauth: new DiscordOAuthClient(config.DISCORD_CLIENT_ID, config.DISCORD_CLIENT_SECRET, config.DASHBOARD_URL),
  intel: new RedisDashboardIntel(redis, lookupQueue),
  bot: botLink,
  nonces: new RedisNonceStore(redis),
  signingKey: config.API_SIGNING_KEY,
  logger,
});

async function shutdown(signal: string) {
  logger.info({ signal }, 'shutting down');
  await app.close();
  await botLink.close();
  await lookupQueue.close();
  redis.disconnect();
  await dbHandle.close();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

try {
  await app.listen({ host: config.API_HOST, port: config.API_PORT });
  logger.info({ host: config.API_HOST, port: config.API_PORT }, 'api listening');
} catch (error) {
  logger.fatal({ err: { message: error instanceof Error ? error.message : 'unknown error' } }, 'startup failed');
  process.exit(1);
}
