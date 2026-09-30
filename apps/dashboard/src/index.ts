import { Redis } from 'ioredis';
import { pino } from 'pino';
import { loadDashboardConfig, logRedactPaths } from '@equinox/config';
import { createDb, createStores } from '@equinox/db';
import { buildApp } from './app.js';
import { DiscordOAuthClient } from './discord-oauth.js';
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

const app = await buildApp({
  stores: createStores(dbHandle.db),
  sessions: new RedisSessionStore(redis),
  oauth: new DiscordOAuthClient(config.DISCORD_CLIENT_ID, config.DISCORD_CLIENT_SECRET, config.DASHBOARD_URL),
  publicUrl: config.DASHBOARD_URL,
  logger,
});

async function shutdown(signal: string) {
  logger.info({ signal }, 'shutting down');
  await app.close();
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
