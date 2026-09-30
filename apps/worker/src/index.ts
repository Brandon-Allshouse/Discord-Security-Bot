import { Queue, Worker } from 'bullmq';
import { Redis } from 'ioredis';
import { loadWorkerConfig } from '@equinox/config';
import { INTEL_FEED_QUEUE, INTEL_STATUS_KEY, INTEL_VT_QUEUE, QUEUE_PREFIX } from '@equinox/core';
import { createDb, ProviderResultStore } from '@equinox/db';
import { ApiBudget } from './budget.js';
import { RedirectProvider } from './chain.js';
import type { JobDeps } from './jobs.js';
import { createLogger } from './logger.js';
import { RdapProvider } from './providers/rdap.js';
import { UrlhausFeed } from './providers/urlhaus.js';
import { VirusTotalProvider } from './providers/virustotal.js';
import { writeStatus } from './status.js';
import { startIntelWorkers } from './workers.js';

const config = loadWorkerConfig();
const logger = createLogger(config.LOG_LEVEL);
const errMessage = (err: unknown) => ({ message: err instanceof Error ? err.message : 'unknown' });

// BullMQ needs its own connection that retries forever; everything else uses a normal one.
const queueConnection = new Redis(config.REDIS_URL, { maxRetriesPerRequest: null });
const redis = new Redis(config.REDIS_URL, { maxRetriesPerRequest: 2, connectTimeout: 5000 });
for (const connection of [queueConnection, redis]) {
  connection.on('error', (err) => logger.error({ err: errMessage(err) }, 'redis error'));
}
const dbHandle = createDb(config.DATABASE_URL, { max: 5 });
const cache = new ProviderResultStore(dbHandle.db);
const queueOptions = { connection: queueConnection, prefix: QUEUE_PREFIX };

const urlhaus = new UrlhausFeed(redis, { authKey: config.URLHAUS_AUTH_KEY });
const vtQueue = new Queue(INTEL_VT_QUEUE, {
  ...queueOptions,
  defaultJobOptions: { removeOnComplete: true, removeOnFail: 100 },
});
const vtLimits = { perDay: config.VT_DAILY_BUDGET, perMinute: config.VT_PER_MINUTE };

const deps: JobDeps = {
  redis,
  cache,
  logger,
  redirects: new RedirectProvider(),
  urlhaus,
  rdap: new RdapProvider(),
  vt: config.VT_API_KEY
    ? {
        provider: new VirusTotalProvider(config.VT_API_KEY, vtLimits),
        budget: new ApiBudget(redis, 'virustotal', vtLimits),
        queue: vtQueue,
      }
    : null,
};

// Heartbeat for the dashboard: which sources are on, and that the worker is alive.
const heartbeat = () =>
  writeStatus(redis, { virustotal: deps.vt !== null }).catch((err: unknown) =>
    logger.warn({ err: errMessage(err) }, 'could not write intel status'),
  );
void heartbeat();
const heartbeatTimer = setInterval(() => void heartbeat(), 60_000);
heartbeatTimer.unref();

const workers: Worker[] = startIntelWorkers({ deps, connection: queueConnection, logger, vtPerMinute: vtLimits.perMinute });
if (deps.vt) logger.info({ tier: config.VT_TIER, ...vtLimits }, 'virustotal enabled');
else logger.warn('VT_API_KEY not set: VirusTotal lookups are off, the other intel sources still run');

// The URLhaus feed, every 15 minutes (abuse.ch asks for no more than every 5). Runs once at startup too.
const feedQueue = new Queue(INTEL_FEED_QUEUE, {
  ...queueOptions,
  defaultJobOptions: { removeOnComplete: true, removeOnFail: 10 },
});
await feedQueue.upsertJobScheduler('urlhaus', { every: 15 * 60_000 }, { name: 'urlhaus' });
const feedWorker = new Worker(
  INTEL_FEED_QUEUE,
  async () => {
    try {
      const count = await urlhaus.sync();
      logger.info({ count }, 'urlhaus feed synced');
      void heartbeat();
    } catch (error) {
      const hint = config.URLHAUS_AUTH_KEY ? undefined : 'set URLHAUS_AUTH_KEY if abuse.ch requires one';
      logger.warn({ err: errMessage(error), hint }, 'urlhaus sync failed, keeping the previous copy');
    }
  },
  { ...queueOptions, concurrency: 1 },
);
feedWorker.on('error', (err) => logger.error({ queue: feedWorker.name, err: errMessage(err) }, 'worker error'));
workers.push(feedWorker);

// Retention (spec §9): drop expired intel answers every hour.
const retention = setInterval(() => {
  cache
    .deleteExpired()
    .then((deleted) => deleted > 0 && logger.info({ deleted }, 'retention: expired intel results deleted'))
    .catch((err: unknown) => logger.error({ err: errMessage(err) }, 'retention failed'));
}, 3600_000);
retention.unref();

logger.info('intel worker started');

async function shutdown(signal: string) {
  logger.info({ signal }, 'shutting down');
  clearInterval(retention);
  clearInterval(heartbeatTimer);
  await redis.del(INTEL_STATUS_KEY).catch(() => undefined);
  await Promise.all(workers.map((w) => w.close()));
  await Promise.all([vtQueue.close(), feedQueue.close()]);
  queueConnection.disconnect();
  redis.disconnect();
  await dbHandle.close();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('unhandledRejection', (err) => logger.error({ err: errMessage(err) }, 'unhandled rejection'));
