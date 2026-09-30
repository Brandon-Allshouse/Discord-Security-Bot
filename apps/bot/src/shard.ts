import { Queue, Worker } from 'bullmq';
import { Client, Events, GatewayIntentBits, Options, Partials, type Guild } from 'discord.js';
import { Redis } from 'ioredis';
import { loadConfig } from '@equinox/config';
import {
  dashboardActionQueue,
  guildSnapshotKey,
  INTEL_LOOKUP_QUEUE,
  INTEL_RESOLVED_CHANNEL,
  QUEUE_PREFIX,
  type IntelLookupJob,
} from '@equinox/core';
import { createDb, createStores } from '@equinox/db';
import { createLimits, type BotContext } from './context.js';
import { DiscordActionExecutor } from './executor.js';
import { offboardGuild, onboardGuild } from './handlers/guilds.js';
import { handleDashboardAction } from './handlers/dashboard-actions.js';
import { handleInteraction } from './handlers/interactions.js';
import { scanMessage, SeenEdits } from './handlers/messages.js';
import { CachedGuildRepository, IndicatorService } from './indicators.js';
import { handleResolved, IntelCache, IntelRequests } from './intel.js';
import { createLogger } from './logger.js';
import { registerCommands } from './register.js';
import { SnapshotPublisher } from './snapshot.js';

const config = loadConfig();
const logger = createLogger(config.LOG_LEVEL, { shard: process.env.SHARDS ?? '0' });

const client = new Client({
  // Only the intents we use. MessageContent is privileged; we need it to read links.
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent],
  // Nothing the bot sends can ping, by default.
  allowedMentions: { parse: [] },
  // Don't cache messages. We read each one as it arrives and then let it go.
  makeCache: Options.cacheWithLimits({ ...Options.DefaultMakeCacheSettings, MessageManager: 0 }),
  // Without this, discord.js drops edit events for messages that aren't cached, which is all of them.
  partials: [Partials.Message],
});
const seenEdits = new SeenEdits();

const dbHandle = createDb(config.DATABASE_URL);
const stores = createStores(dbHandle.db);
const redis = new Redis(config.REDIS_URL, { maxRetriesPerRequest: 2, connectTimeout: 5000 });
redis.on('error', (err) => logger.error({ err: { message: err.message } }, 'redis error'));

// Intel: lookups go to the worker through a queue; results come back over pub/sub.
// BullMQ and subscribers each need their own connection.
const queueConnection = new Redis(config.REDIS_URL, { maxRetriesPerRequest: null });
const subscriber = new Redis(config.REDIS_URL, { maxRetriesPerRequest: null });
for (const connection of [queueConnection, subscriber]) {
  connection.on('error', (err) => logger.error({ err: { message: err.message } }, 'redis error'));
}
const lookupQueue = new Queue<IntelLookupJob>(INTEL_LOOKUP_QUEUE, {
  connection: queueConnection,
  prefix: QUEUE_PREFIX,
  defaultJobOptions: { removeOnComplete: true, removeOnFail: 100, attempts: 2, backoff: { type: 'exponential', delay: 5000 } },
});

const guildCache = new CachedGuildRepository(stores.guilds);
const indicators = new IndicatorService(redis, stores.allowlist);
const intelCache = new IntelCache(redis);
const ctx: BotContext = {
  client,
  logger,
  redis,
  stores,
  guildCache,
  indicators,
  intelCache,
  intel: new IntelRequests(redis, lookupQueue),
  deps: {
    guilds: guildCache,
    indicators,
    detections: stores.detections,
    audit: stores.audit,
    executor: new DiscordActionExecutor(client),
    intel: intelCache,
  },
  limits: createLimits(),
};

// The dashboard's view of each server (channel and role names, missing permissions).
const snapshots = new SnapshotPublisher(redis, logger);
let dashboardWorker: Worker | null = null;

/**
 * Requests from the dashboard (review, setup, test alert) for the servers this shard serves.
 * Off without INTERNAL_SIGNING_KEY: an unsigned request is never trusted.
 */
function startDashboardWorker(shardId: number) {
  const key = config.INTERNAL_SIGNING_KEY;
  if (!key) {
    logger.warn('INTERNAL_SIGNING_KEY not set: dashboard review, setup and test buttons are off');
    return;
  }
  dashboardWorker = new Worker(dashboardActionQueue(shardId), (job) => handleDashboardAction(job.data, ctx, key), {
    connection: queueConnection,
    prefix: QUEUE_PREFIX,
    concurrency: 2,
  });
  dashboardWorker.on('failed', (job, err) => logger.warn({ job: job?.id, err: { message: err.message } }, 'dashboard request failed'));
  dashboardWorker.on('error', (err) => logger.error({ err: { message: err.message } }, 'dashboard worker error'));
}

/** Wraps an event handler so one failure is logged, never crashes the shard. */
function safely<T extends unknown[]>(name: string, fn: (...args: T) => Promise<void>) {
  return (...args: T) => {
    fn(...args).catch((err: unknown) => logger.error({ err, event: name }, 'event handler failed'));
  };
}

client.once(
  Events.ClientReady,
  safely('ready', async (ready) => {
    logger.info({ user: ready.user.tag, guilds: ready.guilds.cache.size }, 'shard ready');
    // Catch up on guilds joined while the bot was offline.
    for (const guild of ready.guilds.cache.values()) {
      if (!(await stores.guilds.get(guild.id))) await onboardGuild(guild, ctx);
      await snapshots.publish(guild);
    }
    startDashboardWorker(client.shard?.ids[0] ?? 0);
    // Refresh regularly too: permission changes on the bot's own role don't always fire an event we get.
    setInterval(() => {
      for (const guild of client.guilds.cache.values()) void snapshots.publish(guild);
    }, 5 * 60_000).unref();
  }),
);
client.on(
  Events.GuildCreate,
  safely('guildCreate', async (guild) => {
    await onboardGuild(guild, ctx);
    await snapshots.publish(guild);
    // First run: commands couldn't be registered before the bot was in the dev server.
    if (guild.id === config.DEV_GUILD_ID && (await registerCommands(config)) === 'registered') {
      logger.info('slash commands registered in dev guild');
    }
  }),
);
client.on(
  Events.GuildDelete,
  safely('guildDelete', async (guild) => {
    await offboardGuild(guild, ctx);
    await redis.del(guildSnapshotKey(guild.id));
  }),
);
// Keep the dashboard's channel and role lists current.
const refresh = (guild: Guild | null) => {
  if (guild) snapshots.schedule(guild);
};
client.on(Events.GuildUpdate, (_before, after) => refresh(after));
client.on(Events.ChannelCreate, (channel) => refresh(channel.guild));
client.on(Events.ChannelUpdate, (_before, after) => refresh('guild' in after ? after.guild : null));
client.on(Events.ChannelDelete, (channel) => refresh('guild' in channel ? channel.guild : null));
client.on(Events.GuildRoleCreate, (role) => refresh(role.guild));
client.on(Events.GuildRoleUpdate, (_before, after) => refresh(after.guild));
client.on(Events.GuildRoleDelete, (role) => refresh(role.guild));
client.on(Events.InteractionCreate, safely('interaction', (interaction) => handleInteraction(interaction, ctx)));
client.on(Events.MessageCreate, safely('messageCreate', (message) => scanMessage(message, ctx)));
client.on(
  Events.MessageUpdate,
  safely('messageUpdate', async (_before, after) => {
    // Scammers edit harmless messages into links after they pass review.
    if (after.partial || !seenEdits.isNew(after.id, after.editedTimestamp)) return;
    await scanMessage(after, ctx);
  }),
);
client.on(Events.Error, (err) => logger.error({ err }, 'client error'));

await subscriber.subscribe(INTEL_RESOLVED_CHANNEL);
subscriber.on(
  'message',
  safely('intelResolved', (_channel: string, message: string) =>
    handleResolved(message, { ...ctx, servesGuild: (guildId) => client.guilds.cache.has(guildId) }),
  ),
);
client.on(Events.ShardDisconnect, () => logger.warn('disconnected from gateway'));

async function shutdown(signal: string) {
  logger.info({ signal }, 'shutting down');
  await client.destroy();
  await dashboardWorker?.close();
  await lookupQueue.close();
  subscriber.disconnect();
  queueConnection.disconnect();
  redis.disconnect();
  await dbHandle.close();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('unhandledRejection', (err) => logger.error({ err }, 'unhandled rejection'));

await client.login(config.DISCORD_TOKEN);
