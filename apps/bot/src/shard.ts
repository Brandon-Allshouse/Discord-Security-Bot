import { Client, Events, GatewayIntentBits, Options, Partials } from 'discord.js';
import { Redis } from 'ioredis';
import { loadConfig } from '@equinox/config';
import { createDb, createStores } from '@equinox/db';
import { createLimits, type BotContext } from './context.js';
import { DiscordActionExecutor } from './executor.js';
import { offboardGuild, onboardGuild } from './handlers/guilds.js';
import { handleInteraction } from './handlers/interactions.js';
import { scanMessage, SeenEdits } from './handlers/messages.js';
import { CachedGuildRepository, IndicatorService } from './indicators.js';
import { createLogger } from './logger.js';
import { registerCommands } from './register.js';

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

const guildCache = new CachedGuildRepository(stores.guilds);
const indicators = new IndicatorService(redis, stores.allowlist);
const ctx: BotContext = {
  client,
  logger,
  redis,
  stores,
  guildCache,
  indicators,
  deps: {
    guilds: guildCache,
    indicators,
    detections: stores.detections,
    audit: stores.audit,
    executor: new DiscordActionExecutor(client),
  },
  limits: createLimits(),
};

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
    }
  }),
);
client.on(
  Events.GuildCreate,
  safely('guildCreate', async (guild) => {
    await onboardGuild(guild, ctx);
    // First run: commands couldn't be registered before the bot was in the dev server.
    if (guild.id === config.DEV_GUILD_ID && (await registerCommands(config)) === 'registered') {
      logger.info('slash commands registered in dev guild');
    }
  }),
);
client.on(Events.GuildDelete, safely('guildDelete', (guild) => offboardGuild(guild, ctx)));
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
client.on(Events.ShardDisconnect, () => logger.warn('disconnected from gateway'));

async function shutdown(signal: string) {
  logger.info({ signal }, 'shutting down');
  await client.destroy();
  redis.disconnect();
  await dbHandle.close();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('unhandledRejection', (err) => logger.error({ err }, 'unhandled rejection'));

await client.login(config.DISCORD_TOKEN);
