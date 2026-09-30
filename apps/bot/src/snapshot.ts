import { ChannelType, type Guild, type GuildTextBasedChannel } from 'discord.js';
import type { Redis } from 'ioredis';
import { GUILD_SNAPSHOT_TTL_SECONDS, guildSnapshotKey, guildSnapshotSchema, type GuildSnapshot } from '@equinox/core';
import type { Logger } from './logger.js';
import { canPostAlerts, missingGuildPermissions } from './permissions.js';

const ALERT_CHANNEL_TYPES = new Set([ChannelType.GuildText, ChannelType.GuildAnnouncement]);

/**
 * What the dashboard may show about a server: channel and role names (so forms show names,
 * not IDs), what the bot can do with each, and which permissions it's missing.
 * Nothing about members or messages.
 */
export function buildSnapshot(guild: Guild, now = new Date()): GuildSnapshot {
  const channels = [...guild.channels.cache.values()]
    .filter((c) => ALERT_CHANNEL_TYPES.has(c.type))
    .sort((a, b) => ('rawPosition' in a && 'rawPosition' in b ? a.rawPosition - b.rawPosition : 0))
    .slice(0, 500)
    .map((c) => ({ id: c.id, name: c.name.slice(0, 100), canPostAlerts: canPostAlerts(c as GuildTextBasedChannel) }));

  const roles = [...guild.roles.cache.values()]
    .filter((r) => r.id !== guild.id)
    .sort((a, b) => b.position - a.position)
    .slice(0, 250)
    .map((r) => ({
      id: r.id,
      name: r.name.slice(0, 100),
      canBeModRole: !r.managed,
      canBeQuarantineRole: r.editable && !r.managed,
    }));

  return guildSnapshotSchema.parse({
    channels,
    roles,
    missingPermissions: missingGuildPermissions(guild),
    updatedAt: now.toISOString(),
  });
}

/**
 * Keeps each server's snapshot in Redis fresh. Changes to channels and roles come in bursts
 * (a new server setup can fire dozens of events), so publishing is debounced per server.
 */
export class SnapshotPublisher {
  private readonly pending = new Map<string, NodeJS.Timeout>();

  constructor(
    private readonly redis: Pick<Redis, 'set'>,
    private readonly logger: Pick<Logger, 'warn'>,
    private readonly debounceMs = 2000,
  ) {}

  async publish(guild: Guild): Promise<void> {
    try {
      await this.redis.set(guildSnapshotKey(guild.id), JSON.stringify(buildSnapshot(guild)), 'EX', GUILD_SNAPSHOT_TTL_SECONDS);
    } catch (error) {
      this.logger.warn({ guildId: guild.id, err: { message: error instanceof Error ? error.message : 'unknown' } }, 'could not publish guild snapshot');
    }
  }

  /** Publish soon, once, however many changes arrive in the meantime. */
  schedule(guild: Guild): void {
    if (this.pending.has(guild.id)) return;
    const timer = setTimeout(() => {
      this.pending.delete(guild.id);
      void this.publish(guild);
    }, this.debounceMs);
    timer.unref();
    this.pending.set(guild.id, timer);
  }
}
