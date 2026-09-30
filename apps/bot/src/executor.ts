import type { Client } from 'discord.js';
import { BRAND, slash, type ActionContext, type ActionExecutor, type ActionKind, type ActionOutcome, type Detection, type GuildSettings } from '@equinox/core';
import { buildAlertMessage } from './alerts.js';

const QUARANTINE_TIMEOUT_MS = 10 * 60 * 1000;

/** Carries out pipeline actions against Discord. Every call includes a reason for Discord's own audit log. */
export class DiscordActionExecutor implements ActionExecutor {
  constructor(private readonly client: Client) {}

  async execute(action: ActionKind, { guild, detection, previous }: ActionContext): Promise<ActionOutcome> {
    const discordGuild = await this.client.guilds.fetch(guild.id);
    const reason = `${BRAND.name} detection ${detection.id}`;

    switch (action) {
      case 'none':
        return { action, ok: true };

      case 'alert': {
        if (!guild.alertChannelId) return { action, ok: false, detail: `No alert channel set, run ${slash('setup')}` };
        const channel = await discordGuild.channels.fetch(guild.alertChannelId);
        if (!channel?.isSendable()) return { action, ok: false, detail: 'Alert channel is not sendable' };
        await channel.send(buildAlertMessage(detection, guild.mode, previous));
        return { action, ok: true };
      }

      case 'delete': {
        if (!detection.channelId || !detection.messageId) return { action, ok: false, detail: 'No message to delete' };
        const channel = await discordGuild.channels.fetch(detection.channelId);
        if (!channel?.isTextBased()) return { action, ok: false, detail: 'Channel not found' };
        await channel.messages.delete(detection.messageId);
        return { action, ok: true };
      }

      case 'quarantine': {
        if (!guild.quarantineRoleId) return { action, ok: false, detail: 'No quarantine role set' };
        const member = await discordGuild.members.fetch(detection.userId);
        await member.roles.add(guild.quarantineRoleId, reason);
        return { action, ok: true };
      }

      case 'timeout': {
        const member = await discordGuild.members.fetch(detection.userId);
        await member.timeout(QUARANTINE_TIMEOUT_MS, reason);
        return { action, ok: true };
      }

      case 'kick':
      case 'ban':
        // The policy never asks for these. Kicks and bans need a moderator to confirm them.
        return { action, ok: false, detail: 'Requires moderator confirmation' };
    }
  }

  async revert(action: ActionKind, guild: GuildSettings, detection: Detection): Promise<ActionOutcome> {
    const discordGuild = await this.client.guilds.fetch(guild.id);
    const reason = `${BRAND.name} detection ${detection.id} reverted`;

    switch (action) {
      case 'quarantine': {
        if (!guild.quarantineRoleId) return { action, ok: false, detail: 'No quarantine role set' };
        const member = await discordGuild.members.fetch(detection.userId);
        await member.roles.remove(guild.quarantineRoleId, reason);
        return { action, ok: true };
      }
      case 'timeout': {
        const member = await discordGuild.members.fetch(detection.userId);
        await member.timeout(null, reason);
        return { action, ok: true };
      }
      case 'ban':
        await discordGuild.bans.remove(detection.userId, reason);
        return { action, ok: true };
      default:
        return { action, ok: false, detail: 'Not reversible' };
    }
  }
}
