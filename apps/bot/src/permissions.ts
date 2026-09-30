import { PermissionFlagsBits, type Guild, type GuildTextBasedChannel } from 'discord.js';

/** Only what the current features actually use. Kick and Ban get added with raid handling (M8). */
export const REQUIRED_GUILD_PERMISSIONS = {
  ViewChannel: PermissionFlagsBits.ViewChannel,
  SendMessages: PermissionFlagsBits.SendMessages,
  EmbedLinks: PermissionFlagsBits.EmbedLinks,
  ManageMessages: PermissionFlagsBits.ManageMessages,
  ManageRoles: PermissionFlagsBits.ManageRoles,
  ModerateMembers: PermissionFlagsBits.ModerateMembers,
} as const;

export function missingGuildPermissions(guild: Guild): string[] {
  const me = guild.members.me;
  if (!me) return Object.keys(REQUIRED_GUILD_PERMISSIONS);
  return Object.entries(REQUIRED_GUILD_PERMISSIONS)
    .filter(([, flag]) => !me.permissions.has(flag))
    .map(([name]) => name);
}

export function canPostAlerts(channel: GuildTextBasedChannel): boolean {
  const me = channel.guild.members.me;
  if (!me) return false;
  return channel
    .permissionsFor(me)
    .has([PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.EmbedLinks]);
}

/** Bits for the OAuth2 invite URL. */
export const INVITE_PERMISSIONS = Object.values(REQUIRED_GUILD_PERMISSIONS).reduce((acc, bit) => acc | bit, 0n);
