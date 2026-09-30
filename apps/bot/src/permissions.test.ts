import { PermissionFlagsBits, PermissionsBitField, type Guild, type GuildTextBasedChannel } from 'discord.js';
import { describe, expect, it } from 'vitest';
import { canPostAlerts, INVITE_PERMISSIONS, missingGuildPermissions, REQUIRED_GUILD_PERMISSIONS } from './permissions.js';

const bits = (...flags: bigint[]) => new PermissionsBitField(flags);
const guildWith = (me: { permissions: PermissionsBitField } | null) => ({ members: { me } }) as unknown as Guild;
const channelWith = (me: object | null, allowed: PermissionsBitField) =>
  ({ guild: { members: { me } }, permissionsFor: () => allowed }) as unknown as GuildTextBasedChannel;

describe('missingGuildPermissions', () => {
  it('lists nothing when the bot has everything it needs', () => {
    expect(missingGuildPermissions(guildWith({ permissions: bits(...Object.values(REQUIRED_GUILD_PERMISSIONS)) }))).toEqual([]);
  });

  it('names exactly the missing permissions', () => {
    const me = { permissions: bits(PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.EmbedLinks) };
    expect(missingGuildPermissions(guildWith(me))).toEqual(['ManageMessages', 'ManageRoles', 'ModerateMembers']);
  });

  it('assumes everything is missing when the bot member is not known', () => {
    expect(missingGuildPermissions(guildWith(null))).toEqual(Object.keys(REQUIRED_GUILD_PERMISSIONS));
  });
});

describe('canPostAlerts', () => {
  it('needs to see the channel, send, and embed links', () => {
    const all = bits(PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.EmbedLinks);
    expect(canPostAlerts(channelWith({}, all))).toBe(true);
    expect(canPostAlerts(channelWith({}, bits(PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages)))).toBe(false);
    expect(canPostAlerts(channelWith(null, all))).toBe(false);
  });
});

describe('invite permissions', () => {
  it('ask for exactly the required permissions: never Administrator, Kick or Ban', () => {
    const invite = new PermissionsBitField(INVITE_PERMISSIONS);
    expect(invite.has(PermissionFlagsBits.Administrator)).toBe(false);
    expect(invite.has(PermissionFlagsBits.KickMembers)).toBe(false);
    expect(invite.has(PermissionFlagsBits.BanMembers)).toBe(false);
    expect(invite.toArray().sort()).toEqual(Object.keys(REQUIRED_GUILD_PERMISSIONS).sort());
  });
});
