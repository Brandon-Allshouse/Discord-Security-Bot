import type { Guild } from 'discord.js';
import { BRAND, slash } from '@equinox/core';
import type { BotContext } from '../context.js';

const QUARANTINE_ROLE_NAME = `${BRAND.name} Quarantine`;

/**
 * Onboarding: register the server as a tenant and create a quarantine role with no
 * permissions if it doesn't have one. New servers start in alert_only, because missing
 * a scam is better than punishing someone who didn't do anything.
 */
export async function onboardGuild(guild: Guild, ctx: BotContext): Promise<void> {
  const settings = await ctx.stores.guilds.register({ id: guild.id, name: guild.name });
  ctx.guildCache.invalidate(guild.id);

  if (!settings.quarantineRoleId) {
    try {
      const role = await guild.roles.create({
        name: QUARANTINE_ROLE_NAME,
        permissions: [],
        reason: `${BRAND.name} setup: role for quarantined members`,
      });
      await ctx.stores.guilds.configure(guild.id, { quarantineRoleId: role.id });
      ctx.guildCache.invalidate(guild.id);
    } catch (error) {
      // Missing Manage Roles: the guild still works, and the status command shows what's missing.
      ctx.logger.warn({ err: error, guildId: guild.id, hint: slash('status') }, 'could not create quarantine role');
    }
  }

  await ctx.stores.audit.write({
    guildId: guild.id,
    actor: 'bot',
    action: 'guild.joined',
    target: null,
    details: { mode: settings.mode },
  });
  ctx.logger.info({ guildId: guild.id }, 'guild onboarded');
}

export async function offboardGuild(guild: Guild, ctx: BotContext): Promise<void> {
  await ctx.stores.guilds.markLeft(guild.id);
  ctx.guildCache.invalidate(guild.id);
  await ctx.stores.audit.write({ guildId: guild.id, actor: 'bot', action: 'guild.left', target: null, details: {} });
}
