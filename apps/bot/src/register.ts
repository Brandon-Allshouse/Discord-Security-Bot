import { REST, Routes } from 'discord.js';
import type { Config } from '@equinox/config';
import { commandDefinitions } from './commands.js';
import { INVITE_PERMISSIONS } from './permissions.js';

type CommandConfig = Pick<Config, 'DISCORD_TOKEN' | 'DISCORD_CLIENT_ID' | 'DEV_GUILD_ID'>;

export interface CommandPublisher {
  put(route: `/${string}`, options: { body: unknown }): Promise<unknown>;
}

export function inviteUrl(clientId: string): string {
  return `https://discord.com/oauth2/authorize?client_id=${clientId}&scope=bot+applications.commands&permissions=${INVITE_PERMISSIONS}`;
}

/**
 * Registers slash commands: to the dev server in development (shows up instantly),
 * globally otherwise.
 *
 * Discord answers 403 when the bot isn't in the dev server yet, which is normal on a
 * first run. That's reported back instead of thrown, so startup can carry on and the
 * shard registers the commands once the bot is invited.
 */
export async function registerCommands(
  cfg: CommandConfig,
  rest: CommandPublisher = new REST().setToken(cfg.DISCORD_TOKEN),
): Promise<'registered' | 'not_in_dev_guild'> {
  const route = cfg.DEV_GUILD_ID
    ? Routes.applicationGuildCommands(cfg.DISCORD_CLIENT_ID, cfg.DEV_GUILD_ID)
    : Routes.applicationCommands(cfg.DISCORD_CLIENT_ID);
  try {
    await rest.put(route, { body: commandDefinitions });
    return 'registered';
  } catch (error) {
    const status = error instanceof Error && 'status' in error ? error.status : undefined;
    if (cfg.DEV_GUILD_ID && status === 403) return 'not_in_dev_guild';
    throw error;
  }
}
