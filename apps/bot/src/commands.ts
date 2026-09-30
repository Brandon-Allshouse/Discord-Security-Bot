import {
  ChannelType,
  InteractionContextType,
  PermissionFlagsBits,
  SlashCommandBuilder,
  type RESTPostAPIChatInputApplicationCommandsJSONBody,
} from 'discord.js';
import { BRAND, GUILD_MODES } from '@equinox/core';

const MODE_LABELS: Record<(typeof GUILD_MODES)[number], string> = {
  alert_only: 'Alert only (default, no automatic actions)',
  protect: 'Protect (act on confirmed threats)',
  strict: 'Strict (also act on suspicious ones)',
};

export const mainCommand = new SlashCommandBuilder()
  .setName(BRAND.command)
  .setDescription(`${BRAND.name} security network`)
  // Hidden from non-admins by default; every handler re-checks at runtime too.
  .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
  .setContexts(InteractionContextType.Guild)
  .addSubcommand((sub) =>
    sub
      .setName('setup')
      .setDescription('Configure the alert channel and roles')
      .addChannelOption((opt) =>
        opt
          .setName('alert_channel')
          .setDescription(`Where ${BRAND.name} posts alerts`)
          .addChannelTypes(ChannelType.GuildText)
          .setRequired(true),
      )
      .addRoleOption((opt) => opt.setName('mod_role').setDescription('Role allowed to act on alerts'))
      .addRoleOption((opt) =>
        opt.setName('quarantine_role').setDescription('Role applied to quarantined members (default: created for you)'),
      ),
  )
  .addSubcommand((sub) =>
    sub
      .setName('mode')
      .setDescription(`Set how ${BRAND.name} responds to threats`)
      .addStringOption((opt) =>
        opt
          .setName('mode')
          .setDescription('Protection mode')
          .setRequired(true)
          .addChoices(...GUILD_MODES.map((mode) => ({ name: MODE_LABELS[mode], value: mode }))),
      ),
  )
  .addSubcommand((sub) => sub.setName('status').setDescription('Show configuration and health'))
  .addSubcommand((sub) => sub.setName('test').setDescription('Send a harmless test signal through the pipeline'))
  .addSubcommand((sub) =>
    sub
      .setName('check')
      .setDescription(`Check a URL against ${BRAND.name}`)
      .addStringOption((opt) => opt.setName('url').setDescription('URL to check').setRequired(true).setMaxLength(2000)),
  )
  .addSubcommandGroup((group) =>
    group
      .setName('allow')
      .setDescription('Manage this server’s domain allowlist')
      .addSubcommand((sub) =>
        sub
          .setName('add')
          .setDescription('Never flag this domain in this server')
          .addStringOption((opt) =>
            opt.setName('domain').setDescription('Domain, e.g. example.com').setRequired(true).setMaxLength(253),
          ),
      )
      .addSubcommand((sub) =>
        sub
          .setName('remove')
          .setDescription('Remove a domain from the allowlist')
          .addStringOption((opt) =>
            opt.setName('domain').setDescription('Domain, e.g. example.com').setRequired(true).setMaxLength(253),
          ),
      )
      .addSubcommand((sub) => sub.setName('list').setDescription('List allowlisted domains')),
  );

export const commandDefinitions: RESTPostAPIChatInputApplicationCommandsJSONBody[] = [mainCommand.toJSON()];
